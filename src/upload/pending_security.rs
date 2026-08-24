use anyhow::{bail, Context, Result};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
#[path = "pending_security_unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "pending_security_windows.rs"]
mod platform;

#[cfg(not(any(unix, windows)))]
compile_error!("durable private upload custody is unsupported on this platform");

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileSnapshot {
    pub(crate) object_id: (u64, u64),
    pub(crate) owner_id: u64,
    pub(crate) links: u64,
    pub(crate) size: u64,
    pub(crate) modified: (i64, i64),
    pub(crate) changed: (i64, i64),
    pub(crate) mode_or_attributes: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct PrivateDirectory {
    inner: Arc<platform::Directory>,
    path: Arc<PathBuf>,
}

impl PartialEq for PrivateDirectory {
    fn eq(&self, other: &Self) -> bool {
        if Arc::ptr_eq(&self.inner, &other.inner) {
            return true;
        }
        self.path == other.path
            && matches!(
                (self.snapshot(), other.snapshot()),
                (Ok(left), Ok(right)) if left == right
            )
    }
}

impl Eq for PrivateDirectory {}

impl PrivateDirectory {
    pub(crate) fn open_or_create(path: &Path, label: &str) -> Result<Self> {
        let normalized = normalized_absolute_path(path)?;
        let inner = platform::Directory::open_or_create(&normalized, label)?;
        let directory = Self {
            inner: Arc::new(inner),
            path: Arc::new(normalized),
        };
        directory.verify_path(label)?;
        Ok(directory)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn open_private_file(
        &self,
        name: &OsStr,
        writable: bool,
        label: &str,
    ) -> Result<File> {
        validate_leaf(name)?;
        let file = self.inner.open_file(name, writable, label)?;
        self.inner.secure_file(&file, label)?;
        self.verify_entry(name, &file, label)?;
        Ok(file)
    }

    pub(crate) fn create_private_file(&self, name: &OsStr, label: &str) -> Result<File> {
        validate_leaf(name)?;
        let file = self.inner.create_file(name, label)?;
        self.inner.secure_file(&file, label)?;
        self.verify_entry(name, &file, label)?;
        file.sync_all()
            .with_context(|| format!("failed to synchronize private {label} file {name:?}"))?;
        self.sync()?;
        Ok(file)
    }

    pub(crate) fn prepare_private_file(&self, name: &OsStr, label: &str) -> Result<File> {
        match self.open_private_file(name, true, label) {
            Ok(file) => Ok(file),
            Err(error) if is_not_found(&error) => self.create_private_file(name, label),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn verify_entry(&self, name: &OsStr, file: &File, label: &str) -> Result<()> {
        validate_leaf(name)?;
        self.inner.verify_entry(name, file, label)
    }

    pub(crate) fn snapshot_file(&self, file: &File, label: &str) -> Result<FileSnapshot> {
        self.inner.snapshot_file(file, label)
    }

    pub(crate) fn remove_file_if_present(&self, name: &OsStr) -> Result<()> {
        validate_leaf(name)?;
        match self.inner.remove_file(name) {
            Ok(()) => {
                self.sync()?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| format!("failed to delete {name:?}")),
        }
    }

    pub(crate) fn contains_file(&self, name: &OsStr) -> Result<bool> {
        match self.open_private_file(name, false, "private file") {
            Ok(_) => Ok(true),
            Err(error) if is_not_found(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn sync(&self) -> Result<()> {
        self.inner.sync(&self.path)
    }

    pub(crate) fn snapshot(&self) -> Result<FileSnapshot> {
        self.inner.snapshot()
    }

    pub(crate) fn verify_path(&self, label: &str) -> Result<()> {
        self.inner.verify_path(&self.path, label)
    }
}

pub(crate) fn secure_sqlite_files(
    directory: &PrivateDirectory,
    database_name: &OsStr,
) -> Result<()> {
    directory.open_private_file(database_name, true, "upload state database")?;
    let database = database_name.to_string_lossy();
    for suffix in ["-wal", "-shm"] {
        let sidecar = OsString::from(format!("{database}{suffix}"));
        match directory.open_private_file(&sidecar, true, "upload state sidecar") {
            Ok(_) => {}
            Err(error) if is_not_found(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn normalized_absolute_path(path: &Path) -> Result<PathBuf> {
    let mut normalized = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().context("failed to resolve current directory")?
    };
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {
                if component == Component::RootDir {
                    normalized.push(Path::new("/"));
                }
            }
            Component::Normal(value) => normalized.push(value),
            Component::ParentDir | Component::Prefix(_) => {
                bail!("private custody path must not contain parent or prefix traversal: {path:?}")
            }
        }
    }
    if !normalized.is_absolute() {
        bail!("private custody path did not resolve to an absolute path: {path:?}");
    }
    Ok(normalized)
}

fn validate_leaf(name: &OsStr) -> Result<()> {
    let path = Path::new(name);
    if name.is_empty()
        || path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        bail!("private custody filename is not one exact leaf: {name:?}");
    }
    Ok(())
}

pub(crate) fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .is_some_and(|cause| cause.kind() == std::io::ErrorKind::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn directory_and_file_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "crowd-cast-private-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let directory = PrivateDirectory::open_or_create(&root, "test").unwrap();
        let file = directory
            .create_private_file(OsStr::new("state"), "test")
            .unwrap();

        assert_eq!(directory.snapshot().unwrap().mode_or_attributes & 0o077, 0);
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o077, 0);
        drop(file);
        drop(directory);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn intermediate_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "crowd-cast-private-link-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let target = root.join("target");
        std::fs::create_dir_all(&target).unwrap();
        symlink(&target, root.join("link")).unwrap();

        let error = PrivateDirectory::open_or_create(&root.join("link/child"), "test")
            .expect_err("intermediate symlink must fail");

        assert!(format!("{error:#}").contains("without symlink traversal"));
        assert!(!target.join("child").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn directory_swap_is_detected_against_the_held_capability() {
        let root = std::env::temp_dir().join(format!(
            "crowd-cast-private-swap-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let directory = PrivateDirectory::open_or_create(&root, "test").unwrap();
        let moved = root.with_extension("moved");
        std::fs::rename(&root, &moved).unwrap();
        std::fs::create_dir(&root).unwrap();

        let error = directory
            .verify_path("test")
            .expect_err("directory replacement must be rejected");

        assert!(format!("{error:#}").contains("changed after capability acquisition"));
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(moved).unwrap();
    }
}
