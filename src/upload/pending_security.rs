use anyhow::{bail, Context, Result};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

const MAX_PRIVATE_DIRECTORY_ENTRIES: usize = 65_536;
const MAX_PRIVATE_FILENAME_BYTES: usize = 1_024;
const MAX_PRIVATE_DIRECTORY_NAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Default)]
pub(super) struct DirectoryEnumerationBudget {
    entries: usize,
    name_bytes: usize,
}

impl DirectoryEnumerationBudget {
    pub(super) fn admit(&mut self, name_bytes: usize) -> Result<()> {
        if name_bytes > MAX_PRIVATE_FILENAME_BYTES {
            bail!("private directory entry name exceeds the custody limit");
        }
        self.entries = self
            .entries
            .checked_add(1)
            .context("private directory entry count overflowed")?;
        if self.entries > MAX_PRIVATE_DIRECTORY_ENTRIES {
            bail!("private directory exceeds the custody entry limit");
        }
        self.name_bytes = self
            .name_bytes
            .checked_add(name_bytes)
            .context("private directory name-byte count overflowed")?;
        if self.name_bytes > MAX_PRIVATE_DIRECTORY_NAME_BYTES {
            bail!("private directory names exceed the custody work limit");
        }
        Ok(())
    }
}

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

    pub(crate) fn file_names(&self) -> Result<Vec<OsString>> {
        let mut names = self.inner.file_names()?;
        names.sort();
        Ok(names)
    }

    pub(crate) fn sqlite_path(&self, name: &OsStr) -> Result<PathBuf> {
        validate_leaf(name)?;
        Ok(self.path.join(name))
    }

    #[cfg(unix)]
    pub(crate) fn process_open_count(&self, file: &File, label: &str) -> Result<usize> {
        self.inner
            .process_open_count(self.snapshot_file(file, label)?.object_id)
    }

    #[cfg(unix)]
    pub(crate) fn require_new_process_open(
        &self,
        file: &File,
        label: &str,
        prior_count: usize,
    ) -> Result<()> {
        if self.process_open_count(file, label)? <= prior_count {
            bail!("SQLite did not open the held upload state database object");
        }
        Ok(())
    }

    #[cfg(all(test, windows))]
    pub(crate) fn make_test_acl_permissive(&self, file: &File) -> Result<()> {
        self.inner.make_test_acl_permissive(file)
    }

    #[cfg(all(test, windows))]
    pub(crate) fn test_acl_bytes(&self, file: &File) -> Result<Vec<u8>> {
        self.inner.test_acl_bytes(file)
    }

    pub(crate) fn remove_file_if_matches(
        &self,
        name: &OsStr,
        expected_object_id: (u64, u64),
    ) -> Result<()> {
        let _cleanup = cleanup_lock()
            .lock()
            .map_err(|_| anyhow::anyhow!("private cleanup lock is poisoned"))?;
        validate_leaf(name)?;
        let file = match self.inner.open_file_for_delete(name, "deleted") {
            Ok(file) => file,
            Err(error) if is_not_found(&error) => return Ok(()),
            Err(error) => return Err(error),
        };
        let snapshot = self.inner.validate_private_file(&file, "deleted")?;
        if snapshot.object_id != expected_object_id {
            bail!("refusing to delete a replacement private file {name:?}");
        }
        self.verify_entry(name, &file, "deleted")?;
        match self.inner.remove_file(name, &file) {
            Ok(()) => {
                self.sync()?;
                Ok(())
            }
            Err(error) => Err(error).with_context(|| format!("failed to delete {name:?}")),
        }
    }

    pub(crate) fn contains_file(&self, name: &OsStr) -> Result<bool> {
        validate_leaf(name)?;
        match self.inner.open_file(name, false, "private file") {
            Ok(file) => {
                self.inner.validate_private_file(&file, "private file")?;
                self.verify_entry(name, &file, "private file")?;
                Ok(true)
            }
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

fn cleanup_lock() -> &'static Mutex<()> {
    // POSIX cannot condition unlinkat on inode identity. This lock serializes collector cleanup in
    // one process; the held directory lock covers other collector processes on the same object.
    // A malicious same-UID process that ignores advisory locks remains outside this boundary.
    static CLEANUP_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    CLEANUP_LOCK.get_or_init(|| Mutex::new(()))
}

pub(crate) fn open_sqlite_sidecars(
    directory: &PrivateDirectory,
    database_name: &OsStr,
) -> Result<Vec<File>> {
    let database = database_name.to_string_lossy();
    let mut files = Vec::with_capacity(2);
    for suffix in ["-wal", "-shm"] {
        let sidecar = OsString::from(format!("{database}{suffix}"));
        let file = directory
            .open_private_file(&sidecar, true, "upload state sidecar")
            .with_context(|| format!("missing required SQLite sidecar {sidecar:?}"))?;
        directory.verify_entry(&sidecar, &file, "upload state sidecar")?;
        #[cfg(unix)]
        if directory.process_open_count(&file, "upload state sidecar")? < 2 {
            bail!("SQLite did not open held upload state sidecar {sidecar:?}");
        }
        files.push(file);
    }
    Ok(files)
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
            Component::Prefix(prefix) => {
                #[cfg(windows)]
                {
                    if !normalized.as_os_str().is_empty()
                        || !matches!(prefix.kind(), std::path::Prefix::Disk(_))
                    {
                        bail!("private custody path has an unsupported Windows prefix: {path:?}");
                    }
                    normalized.push(prefix.as_os_str());
                }
                #[cfg(not(windows))]
                {
                    let _ = prefix;
                    bail!("private custody path contains a prefix: {path:?}");
                }
            }
            Component::ParentDir => {
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
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = std::env::temp_dir().join(format!(
            "crowd-cast-private-link-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let target = root.join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
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

    #[cfg(unix)]
    #[test]
    fn intermediate_swap_back_to_the_held_directory_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "crowd-cast-private-parent-swap-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let path = root.join("parent/held");
        let directory = PrivateDirectory::open_or_create(&path, "test").unwrap();
        let moved = root.join("moved-parent");
        std::fs::rename(root.join("parent"), &moved).unwrap();
        symlink(&moved, root.join("parent")).unwrap();

        let error = directory
            .verify_path("test")
            .expect_err("a swapped intermediate symlink must be rejected");

        assert!(format!("{error:#}").contains("without symlink traversal"));
        drop(directory);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn special_file_is_rejected_without_blocking() {
        use std::os::unix::ffi::OsStrExt;

        let root = std::env::temp_dir().join(format!(
            "crowd-cast-private-fifo-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let directory = PrivateDirectory::open_or_create(&root, "test").unwrap();
        let fifo = root.join("pipe");
        let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);

        let error = directory
            .open_private_file(OsStr::new("pipe"), false, "test")
            .expect_err("a FIFO must fail instead of waiting for a writer");

        assert!(format!("{error:#}").contains("not a private regular file"));
        drop(directory);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn replacement_permissions_are_not_changed_before_identity_rejection() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "crowd-cast-private-delete-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let directory = PrivateDirectory::open_or_create(&root, "test").unwrap();
        let name = OsStr::new("artifact");
        let original = directory.create_private_file(name, "test").unwrap();
        let original_id = directory
            .snapshot_file(&original, "test")
            .unwrap()
            .object_id;
        drop(original);
        std::fs::rename(root.join(name), root.join("original")).unwrap();
        std::fs::write(root.join(name), b"replacement").unwrap();
        std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o644)).unwrap();

        directory
            .remove_file_if_matches(name, original_id)
            .expect_err("replacement identity must be rejected");

        assert_eq!(
            std::fs::symlink_metadata(root.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        drop(directory);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn held_directory_enumeration_ignores_a_replacement_path() {
        let root = std::env::temp_dir().join(format!(
            "crowd-cast-private-enumerate-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let directory = PrivateDirectory::open_or_create(&root, "test").unwrap();
        directory
            .create_private_file(OsStr::new("held"), "test")
            .unwrap();
        let moved = root.with_extension("moved");
        std::fs::rename(&root, &moved).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("replacement"), b"outside").unwrap();

        assert_eq!(directory.file_names().unwrap(), [OsString::from("held")]);

        drop(directory);
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(moved).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sqlite_descriptor_attestation_rejects_a_replacement_database() {
        let root = std::env::temp_dir().join(format!(
            "crowd-cast-private-sqlite-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let path = root.join("parent/state");
        let directory = PrivateDirectory::open_or_create(&path, "test").unwrap();
        let database_name = OsStr::new("state.sqlite3");
        let file = directory
            .create_private_file(database_name, "test")
            .unwrap();
        let before = directory.process_open_count(&file, "test").unwrap();
        drop(file);
        let moved = root.join("moved-parent");
        std::fs::rename(root.join("parent"), &moved).unwrap();
        std::fs::create_dir(root.join("parent")).unwrap();
        std::fs::create_dir(root.join("parent/state")).unwrap();
        let replacement_path = root.join("parent/state/state.sqlite3");
        std::fs::File::create(&replacement_path).unwrap();

        let _replacement = rusqlite::Connection::open(&replacement_path).unwrap();

        let held = directory
            .open_private_file(database_name, false, "test")
            .unwrap();
        let error = directory
            .require_new_process_open(&held, "test", before)
            .expect_err("a replacement SQLite descriptor must not attest the held database");
        assert!(format!("{error:#}").contains("did not open the held"));
        directory
            .verify_path("test")
            .expect_err("replacement path must fail capability verification");
        drop(directory);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn competing_cleanup_waits_for_the_process_global_guard() {
        let root = std::env::temp_dir().join(format!(
            "crowd-cast-private-cleanup-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let directory = PrivateDirectory::open_or_create(&root, "test").unwrap();
        let name = OsString::from("artifact");
        let file = directory.create_private_file(&name, "test").unwrap();
        let object_id = directory.snapshot_file(&file, "test").unwrap().object_id;
        drop(file);
        let guard = cleanup_lock().lock().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let competing = directory.clone();
        let handle = std::thread::spawn(move || {
            sender
                .send(competing.remove_file_if_matches(&name, object_id))
                .unwrap();
        });

        assert!(receiver
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());
        drop(guard);
        receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap()
            .unwrap();
        handle.join().unwrap();

        drop(directory);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn directory_enumeration_budget_is_exact() {
        let mut budget = DirectoryEnumerationBudget::default();
        for _ in 0..MAX_PRIVATE_DIRECTORY_ENTRIES {
            budget.admit(1).unwrap();
        }
        assert!(budget.admit(1).is_err());

        let mut budget = DirectoryEnumerationBudget::default();
        assert!(budget.admit(MAX_PRIVATE_FILENAME_BYTES + 1).is_err());

        let mut budget = DirectoryEnumerationBudget::default();
        for _ in 0..(MAX_PRIVATE_DIRECTORY_NAME_BYTES / MAX_PRIVATE_FILENAME_BYTES) {
            budget.admit(MAX_PRIVATE_FILENAME_BYTES).unwrap();
        }
        assert!(budget.admit(1).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn replaceable_parent_is_rejected_before_creating_custody() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "crowd-cast-private-parent-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770)).unwrap();

        let error = PrivateDirectory::open_or_create(&root.join("state"), "test")
            .expect_err("a non-sticky writable parent must be rejected");

        assert!(format!("{error:#}").contains("replaceable group/world-writable"));
        assert!(!root.join("state").exists());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn competing_directory_custody_is_rejected() {
        let root = std::env::temp_dir().join(format!(
            "crowd-cast-private-instance-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let directory = PrivateDirectory::open_or_create(&root, "test").unwrap();

        let error = PrivateDirectory::open_or_create(&root, "competing test")
            .expect_err("one directory object must have only one collector custodian");

        assert!(format!("{error:#}").contains("exclusive custody"));
        drop(directory);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn replacement_acl_is_not_changed_before_identity_rejection() {
        let root = std::env::temp_dir().join(format!(
            "crowd-cast-private-delete-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let directory = PrivateDirectory::open_or_create(&root, "test").unwrap();
        let name = OsStr::new("artifact");
        let original = directory.create_private_file(name, "test").unwrap();
        let original_id = directory
            .snapshot_file(&original, "test")
            .unwrap()
            .object_id;
        drop(original);
        std::fs::rename(root.join(name), root.join("original")).unwrap();
        std::fs::write(root.join(name), b"replacement").unwrap();
        let replacement = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join(name))
            .unwrap();
        directory.make_test_acl_permissive(&replacement).unwrap();
        let acl_before = directory.test_acl_bytes(&replacement).unwrap();
        drop(replacement);

        directory
            .remove_file_if_matches(name, original_id)
            .expect_err("replacement identity must be rejected");

        let replacement = std::fs::OpenOptions::new()
            .read(true)
            .open(root.join(name))
            .unwrap();
        assert_eq!(directory.test_acl_bytes(&replacement).unwrap(), acl_before);
        drop(replacement);
        drop(directory);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn held_component_cannot_be_renamed_during_custody() {
        let root = std::env::temp_dir().join(format!(
            "crowd-cast-private-component-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let parent = root.join("parent");
        let directory = PrivateDirectory::open_or_create(&parent.join("held"), "test").unwrap();

        std::fs::rename(&parent, root.join("moved"))
            .expect_err("held Windows component must deny rename/delete sharing");

        drop(directory);
        std::fs::remove_dir_all(root).unwrap();
    }
}
