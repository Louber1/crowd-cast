use super::pending_security::PrivateDirectory;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArtifactSeal {
    directory: PrivateDirectory,
    name: OsString,
    pub(crate) path: PathBuf,
    pub(crate) size_bytes: u64,
    pub(crate) sha256: String,
}

impl ArtifactSeal {
    pub(super) fn from_stored(
        directory: &PrivateDirectory,
        path: PathBuf,
        size_bytes: u64,
        sha256: String,
    ) -> Result<Self> {
        if path.parent() != Some(directory.path()) {
            bail!("stored artifact is outside its private directory: {path:?}");
        }
        let name = path
            .file_name()
            .context("stored artifact has no filename")?
            .to_os_string();
        Ok(Self {
            directory: directory.clone(),
            name,
            path,
            size_bytes,
            sha256,
        })
    }

    pub(crate) fn seal(
        directory: &PrivateDirectory,
        name: &OsStr,
        role: &str,
        synchronize: bool,
    ) -> Result<Self> {
        Self::seal_with_hook(directory, name, role, synchronize, || Ok(()))
    }

    fn seal_with_hook(
        directory: &PrivateDirectory,
        name: &OsStr,
        role: &str,
        synchronize: bool,
        hook: impl FnOnce() -> Result<()>,
    ) -> Result<Self> {
        let mut file = directory.open_private_file(name, synchronize, role)?;
        let before = directory.snapshot_file(&file, role)?;
        directory.verify_entry(name, &file, role)?;
        if synchronize {
            file.sync_all()
                .with_context(|| format!("failed to synchronize pending {role} artifact"))?;
            directory.sync()?;
        }
        let (copied, digest) = hash_file(&mut file, role)?;
        hook()?;
        let (second_copy, second_digest) = hash_file(&mut file, role)?;
        let after = directory.snapshot_file(&file, role)?;
        if copied != before.size
            || second_copy != copied
            || second_digest != digest
            || after != before
        {
            bail!("pending {role} artifact changed while hashing");
        }
        directory.verify_entry(name, &file, role)?;
        file.seek(SeekFrom::Start(0))
            .with_context(|| format!("failed to rewind pending {role} artifact"))?;
        Ok(Self {
            directory: directory.clone(),
            name: name.to_os_string(),
            path: directory.path().join(name),
            size_bytes: copied,
            sha256: digest,
        })
    }

    pub(crate) fn verify(&self, role: &str) -> Result<()> {
        self.open_verified(role).map(|_| ())
    }

    pub(crate) fn open_verified(&self, role: &str) -> Result<File> {
        let mut file = self.directory.open_private_file(&self.name, false, role)?;
        self.verify_open_file(&mut file, role)?;
        Ok(file)
    }

    pub(crate) fn verify_open_file(&self, file: &mut File, role: &str) -> Result<()> {
        self.directory.verify_entry(&self.name, file, role)?;
        let before = self.directory.snapshot_file(file, role)?;
        if before.size != self.size_bytes {
            bail!("pending {role} artifact size changed: {:?}", self.path);
        }
        file.seek(SeekFrom::Start(0))
            .with_context(|| format!("failed to seek pending {role} artifact {:?}", self.path))?;
        let mut hasher = Sha256::new();
        let copied = std::io::copy(file, &mut hasher)
            .with_context(|| format!("failed to hash pending {role} artifact {:?}", self.path))?;
        let after = self.directory.snapshot_file(file, role)?;
        let sha256 = format!("{:x}", hasher.finalize());
        if copied != self.size_bytes || after != before || sha256 != self.sha256 {
            bail!("pending {role} artifact digest changed: {:?}", self.path);
        }
        self.directory.verify_entry(&self.name, file, role)?;
        file.seek(SeekFrom::Start(0))
            .with_context(|| format!("failed to rewind pending {role} artifact {:?}", self.path))?;
        Ok(())
    }

    pub(crate) fn exists(&self) -> Result<bool> {
        self.directory.contains_file(&self.name)
    }

    pub(crate) fn remove_if_present(&self) -> Result<()> {
        self.directory.remove_file_if_present(&self.name)
    }
}

fn hash_file(file: &mut File, role: &str) -> Result<(u64, String)> {
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("failed to seek pending {role} artifact"))?;
    let mut hasher = Sha256::new();
    let copied = std::io::copy(file, &mut hasher)
        .with_context(|| format!("failed to hash pending {role} artifact"))?;
    Ok((copied, format!("{:x}", hasher.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestPaths {
        root: PathBuf,
        output: PrivateDirectory,
    }

    impl TestPaths {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "crowd-cast-artifact-{name}-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            let output =
                PrivateDirectory::open_or_create(&root.join("recordings"), "recording").unwrap();
            Self { root, output }
        }

        fn write(&self, name: &str, bytes: &[u8]) {
            let mut file = self
                .output
                .create_private_file(OsStr::new(name), "artifact")
                .unwrap();
            std::io::Write::write_all(&mut file, bytes).unwrap();
            file.sync_all().unwrap();
        }
    }

    impl Drop for TestPaths {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(unix)]
    #[test]
    fn seal_rejects_a_symlink_without_reading_its_target() {
        use std::os::unix::fs::symlink;

        let paths = TestPaths::new("symlink");
        let target = paths.root.join("secret");
        std::fs::write(&target, b"secret bytes").unwrap();
        symlink(
            &target,
            paths.output.path().join("recording_session_seg0000.mp4"),
        )
        .unwrap();

        let error = ArtifactSeal::seal(
            &paths.output,
            OsStr::new("recording_session_seg0000.mp4"),
            "video",
            true,
        )
        .expect_err("artifact symlinks must be rejected");

        assert!(format!("{error:#}").contains("private video file"));
        assert_eq!(std::fs::read(target).unwrap(), b"secret bytes");
    }

    #[test]
    fn same_size_mutation_during_hash_is_rejected() {
        let paths = TestPaths::new("mutation");
        let name = OsStr::new("recording_session_seg0000.mp4");
        paths.write(name.to_str().unwrap(), b"before");
        let artifact_path = paths.output.path().join(name);

        let error = ArtifactSeal::seal_with_hook(&paths.output, name, "video", true, || {
            std::fs::write(&artifact_path, b"mutate")?;
            Ok(())
        })
        .expect_err("same-size mutation must invalidate admission");

        assert!(format!("{error:#}").contains("changed while hashing"));
    }

    #[cfg(unix)]
    #[test]
    fn path_swap_and_chmod_are_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let paths = TestPaths::new("swap");
        let name = OsStr::new("recording_session_seg0000.mp4");
        paths.write(name.to_str().unwrap(), b"sealed");
        let artifact_path = paths.output.path().join(name);
        let moved = paths.output.path().join("moved.mp4");

        let error = ArtifactSeal::seal_with_hook(&paths.output, name, "video", true, || {
            std::fs::rename(&artifact_path, &moved)?;
            std::fs::write(&artifact_path, b"sealed")?;
            std::fs::set_permissions(&moved, std::fs::Permissions::from_mode(0o644))?;
            Ok(())
        })
        .expect_err("path swap and permission mutation must invalidate admission");

        let text = format!("{error:#}");
        assert!(text.contains("changed while hashing") || text.contains("entry changed"));
    }
}
