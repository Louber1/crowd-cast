use super::{DirectoryEnumerationBudget, FileSnapshot};
use anyhow::{bail, Context, Result};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path};

const MAX_PROCESS_DESCRIPTOR_ENTRIES: usize = 65_536;

#[derive(Default)]
struct ProcessDescriptorScan {
    entries: usize,
}

impl ProcessDescriptorScan {
    fn admit_entry(&mut self) -> Result<()> {
        self.entries = self
            .entries
            .checked_add(1)
            .context("process descriptor entry count overflowed")?;
        if self.entries > MAX_PROCESS_DESCRIPTOR_ENTRIES {
            bail!("process descriptor table exceeds the SQLite attestation work limit");
        }
        Ok(())
    }

    fn parse_name(name: &OsStr) -> Result<RawFd> {
        let bytes = name.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 10
            || !bytes.iter().all(u8::is_ascii_digit)
            || (bytes.len() > 1 && bytes[0] == b'0')
        {
            bail!("process descriptor table contains a non-canonical descriptor name");
        }
        let value = std::str::from_utf8(bytes)
            .context("process descriptor name is not ASCII")?
            .parse::<u64>()
            .context("process descriptor name is outside the numeric range")?;
        if value > RawFd::MAX as u64 {
            bail!("process descriptor name exceeds the platform descriptor range");
        }
        Ok(value as RawFd)
    }
}

#[derive(Debug)]
pub(super) struct Directory {
    file: File,
}

impl Directory {
    pub(super) fn open_or_create(path: &Path, label: &str) -> Result<Self> {
        let mut current = open_directory_path(Path::new("/"))
            .context("failed to open filesystem root for private directory traversal")?;
        for component in path.components() {
            let name = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => name,
                _ => bail!("unsupported private directory component in {path:?}"),
            };
            validate_trusted_parent(&current, label)?;
            match open_directory_at(current.as_raw_fd(), name) {
                Ok(next) => current = next,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    mkdir_at(current.as_raw_fd(), name)?;
                    current = open_directory_at(current.as_raw_fd(), name).with_context(|| {
                        format!("failed to open newly created {label} directory component {name:?}")
                    })?;
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to open {label} directory without symlink traversal {path:?}"
                        )
                    });
                }
            }
        }
        if unsafe { libc::flock(current.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!("failed to lock {label} directory for exclusive custody")
            });
        }
        let directory = Self { file: current };
        directory.secure_directory(label)?;
        Ok(directory)
    }

    pub(super) fn open_file(&self, name: &OsStr, writable: bool, label: &str) -> Result<File> {
        let name = c_string(name)?;
        let access = if writable {
            libc::O_RDWR
        } else {
            libc::O_RDONLY
        };
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                access | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to open private {label} file {name:?}"));
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub(super) fn create_file(&self, name: &OsStr, label: &str) -> Result<File> {
        let name = c_string(name)?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to create private {label} file {name:?}"));
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub(super) fn secure_file(&self, file: &File, label: &str) -> Result<()> {
        let before = snapshot_fd(file.as_raw_fd(), label)?;
        if before.owner_id != unsafe { libc::geteuid() } as u64
            || before.links != 1
            || before.mode_or_attributes & libc::S_IFMT as u64 != libc::S_IFREG as u64
        {
            bail!("{label} is not a private regular file owned by this user");
        }
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to apply private file permissions");
        }
        let after = snapshot_fd(file.as_raw_fd(), label)?;
        if after.object_id != before.object_id || after.mode_or_attributes & 0o077 != 0 {
            bail!("{label} file changed while applying private permissions");
        }
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) }
                != 0
        {
            return Err(std::io::Error::last_os_error())
                .context("failed to clear nonblocking mode on private regular file");
        }
        Ok(())
    }

    pub(super) fn validate_private_file(&self, file: &File, label: &str) -> Result<FileSnapshot> {
        let snapshot = snapshot_fd(file.as_raw_fd(), label)?;
        if snapshot.owner_id != unsafe { libc::geteuid() } as u64
            || snapshot.links != 1
            || snapshot.mode_or_attributes & libc::S_IFMT as u64 != libc::S_IFREG as u64
            || snapshot.mode_or_attributes & 0o077 != 0
        {
            bail!("{label} is not an owner-only regular file owned by this user");
        }
        Ok(snapshot)
    }

    pub(super) fn verify_entry(&self, name: &OsStr, file: &File, label: &str) -> Result<()> {
        let name = c_string(name)?;
        let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                status.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to inspect private {label} directory entry"));
        }
        let entry = snapshot_stat(unsafe { status.assume_init() });
        let opened = snapshot_fd(file.as_raw_fd(), label)?;
        if entry.object_id != opened.object_id
            || entry.owner_id != opened.owner_id
            || entry.links != opened.links
            || entry.mode_or_attributes & libc::S_IFMT as u64 != libc::S_IFREG as u64
        {
            bail!("private {label} directory entry changed while opening");
        }
        Ok(())
    }

    pub(super) fn open_file_for_delete(&self, name: &OsStr, label: &str) -> Result<File> {
        self.open_file(name, true, label)
    }

    pub(super) fn remove_file(&self, name: &OsStr, file: &File) -> std::io::Result<()> {
        self.verify_entry(name, file, "deleted").map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("{error:#}"))
        })?;
        let name = c_string(name).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{error:#}"))
        })?;
        if unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn sync(&self, _path: &Path) -> Result<()> {
        self.file
            .sync_all()
            .context("failed to synchronize private directory handle")
    }

    pub(super) fn snapshot(&self) -> Result<FileSnapshot> {
        snapshot_fd(self.file.as_raw_fd(), "private directory")
    }

    pub(super) fn snapshot_file(&self, file: &File, label: &str) -> Result<FileSnapshot> {
        snapshot_fd(file.as_raw_fd(), label)
    }

    pub(super) fn file_names(&self) -> Result<Vec<OsString>> {
        let duplicate = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to duplicate private directory for enumeration");
        }
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(duplicate);
            }
            return Err(error).context("failed to enumerate private directory capability");
        }
        let mut names = Vec::new();
        let mut budget = DirectoryEnumerationBudget::default();
        loop {
            set_errno(0);
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                let error = current_errno();
                if error != 0 {
                    unsafe {
                        libc::closedir(stream);
                    }
                    return Err(std::io::Error::from_raw_os_error(error))
                        .context("failed while enumerating private directory capability");
                }
                break;
            }
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes != b"." && bytes != b".." {
                if let Err(error) = budget.admit(bytes.len()) {
                    unsafe {
                        libc::closedir(stream);
                    }
                    return Err(error);
                }
                names.push(OsString::from_vec(bytes.to_vec()));
            }
        }
        if unsafe { libc::closedir(stream) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to close private directory enumeration");
        }
        Ok(names)
    }

    pub(super) fn process_open_count(&self, expected_object_id: (u64, u64)) -> Result<usize> {
        #[cfg(target_os = "linux")]
        let descriptors = Path::new("/proc/self/fd");
        #[cfg(target_os = "macos")]
        let descriptors = Path::new("/dev/fd");
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        compile_error!("SQLite custody requires process descriptor attestation on Unix");
        let mut count = 0usize;
        let mut scan = ProcessDescriptorScan::default();
        for entry in std::fs::read_dir(descriptors)
            .context("failed to enumerate process descriptors for SQLite attestation")?
        {
            let entry = entry.context("failed to read process descriptor entry")?;
            scan.admit_entry()?;
            let descriptor = ProcessDescriptorScan::parse_name(&entry.file_name())?;
            match snapshot_fd(descriptor, "process descriptor") {
                Ok(snapshot) if snapshot.object_id == expected_object_id => count += 1,
                Ok(_) => {}
                Err(error) if raw_error(&error) == Some(libc::EBADF) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(count)
    }

    pub(super) fn verify_path(&self, path: &Path, label: &str) -> Result<()> {
        let path_file = open_existing_directory(path).with_context(|| {
            format!("failed to verify {label} directory path without symlink traversal {path:?}")
        })?;
        if snapshot_fd(path_file.as_raw_fd(), label)?.object_id != self.snapshot()?.object_id {
            bail!("{label} directory path changed after capability acquisition");
        }
        Ok(())
    }

    fn secure_directory(&self, label: &str) -> Result<()> {
        let before = self.snapshot()?;
        if before.owner_id != unsafe { libc::geteuid() } as u64
            || before.mode_or_attributes & libc::S_IFMT as u64 != libc::S_IFDIR as u64
        {
            bail!("{label} directory is not owned by this user");
        }
        if unsafe { libc::fchmod(self.file.as_raw_fd(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to make {label} directory private"));
        }
        let after = self.snapshot()?;
        if after.object_id != before.object_id || after.mode_or_attributes & 0o077 != 0 {
            bail!("{label} directory changed while applying private permissions");
        }
        Ok(())
    }
}

fn validate_trusted_parent(directory: &File, label: &str) -> Result<()> {
    let snapshot = snapshot_fd(directory.as_raw_fd(), label)?;
    let current_user = unsafe { libc::geteuid() } as u64;
    if snapshot.mode_or_attributes & libc::S_IFMT as u64 != libc::S_IFDIR as u64
        || (snapshot.owner_id != 0 && snapshot.owner_id != current_user)
    {
        bail!("{label} path has a directory parent outside the trusted ownership boundary");
    }
    let writable_by_others = snapshot.mode_or_attributes & 0o022 != 0;
    let sticky = snapshot.mode_or_attributes & libc::S_ISVTX as u64 != 0;
    if writable_by_others && !sticky {
        bail!("{label} path has a replaceable group/world-writable directory parent");
    }
    Ok(())
}

fn open_existing_directory(path: &Path) -> Result<File> {
    let mut current = open_directory_path(Path::new("/"))
        .context("failed to open filesystem root for private directory verification")?;
    for component in path.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            _ => bail!("unsupported private directory component in {path:?}"),
        };
        current = open_directory_at(current.as_raw_fd(), name)?;
    }
    Ok(current)
}

fn open_directory_path(path: &Path) -> std::io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_directory_at(parent: RawFd, name: &OsStr) -> std::io::Result<File> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn mkdir_at(parent: RawFd, name: &OsStr) -> Result<()> {
    let name = c_string(name)?;
    if unsafe { libc::mkdirat(parent, name.as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to create private directory component {name:?}"));
    }
    Ok(())
}

fn c_string(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).context("private custody path contains NUL")
}

fn snapshot_fd(fd: RawFd, label: &str) -> Result<FileSnapshot> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, status.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to inspect opened {label}"));
    }
    Ok(snapshot_stat(unsafe { status.assume_init() }))
}

fn raw_error(error: &anyhow::Error) -> Option<i32> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .and_then(std::io::Error::raw_os_error)
}

#[cfg(target_os = "linux")]
fn set_errno(value: i32) {
    unsafe {
        *libc::__errno_location() = value;
    }
}

#[cfg(target_os = "linux")]
fn current_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[cfg(target_os = "macos")]
fn set_errno(value: i32) {
    unsafe {
        *libc::__error() = value;
    }
}

#[cfg(target_os = "macos")]
fn current_errno() -> i32 {
    unsafe { *libc::__error() }
}

#[cfg(target_os = "macos")]
fn snapshot_stat(status: libc::stat) -> FileSnapshot {
    FileSnapshot {
        object_id: (status.st_dev as u64, status.st_ino as u64),
        owner_id: status.st_uid as u64,
        links: status.st_nlink as u64,
        size: status.st_size as u64,
        modified: (status.st_mtimespec.tv_sec, status.st_mtimespec.tv_nsec),
        changed: (status.st_ctimespec.tv_sec, status.st_ctimespec.tv_nsec),
        mode_or_attributes: status.st_mode as u64,
    }
}

#[cfg(not(target_os = "macos"))]
fn snapshot_stat(status: libc::stat) -> FileSnapshot {
    FileSnapshot {
        object_id: (status.st_dev as u64, status.st_ino as u64),
        owner_id: status.st_uid as u64,
        links: status.st_nlink as u64,
        size: status.st_size as u64,
        modified: (status.st_mtime, status.st_mtime_nsec),
        changed: (status.st_ctime, status.st_ctime_nsec),
        mode_or_attributes: status.st_mode as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_scan_admission_is_exact_and_canonical() {
        let mut scan = ProcessDescriptorScan::default();
        for _ in 0..MAX_PROCESS_DESCRIPTOR_ENTRIES {
            scan.admit_entry().unwrap();
        }
        assert!(scan.admit_entry().is_err());

        for invalid in ["", "00", "-1", "1x", "2147483648", "12345678901"] {
            assert!(ProcessDescriptorScan::parse_name(OsStr::new(invalid)).is_err());
        }
        assert_eq!(
            ProcessDescriptorScan::parse_name(OsStr::new("2147483647")).unwrap(),
            RawFd::MAX
        );
    }
}
