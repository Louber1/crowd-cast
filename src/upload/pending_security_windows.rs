use super::FileSnapshot;
use anyhow::{bail, Context, Result};
use std::ffi::OsStr;
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, BOOL, BOOLEAN, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SetSecurityInfo, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FileBasicInfo, FileDispositionInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx, SetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    CREATE_NEW, DELETE, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_BASIC_INFO, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

#[derive(Debug)]
pub(super) struct Directory {
    file: File,
    path: PathBuf,
}

impl Directory {
    pub(super) fn open_or_create(path: &Path, label: &str) -> Result<Self> {
        let mut current = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Prefix(prefix) => current.push(prefix.as_os_str()),
                Component::RootDir => current.push(Path::new(r"\")),
                Component::CurDir => {}
                Component::Normal(name) => {
                    current.push(name);
                    match open_directory_path(&current, false) {
                        Ok(file) => reject_reparse_handle(&file, label, true)?,
                        Err(error) if is_not_found(&error) => create_directory(&current)?,
                        Err(error) => return Err(error),
                    }
                }
                Component::ParentDir => bail!("private directory path contains parent traversal"),
            }
        }
        let file = open_directory_path(path, true).with_context(|| {
            format!("failed to open {label} directory with a non-reparse handle {path:?}")
        })?;
        reject_reparse_handle(&file, label, true)?;
        apply_and_verify_owner_acl(&file, true)?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }

    pub(super) fn open_file(&self, name: &OsStr, writable: bool, label: &str) -> Result<File> {
        self.verify_path(&self.path, label)?;
        let file = open_file_path(&self.path.join(name), writable, false, None)
            .with_context(|| format!("failed to open private {label} file {name:?}"))?;
        reject_reparse_handle(&file, label, false)?;
        self.verify_path(&self.path, label)?;
        Ok(file)
    }

    pub(super) fn create_file(&self, name: &OsStr, label: &str) -> Result<File> {
        self.verify_path(&self.path, label)?;
        let file = with_owner_descriptor(false, |attributes| {
            open_file_path(&self.path.join(name), true, true, Some(attributes))
        })
        .with_context(|| format!("failed to create private {label} file {name:?}"))?;
        reject_reparse_handle(&file, label, false)?;
        self.verify_path(&self.path, label)?;
        Ok(file)
    }

    pub(super) fn secure_file(&self, file: &File, _label: &str) -> Result<()> {
        apply_and_verify_owner_acl(file, false)
    }

    pub(super) fn verify_entry(&self, name: &OsStr, file: &File, label: &str) -> Result<()> {
        self.verify_path(&self.path, label)?;
        let current = open_file_path(&self.path.join(name), false, false, None)
            .with_context(|| format!("failed to verify private {label} file {name:?}"))?;
        reject_reparse_handle(&current, label, false)?;
        if snapshot_handle(&current, label)?.object_id != snapshot_handle(file, label)?.object_id {
            bail!("private {label} directory entry changed while opening");
        }
        self.verify_path(&self.path, label)?;
        Ok(())
    }

    pub(super) fn remove_file(&self, name: &OsStr) -> std::io::Result<()> {
        let file = self
            .open_file(name, true, "deleted")
            .map_err(|error| io_error(&error))?;
        let disposition = FILE_DISPOSITION_INFO {
            DeleteFile: BOOLEAN(1),
        };
        unsafe {
            SetFileInformationByHandle(
                raw_handle(&file),
                FileDispositionInfo,
                (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;
        }
        Ok(())
    }

    pub(super) fn sync(&self, _path: &Path) -> Result<()> {
        self.file
            .sync_all()
            .context("failed to durably flush private Windows directory handle")
    }

    pub(super) fn snapshot(&self) -> Result<FileSnapshot> {
        snapshot_handle(&self.file, "private directory")
    }

    pub(super) fn snapshot_file(&self, file: &File, label: &str) -> Result<FileSnapshot> {
        verify_exact_owner_acl(file, false)?;
        snapshot_handle(file, label)
    }

    pub(super) fn verify_path(&self, path: &Path, label: &str) -> Result<()> {
        let current = open_directory_path(path, false)
            .with_context(|| format!("failed to verify private {label} directory path {path:?}"))?;
        reject_reparse_handle(&current, label, true)?;
        if snapshot_handle(&current, label)?.object_id != self.snapshot()?.object_id {
            bail!("private {label} directory path changed after capability acquisition");
        }
        Ok(())
    }
}

fn create_directory(path: &Path) -> Result<()> {
    with_owner_descriptor(true, |attributes| {
        let path = wide(path.as_os_str());
        unsafe { CreateDirectoryW(PCWSTR(path.as_ptr()), Some(attributes)) }
            .map_err(anyhow::Error::from)
    })
}

fn open_directory_path(path: &Path, writable: bool) -> Result<File> {
    let access = if writable {
        FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0
    } else {
        FILE_GENERIC_READ.0
    };
    let path = wide(path.as_os_str());
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .context("failed to open Windows directory handle")?;
    Ok(unsafe { File::from_raw_handle(handle.0) })
}

fn open_file_path(
    path: &Path,
    writable: bool,
    create_new: bool,
    attributes: Option<*const SECURITY_ATTRIBUTES>,
) -> Result<File> {
    let mut access = FILE_GENERIC_READ.0 | DELETE.0;
    if writable {
        access |= FILE_GENERIC_WRITE.0;
    }
    let path = wide(path.as_os_str());
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            attributes,
            if create_new {
                CREATE_NEW
            } else {
                OPEN_EXISTING
            },
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            None,
        )
    }
    .context("failed to open Windows file handle")?;
    Ok(unsafe { File::from_raw_handle(handle.0) })
}

fn reject_reparse_handle(file: &File, label: &str, directory: bool) -> Result<()> {
    let snapshot = snapshot_handle(file, label)?;
    let attributes = snapshot.mode_or_attributes as u32;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        bail!("private {label} object is a Windows reparse point");
    }
    let is_directory = attributes & 0x10 != 0;
    if is_directory != directory {
        bail!("private {label} object has the wrong Windows file type");
    }
    Ok(())
}

fn apply_and_verify_owner_acl(file: &File, directory: bool) -> Result<()> {
    with_current_user_sid(|user_sid| {
        with_descriptor_for_sid(user_sid, directory, |descriptor| {
            let mut present = BOOL::default();
            let mut defaulted = BOOL::default();
            let mut dacl: *mut ACL = std::ptr::null_mut();
            unsafe {
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
                    .context("failed to read constructed Windows DACL")?;
                if !present.as_bool() || dacl.is_null() {
                    bail!("constructed Windows security descriptor has no DACL");
                }
                SetSecurityInfo(
                    raw_handle(file),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    PSID::default(),
                    PSID::default(),
                    Some(dacl),
                    None,
                )
                .ok()
                .context("failed to set owner-only Windows DACL by handle")?;
            }
            Ok(())
        })?;
        verify_acl_for_sid(file, user_sid, directory)
    })
}

fn verify_exact_owner_acl(file: &File, directory: bool) -> Result<()> {
    with_current_user_sid(|sid| verify_acl_for_sid(file, sid, directory))
}

fn verify_acl_for_sid(file: &File, user_sid: PSID, directory: bool) -> Result<()> {
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        GetSecurityInfo(
            raw_handle(file),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            Some(&mut descriptor),
        )
        .ok()
        .context("failed to read Windows security by handle")?;
    }
    let _descriptor = LocalGuard(HLOCAL(descriptor.0));
    unsafe { EqualSid(owner, user_sid) }.context("Windows object owner is not the current user")?;
    if dacl.is_null() {
        bail!("Windows object has no owner-only DACL");
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
        .context("failed to inspect Windows DACL control")?;
    if control & SE_DACL_PROTECTED.0 == 0 {
        bail!("Windows object DACL still inherits access");
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    unsafe {
        GetAclInformation(
            dacl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
        .context("failed to inspect Windows DACL")?;
    }
    if info.AceCount != 1 {
        bail!("Windows object DACL grants more than one principal");
    }
    let mut ace_pointer = std::ptr::null_mut();
    unsafe { GetAce(dacl, 0, &mut ace_pointer) }.context("failed to inspect Windows DACL entry")?;
    let ace = unsafe { &*(ace_pointer.cast::<ACCESS_ALLOWED_ACE>()) };
    let expected_flags = if directory { 3 } else { 0 };
    if ace.Header.AceType != 0
        || ace.Header.AceFlags != expected_flags
        || ace.Mask != FILE_ALL_ACCESS.0
    {
        bail!("Windows object DACL is not the exact owner-only contract");
    }
    let ace_sid = PSID((&ace.SidStart as *const u32).cast_mut().cast());
    unsafe { EqualSid(ace_sid, user_sid) }
        .context("Windows object DACL grants a different principal")?;
    Ok(())
}

fn with_owner_descriptor<T>(
    directory: bool,
    action: impl FnOnce(*const SECURITY_ATTRIBUTES) -> Result<T>,
) -> Result<T> {
    with_current_user_sid(|sid| {
        with_descriptor_for_sid(sid, directory, |descriptor| {
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: BOOL(0),
            };
            action(&attributes)
        })
    })
}

fn with_descriptor_for_sid<T>(
    user_sid: PSID,
    directory: bool,
    action: impl FnOnce(PSECURITY_DESCRIPTOR) -> Result<T>,
) -> Result<T> {
    let mut sid_text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(user_sid, &mut sid_text) }
        .context("failed to format current Windows user SID")?;
    let sid_guard = LocalGuard(HLOCAL(sid_text.0.cast()));
    let inheritance = if directory { "OICI" } else { "" };
    let sddl = format!("D:P(A;{inheritance};FA;;;{})", unsafe {
        sid_text.to_string()?
    });
    drop(sid_guard);
    let sddl = wide(OsStr::new(&sddl));
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            1,
            &mut descriptor,
            None,
        )
    }
    .context("failed to construct owner-only Windows descriptor")?;
    let _descriptor = LocalGuard(HLOCAL(descriptor.0));
    action(descriptor)
}

fn with_current_user_sid<T>(action: impl FnOnce(PSID) -> Result<T>) -> Result<T> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .context("failed to open current Windows process token")?;
    let _token = HandleGuard(token);
    let mut length = 0;
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut length) };
    if length == 0 {
        bail!("Windows did not report a current-user token size");
    }
    let word = std::mem::size_of::<usize>();
    let mut buffer = vec![0usize; (length as usize).div_ceil(word)];
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            length,
            &mut length,
        )
    }
    .context("failed to read current Windows user SID")?;
    let sid = unsafe { (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    action(sid)
}

fn snapshot_handle(file: &File, label: &str) -> Result<FileSnapshot> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let mut basic = FILE_BASIC_INFO::default();
    unsafe {
        GetFileInformationByHandle(raw_handle(file), &mut information)
            .with_context(|| format!("failed to identify opened {label}"))?;
        GetFileInformationByHandleEx(
            raw_handle(file),
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
        .with_context(|| format!("failed to inspect opened {label}"))?;
    }
    let index = ((information.nFileIndexHigh as u64) << 32) | information.nFileIndexLow as u64;
    let size = ((information.nFileSizeHigh as u64) << 32) | information.nFileSizeLow as u64;
    Ok(FileSnapshot {
        object_id: (information.dwVolumeSerialNumber as u64, index),
        owner_id: 0,
        links: information.nNumberOfLinks as u64,
        size,
        modified: (basic.LastWriteTime, 0),
        changed: (basic.ChangeTime, 0),
        mode_or_attributes: basic.FileAttributes as u64,
    })
}

fn raw_handle(file: &File) -> HANDLE {
    HANDLE(file.as_raw_handle())
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn is_not_found(error: &anyhow::Error) -> bool {
    let io_missing = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .is_some_and(|cause| cause.kind() == std::io::ErrorKind::NotFound);
    let windows_missing = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<windows::core::Error>())
        .is_some_and(|cause| {
            cause.code() == windows::core::HRESULT::from_win32(2)
                || cause.code() == windows::core::HRESULT::from_win32(3)
        });
    io_missing || windows_missing
}

fn io_error(error: &anyhow::Error) -> std::io::Error {
    if is_not_found(error) {
        std::io::Error::new(std::io::ErrorKind::NotFound, format!("{error:#}"))
    } else {
        std::io::Error::new(std::io::ErrorKind::Other, format!("{error:#}"))
    }
}

struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct LocalGuard(HLOCAL);
impl Drop for LocalGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(self.0);
        }
    }
}
