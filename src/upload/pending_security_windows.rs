use super::FileSnapshot;
use anyhow::{bail, Result};
use std::ffi::OsStr;
use std::fs::File;
use std::path::Path;

#[derive(Debug)]
pub(super) struct Directory;

impl Directory {
    pub(super) fn open_or_create(_path: &Path, _label: &str) -> Result<Self> {
        bail!("private durable upload custody requires the validated Windows handle contract")
    }

    pub(super) fn open_file(&self, _name: &OsStr, _writable: bool, _label: &str) -> Result<File> {
        bail!("private durable upload custody is unavailable")
    }

    pub(super) fn create_file(&self, _name: &OsStr, _label: &str) -> Result<File> {
        bail!("private durable upload custody is unavailable")
    }

    pub(super) fn secure_file(&self, _file: &File, _label: &str) -> Result<()> {
        bail!("private durable upload custody is unavailable")
    }

    pub(super) fn verify_entry(&self, _name: &OsStr, _file: &File, _label: &str) -> Result<()> {
        bail!("private durable upload custody is unavailable")
    }

    pub(super) fn remove_file(&self, _name: &OsStr) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "private durable upload custody is unavailable",
        ))
    }

    pub(super) fn sync(&self, _path: &Path) -> Result<()> {
        bail!("private durable upload custody is unavailable")
    }

    pub(super) fn snapshot(&self) -> Result<FileSnapshot> {
        bail!("private durable upload custody is unavailable")
    }

    pub(super) fn snapshot_file(&self, _file: &File, _label: &str) -> Result<FileSnapshot> {
        bail!("private durable upload custody is unavailable")
    }

    pub(super) fn verify_path(&self, _path: &Path, _label: &str) -> Result<()> {
        bail!("private durable upload custody is unavailable")
    }
}
