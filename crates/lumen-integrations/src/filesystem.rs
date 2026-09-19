use std::{
    ffi::OsStr,
    io::{Read, Write},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
#[cfg(windows)]
use cap_std::fs::OpenOptionsExt as _;
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use lumen_core::{action::CanonicalValue, capability::WorkspacePath};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub struct WorkspaceReader {
    directory: Arc<Dir>,
    max_read_bytes: usize,
    max_write_bytes: usize,
}

impl WorkspaceReader {
    pub fn new(root: impl AsRef<Path>, max_output_bytes: usize) -> Result<Self, FilesystemError> {
        Self::with_limits(root, max_output_bytes, max_output_bytes)
    }

    pub fn with_limits(
        root: impl AsRef<Path>,
        max_read_bytes: usize,
        max_write_bytes: usize,
    ) -> Result<Self, FilesystemError> {
        if max_read_bytes == 0 {
            return Err(FilesystemError::InvalidOutputLimit);
        }
        if max_write_bytes == 0 {
            return Err(FilesystemError::InvalidWriteLimit);
        }

        let root = std::fs::canonicalize(root)
            .map_err(|error| FilesystemError::OpenWorkspace(error.to_string()))?;
        let directory = Dir::open_ambient_dir(&root, ambient_authority())
            .map_err(|error| FilesystemError::OpenWorkspace(error.to_string()))?;
        Ok(Self {
            directory: Arc::new(directory),
            max_read_bytes,
            max_write_bytes,
        })
    }

    pub async fn read_text(&self, path: &WorkspacePath) -> Result<String, FilesystemError> {
        let directory = clone_dir(&self.directory)?;
        let path = path.as_str().to_owned();
        let limit = self.max_read_bytes;

        tokio::task::spawn_blocking(move || read_required_text(&directory, &path, limit))
            .await
            .map_err(|error| FilesystemError::Read(error.to_string()))?
    }

    pub fn prepare_write(
        &self,
        path: &WorkspacePath,
        content: impl Into<String>,
    ) -> Result<PreparedFileWrite, FilesystemError> {
        let content = content.into();
        let actual = content.len();
        if actual > self.max_write_bytes {
            return Err(FilesystemError::WriteLimitExceeded {
                limit: self.max_write_bytes,
                actual,
            });
        }

        let directory = clone_dir(&self.directory)?;
        open_parent(&directory, Path::new(path.as_str()))?;
        let before = snapshot(&directory, path.as_str(), self.max_read_bytes)?;
        Ok(PreparedFileWrite {
            path: path.as_str().to_owned(),
            before,
            after: FileContent::new(content),
        })
    }

    pub async fn replace_text(&self, prepared: &PreparedFileWrite) -> Result<(), FilesystemError> {
        prepared.validate(self.max_write_bytes)?;
        let directory = clone_dir(&self.directory)?;
        let prepared = prepared.clone();
        let read_limit = self.max_read_bytes;

        tokio::task::spawn_blocking(move || {
            replace_text_blocking(&directory, &prepared, read_limit)
        })
        .await
        .map_err(|error| FilesystemError::Write(error.to_string()))?
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreparedFileWrite {
    path: String,
    before: FileSnapshot,
    after: FileContent,
}

impl PreparedFileWrite {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub const fn before(&self) -> &FileSnapshot {
        &self.before
    }

    pub const fn after(&self) -> &FileContent {
        &self.after
    }

    pub fn to_canonical_value(&self) -> Result<CanonicalValue, FilesystemError> {
        let value = serde_json::to_value(self)
            .map_err(|error| FilesystemError::InvalidPreparedWrite(error.to_string()))?;
        serde_json::from_value(value)
            .map_err(|error| FilesystemError::InvalidPreparedWrite(error.to_string()))
    }

    fn validate(&self, write_limit: usize) -> Result<(), FilesystemError> {
        WorkspacePath::parse(&self.path)
            .map_err(|error| FilesystemError::InvalidPreparedWrite(error.to_string()))?;
        self.before.validate()?;
        self.after.validate()?;
        if self.after.bytes > write_limit {
            return Err(FilesystemError::WriteLimitExceeded {
                limit: write_limit,
                actual: self.after.bytes,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileSnapshot {
    exists: bool,
    content: Option<String>,
    sha256: Option<String>,
    bytes: usize,
}

impl FileSnapshot {
    fn absent() -> Self {
        Self {
            exists: false,
            content: None,
            sha256: None,
            bytes: 0,
        }
    }

    fn present(content: String) -> Self {
        let bytes = content.len();
        let sha256 = Some(digest(content.as_bytes()));
        Self {
            exists: true,
            content: Some(content),
            sha256,
            bytes,
        }
    }

    pub const fn exists(&self) -> bool {
        self.exists
    }

    pub fn content(&self) -> Option<&str> {
        self.content.as_deref()
    }

    pub fn sha256(&self) -> Option<&str> {
        self.sha256.as_deref()
    }

    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    fn validate(&self) -> Result<(), FilesystemError> {
        match (&self.content, &self.sha256, self.exists) {
            (None, None, false) if self.bytes == 0 => Ok(()),
            (Some(content), Some(sha256), true)
                if self.bytes == content.len() && sha256 == &digest(content.as_bytes()) =>
            {
                Ok(())
            }
            _ => Err(FilesystemError::InvalidPreparedWrite(
                "before snapshot fields are inconsistent".into(),
            )),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileContent {
    content: String,
    sha256: String,
    bytes: usize,
}

impl FileContent {
    fn new(content: String) -> Self {
        let bytes = content.len();
        let sha256 = digest(content.as_bytes());
        Self {
            content,
            sha256,
            bytes,
        }
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    fn validate(&self) -> Result<(), FilesystemError> {
        if self.bytes == self.content.len() && self.sha256 == digest(self.content.as_bytes()) {
            Ok(())
        } else {
            Err(FilesystemError::InvalidPreparedWrite(
                "replacement content hash or byte length does not match".into(),
            ))
        }
    }
}

fn replace_text_blocking(
    directory: &Dir,
    prepared: &PreparedFileWrite,
    read_limit: usize,
) -> Result<(), FilesystemError> {
    let path = Path::new(prepared.path());
    let parent = open_parent(directory, path)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| FilesystemError::InvalidPreparedWrite("target has no file name".into()))?;
    if snapshot(directory, prepared.path(), read_limit)? != prepared.before {
        return Err(FilesystemError::WriteConflict);
    }

    let temp_name = next_temp_name();
    let result = write_and_replace(
        &parent, &temp_name, file_name, prepared, directory, read_limit,
    );
    if result.is_err() {
        let _ = parent.remove_file(&temp_name);
    }
    result
}

fn write_and_replace(
    parent: &Dir,
    temp_name: &str,
    file_name: &OsStr,
    prepared: &PreparedFileWrite,
    root: &Dir,
    read_limit: usize,
) -> Result<(), FilesystemError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(windows)]
    options.access_mode(
        windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE
            | windows_sys::Win32::Storage::FileSystem::DELETE,
    );
    let mut temp = parent
        .open_with(temp_name, &options)
        .map_err(|error| FilesystemError::Write(error.to_string()))?;

    if prepared.before.exists {
        let permissions = parent
            .symlink_metadata(file_name)
            .map_err(|_| FilesystemError::WriteConflict)?
            .permissions();
        temp.set_permissions(permissions)
            .map_err(|error| FilesystemError::Write(error.to_string()))?;
    }
    temp.write_all(prepared.after.content.as_bytes())
        .map_err(|error| FilesystemError::Write(error.to_string()))?;
    temp.sync_all()
        .map_err(|error| FilesystemError::Write(error.to_string()))?;
    if snapshot(root, prepared.path(), read_limit)? != prepared.before {
        return Err(FilesystemError::WriteConflict);
    }

    if prepared.before.exists {
        replace_existing(parent, &temp, temp_name, file_name)?;
        drop(temp);
    } else {
        drop(temp);
        parent
            .hard_link(temp_name, parent, file_name)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::AlreadyExists => FilesystemError::WriteConflict,
                _ => FilesystemError::Write(error.to_string()),
            })?;
        parent
            .remove_file(temp_name)
            .map_err(|error| FilesystemError::Write(error.to_string()))?;
    }

    sync_directory(parent)
}

#[cfg(unix)]
fn replace_existing(
    parent: &Dir,
    _temp: &cap_std::fs::File,
    temp_name: &str,
    file_name: &OsStr,
) -> Result<(), FilesystemError> {
    parent
        .rename(temp_name, parent, file_name)
        .map_err(|error| FilesystemError::Write(error.to_string()))
}

#[cfg(windows)]
fn replace_existing(
    parent: &Dir,
    temp: &cap_std::fs::File,
    _temp_name: &str,
    file_name: &OsStr,
) -> Result<(), FilesystemError> {
    use std::os::windows::{ffi::OsStrExt as _, io::AsRawHandle as _};
    use windows_sys::{
        Wdk::Storage::FileSystem::{
            FILE_RENAME_INFORMATION, FileRenameInformation, NtSetInformationFile,
            RtlNtStatusToDosErrorNoTeb,
        },
        Win32::System::IO::IO_STATUS_BLOCK,
    };

    let file_name = file_name.encode_wide().collect::<Vec<_>>();
    let file_name_byte_len = file_name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or_else(|| FilesystemError::Write("target file name is too long".into()))?;
    let byte_len = std::mem::size_of::<FILE_RENAME_INFORMATION>()
        .checked_add(file_name_byte_len)
        .ok_or_else(|| FilesystemError::Write("target file name is too long".into()))?;
    let mut storage = vec![0_usize; byte_len.div_ceil(std::mem::size_of::<usize>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    unsafe {
        (*info).Anonymous.ReplaceIfExists = true;
        (*info).RootDirectory = parent.as_raw_handle();
        (*info).FileNameLength = u32::try_from(file_name_byte_len)
            .map_err(|_| FilesystemError::Write("target file name is too long".into()))?;
        std::ptr::copy_nonoverlapping(
            file_name.as_ptr(),
            (*info).FileName.as_mut_ptr(),
            file_name.len(),
        );
    }
    let mut status_block = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtSetInformationFile(
            temp.as_raw_handle(),
            &mut status_block,
            info.cast(),
            u32::try_from(byte_len)
                .map_err(|_| FilesystemError::Write("target file name is too long".into()))?,
            FileRenameInformation,
        )
    };
    if status < 0 {
        let error = unsafe { RtlNtStatusToDosErrorNoTeb(status) };
        return Err(FilesystemError::Write(
            std::io::Error::from_raw_os_error(i32::try_from(error).unwrap_or(i32::MAX)).to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Dir) -> Result<(), FilesystemError> {
    let descriptor = rustix::fs::openat(
        directory,
        ".",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| FilesystemError::Write(error.to_string()))?;
    std::fs::File::from(descriptor)
        .sync_all()
        .map_err(|error| FilesystemError::Write(error.to_string()))
}

#[cfg(windows)]
fn sync_directory(_directory: &Dir) -> Result<(), FilesystemError> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_directory(directory: &Dir) -> Result<(), FilesystemError> {
    clone_dir(directory)?
        .into_std_file()
        .sync_all()
        .map_err(|error| FilesystemError::Write(error.to_string()))
}

fn snapshot(directory: &Dir, path: &str, limit: usize) -> Result<FileSnapshot, FilesystemError> {
    match read_optional_text(directory, path, limit)? {
        Some(content) => Ok(FileSnapshot::present(content)),
        None => Ok(FileSnapshot::absent()),
    }
}

fn read_required_text(
    directory: &Dir,
    path: &str,
    limit: usize,
) -> Result<String, FilesystemError> {
    read_optional_text(directory, path, limit)?.ok_or(FilesystemError::NotFound)
}

fn read_optional_text(
    directory: &Dir,
    path: &str,
    limit: usize,
) -> Result<Option<String>, FilesystemError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = match directory.open_with(path, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(map_open_error(error)),
    };
    let metadata = file
        .metadata()
        .map_err(|error| FilesystemError::Read(error.to_string()))?;
    if !metadata.is_file() {
        return Err(FilesystemError::AccessDenied);
    }
    let mut bytes = Vec::with_capacity(limit.min(8 * 1024));
    std::io::Read::by_ref(&mut file)
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| FilesystemError::Read(error.to_string()))?;
    if bytes.len() > limit {
        return Err(FilesystemError::OutputLimitExceeded { limit });
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| FilesystemError::InvalidUtf8)
}

fn open_parent(directory: &Dir, path: &Path) -> Result<Dir, FilesystemError> {
    match path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) => directory.open_dir(parent).map_err(map_open_error),
        None => clone_dir(directory),
    }
}

fn clone_dir(directory: &Dir) -> Result<Dir, FilesystemError> {
    directory
        .try_clone()
        .map_err(|error| FilesystemError::Read(error.to_string()))
}

fn next_temp_name() -> String {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!(".lumen-write-{}-{sequence}.tmp", std::process::id())
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn map_open_error(error: std::io::Error) -> FilesystemError {
    match error.kind() {
        std::io::ErrorKind::NotFound => FilesystemError::NotFound,
        std::io::ErrorKind::PermissionDenied => FilesystemError::AccessDenied,
        _ => FilesystemError::AccessDenied,
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FilesystemError {
    #[error("workspace could not be opened: {0}")]
    OpenWorkspace(String),
    #[error("path is outside the workspace or is not accessible")]
    AccessDenied,
    #[error("file was not found")]
    NotFound,
    #[error("file output exceeds the {limit}-byte limit")]
    OutputLimitExceeded { limit: usize },
    #[error("replacement is {actual} bytes and exceeds the {limit}-byte write limit")]
    WriteLimitExceeded { limit: usize, actual: usize },
    #[error("file is not valid UTF-8")]
    InvalidUtf8,
    #[error("file could not be read: {0}")]
    Read(String),
    #[error("file could not be written: {0}")]
    Write(String),
    #[error("file changed after the action preview was created")]
    WriteConflict,
    #[error("prepared file write is invalid: {0}")]
    InvalidPreparedWrite(String),
    #[error("output limit must be greater than zero")]
    InvalidOutputLimit,
    #[error("write limit must be greater than zero")]
    InvalidWriteLimit,
}
