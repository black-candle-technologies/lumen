use std::{io::Read, path::Path};

use cap_std::{ambient_authority, fs::Dir};
use lumen_core::capability::WorkspacePath;
use thiserror::Error;

pub struct WorkspaceReader {
    directory: Dir,
    max_output_bytes: usize,
}

impl WorkspaceReader {
    pub fn new(root: impl AsRef<Path>, max_output_bytes: usize) -> Result<Self, FilesystemError> {
        if max_output_bytes == 0 {
            return Err(FilesystemError::InvalidOutputLimit);
        }

        let directory = Dir::open_ambient_dir(root, ambient_authority())
            .map_err(|error| FilesystemError::OpenWorkspace(error.to_string()))?;
        Ok(Self {
            directory,
            max_output_bytes,
        })
    }

    pub async fn read_text(&self, path: &WorkspacePath) -> Result<String, FilesystemError> {
        let directory = self
            .directory
            .try_clone()
            .map_err(|error| FilesystemError::Read(error.to_string()))?;
        let path = path.as_str().to_owned();
        let limit = self.max_output_bytes;

        tokio::task::spawn_blocking(move || {
            let mut file = directory.open(&path).map_err(map_open_error)?;
            let mut bytes = Vec::with_capacity(limit.min(8 * 1024));
            file.by_ref()
                .take(limit.saturating_add(1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|error| FilesystemError::Read(error.to_string()))?;
            if bytes.len() > limit {
                return Err(FilesystemError::OutputLimitExceeded { limit });
            }
            String::from_utf8(bytes).map_err(|_| FilesystemError::InvalidUtf8)
        })
        .await
        .map_err(|error| FilesystemError::Read(error.to_string()))?
    }
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
    #[error("file is not valid UTF-8")]
    InvalidUtf8,
    #[error("file could not be read: {0}")]
    Read(String),
    #[error("output limit must be greater than zero")]
    InvalidOutputLimit,
}
