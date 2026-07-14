use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{ambient_authority, fs::Dir};
use lumen_core::extension::{PluginManifest, Sha256Digest};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::extension_schema::{BoundedSchema, SchemaError, SchemaLimits};

const MANIFEST_NAME: &str = "lumen-plugin.toml";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageLimits {
    max_files: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
    schema: SchemaLimits,
}

impl PackageLimits {
    pub const fn new(
        max_files: usize,
        max_file_bytes: u64,
        max_total_bytes: u64,
        schema: SchemaLimits,
    ) -> Result<Self, PackageStageError> {
        if max_files == 0
            || max_file_bytes == 0
            || max_total_bytes == 0
            || max_file_bytes > max_total_bytes
        {
            return Err(PackageStageError::InvalidLimits);
        }
        Ok(Self {
            max_files,
            max_file_bytes,
            max_total_bytes,
            schema,
        })
    }
}

impl Default for PackageLimits {
    fn default() -> Self {
        Self::new(
            1_024,
            32 * 1024 * 1024,
            128 * 1024 * 1024,
            SchemaLimits::default(),
        )
        .expect("static package limits")
    }
}

#[derive(Clone, Debug)]
pub struct PackageStager {
    limits: PackageLimits,
}

impl PackageStager {
    pub const fn new(limits: PackageLimits) -> Self {
        Self { limits }
    }

    pub fn stage(
        &self,
        source: impl AsRef<Path>,
        quarantine_root: impl AsRef<Path>,
    ) -> Result<StagedPackage, PackageStageError> {
        let source = fs::canonicalize(source.as_ref())?;
        let source_meta = fs::symlink_metadata(&source)?;
        if !source_meta.file_type().is_dir() {
            return Err(PackageStageError::InvalidSource);
        }
        fs::create_dir_all(quarantine_root.as_ref())?;
        let quarantine_root = fs::canonicalize(quarantine_root.as_ref())?;
        if quarantine_root.starts_with(&source) {
            return Err(PackageStageError::InvalidQuarantine);
        }

        let mut snapshots = Vec::new();
        collect_files(&source, &source, 0, self.limits, &mut snapshots)?;
        snapshots.sort_by(|left, right| left.path.cmp(&right.path));
        if snapshots.is_empty() || snapshots.len() > self.limits.max_files {
            return Err(PackageStageError::TooManyFiles);
        }
        let total = snapshots.iter().try_fold(0_u64, |total, file| {
            total
                .checked_add(file.bytes.len() as u64)
                .ok_or(PackageStageError::PackageTooLarge)
        })?;
        if total > self.limits.max_total_bytes {
            return Err(PackageStageError::PackageTooLarge);
        }

        let manifest_bytes = snapshot(&snapshots, MANIFEST_NAME)?.bytes.as_slice();
        let manifest_text = std::str::from_utf8(manifest_bytes)
            .map_err(|_| PackageStageError::InvalidManifest("manifest is not UTF-8".into()))?;
        let manifest: PluginManifest = toml::from_str(manifest_text)
            .map_err(|error| PackageStageError::InvalidManifest(error.to_string()))?;
        validate_schemas(&manifest, &snapshots, self.limits.schema)?;

        let artifact = snapshot(&snapshots, manifest.runtime().entrypoint().as_str())?;
        if &artifact.digest != manifest.integrity().artifact() {
            return Err(PackageStageError::ArtifactDigestMismatch);
        }
        let artifact_digest = artifact.digest.clone();
        let canonical_manifest = serde_json::to_vec(&manifest)
            .map_err(|error| PackageStageError::InvalidManifest(error.to_string()))?;
        let manifest_digest = sha256(&canonical_manifest);
        let package_digest = package_digest(&snapshots);
        let destination = quarantine_root.join(package_digest.as_str());
        if !destination.exists() {
            write_snapshot(&quarantine_root, &destination, &snapshots)?;
        }
        verify_existing(&destination, &snapshots, self.limits)?;
        let files = snapshots
            .into_iter()
            .map(|file| (file.path, file.digest))
            .collect();
        Ok(StagedPackage {
            manifest,
            files,
            package_digest,
            manifest_digest,
            artifact_digest,
            quarantine_path: destination,
        })
    }
}

impl Default for PackageStager {
    fn default() -> Self {
        Self::new(PackageLimits::default())
    }
}

#[derive(Clone, Debug)]
pub struct StagedPackage {
    manifest: PluginManifest,
    files: BTreeMap<String, Sha256Digest>,
    package_digest: Sha256Digest,
    manifest_digest: Sha256Digest,
    artifact_digest: Sha256Digest,
    quarantine_path: PathBuf,
}

impl StagedPackage {
    pub const fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    pub const fn files(&self) -> &BTreeMap<String, Sha256Digest> {
        &self.files
    }

    pub const fn package_digest(&self) -> &Sha256Digest {
        &self.package_digest
    }

    pub const fn manifest_digest(&self) -> &Sha256Digest {
        &self.manifest_digest
    }

    pub const fn artifact_digest(&self) -> &Sha256Digest {
        &self.artifact_digest
    }

    pub fn quarantine_path(&self) -> &Path {
        &self.quarantine_path
    }
}

#[derive(Debug, Error)]
pub enum PackageStageError {
    #[error("package limits are invalid")]
    InvalidLimits,
    #[error("package source must be a directory")]
    InvalidSource,
    #[error("quarantine must not be inside the package source")]
    InvalidQuarantine,
    #[error("package path is not canonical UTF-8 ASCII: {0}")]
    InvalidPath(String),
    #[error("package contains an unsupported file: {0}")]
    UnsupportedFile(String),
    #[error("package contains too many files")]
    TooManyFiles,
    #[error("package file exceeds its limit: {0}")]
    FileTooLarge(String),
    #[error("package exceeds its aggregate byte limit")]
    PackageTooLarge,
    #[error("package file changed while it was read: {0}")]
    FileChanged(String),
    #[error("package is missing required file: {0}")]
    MissingFile(String),
    #[error("plugin manifest is invalid: {0}")]
    InvalidManifest(String),
    #[error("plugin schema is invalid: {0}")]
    InvalidSchema(#[from] SchemaError),
    #[error("declared artifact digest does not match the entrypoint")]
    ArtifactDigestMismatch,
    #[error("existing quarantined bytes do not match their content address")]
    QuarantineConflict,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug)]
struct FileSnapshot {
    path: String,
    bytes: Vec<u8>,
    digest: Sha256Digest,
}

fn collect_files(
    root: &Path,
    directory: &Path,
    depth: usize,
    limits: PackageLimits,
    output: &mut Vec<FileSnapshot>,
) -> Result<(), PackageStageError> {
    if depth > 32 {
        return Err(PackageStageError::InvalidPath(
            directory.display().to_string(),
        ));
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| PackageStageError::InvalidPath(path.display().to_string()))?;
        let normalized = normalize_path(relative)?;
        let metadata = fs::symlink_metadata(&path)?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(PackageStageError::UnsupportedFile(normalized));
        }
        if file_type.is_dir() {
            collect_files(root, &path, depth + 1, limits, output)?;
            continue;
        }
        if !file_type.is_file() || has_multiple_links(&metadata) {
            return Err(PackageStageError::UnsupportedFile(normalized));
        }
        if output.len() >= limits.max_files {
            return Err(PackageStageError::TooManyFiles);
        }
        if metadata.len() > limits.max_file_bytes {
            return Err(PackageStageError::FileTooLarge(normalized));
        }
        let mut file = open_no_follow(&path)?;
        let handle_before = file.metadata()?;
        if StableMetadata::from(&metadata) != StableMetadata::from(&handle_before) {
            return Err(PackageStageError::FileChanged(normalized));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)?;
        let handle_after = file.metadata()?;
        let after_metadata = fs::symlink_metadata(&path)?;
        if !after_metadata.file_type().is_file()
            || has_multiple_links(&after_metadata)
            || StableMetadata::from(&handle_before) != StableMetadata::from(&handle_after)
            || StableMetadata::from(&handle_after) != StableMetadata::from(&after_metadata)
            || bytes.len() as u64 != after_metadata.len()
        {
            return Err(PackageStageError::FileChanged(normalized));
        }
        output.push(FileSnapshot {
            path: normalized,
            digest: sha256(&bytes),
            bytes,
        });
    }
    Ok(())
}

fn normalize_path(path: &Path) -> Result<String, PackageStageError> {
    let value = path
        .to_str()
        .ok_or_else(|| PackageStageError::InvalidPath(path.display().to_string()))?;
    if value.is_empty()
        || value.len() > 4096
        || !value.is_ascii()
        || value.contains('\\')
        || value.split('/').any(|segment| {
            segment.is_empty()
                || segment == "."
                || segment == ".."
                || segment.bytes().any(|byte| byte.is_ascii_control())
        })
    {
        return Err(PackageStageError::InvalidPath(value.to_owned()));
    }
    Ok(value.to_owned())
}

fn snapshot<'a>(
    snapshots: &'a [FileSnapshot],
    path: &str,
) -> Result<&'a FileSnapshot, PackageStageError> {
    snapshots
        .binary_search_by_key(&path, |file| file.path.as_str())
        .map(|index| &snapshots[index])
        .map_err(|_| PackageStageError::MissingFile(path.to_owned()))
}

fn validate_schemas(
    manifest: &PluginManifest,
    snapshots: &[FileSnapshot],
    limits: SchemaLimits,
) -> Result<(), PackageStageError> {
    for component in manifest.components() {
        for path in [component.input_schema(), component.output_schema()] {
            compile_schema(snapshot(snapshots, path.as_str())?, limits)?;
        }
    }
    if let Some(settings) = manifest.settings() {
        compile_schema(snapshot(snapshots, settings.schema().as_str())?, limits)?;
    }
    Ok(())
}

fn compile_schema(snapshot: &FileSnapshot, limits: SchemaLimits) -> Result<(), PackageStageError> {
    let value = serde_json::from_slice(&snapshot.bytes)
        .map_err(|_| PackageStageError::InvalidSchema(SchemaError::InvalidSchema))?;
    BoundedSchema::compile(value, limits)?;
    Ok(())
}

fn package_digest(snapshots: &[FileSnapshot]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    for file in snapshots {
        hasher.update((file.path.len() as u64).to_be_bytes());
        hasher.update(file.path.as_bytes());
        hasher.update((file.bytes.len() as u64).to_be_bytes());
        hasher.update(file.digest.as_str().as_bytes());
    }
    parse_digest(hasher.finalize())
}

fn sha256(bytes: &[u8]) -> Sha256Digest {
    parse_digest(Sha256::digest(bytes))
}

fn parse_digest(bytes: impl std::fmt::LowerHex) -> Sha256Digest {
    Sha256Digest::parse(format!("{bytes:x}")).expect("SHA-256 output is canonical")
}

fn write_snapshot(
    root: &Path,
    destination: &Path,
    snapshots: &[FileSnapshot],
) -> Result<(), PackageStageError> {
    let temporary = root.join(format!(".staging-{}", Uuid::new_v4()));
    fs::create_dir(&temporary)?;
    let result = (|| {
        for file in snapshots {
            let target = temporary.join(&file.path);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&target, &file.bytes)?;
            let mut permissions = fs::metadata(&target)?.permissions();
            permissions.set_readonly(true);
            fs::set_permissions(&target, permissions)?;
        }
        fs::rename(&temporary, destination)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

fn verify_existing(
    destination: &Path,
    snapshots: &[FileSnapshot],
    limits: PackageLimits,
) -> Result<(), PackageStageError> {
    let mut actual = Vec::new();
    collect_files(destination, destination, 0, limits, &mut actual)
        .map_err(|_| PackageStageError::QuarantineConflict)?;
    actual.sort_by(|left, right| left.path.cmp(&right.path));
    if actual.len() != snapshots.len()
        || actual.iter().zip(snapshots).any(|(actual, expected)| {
            actual.path != expected.path || actual.digest != expected.digest
        })
    {
        return Err(PackageStageError::QuarantineConflict);
    }

    let directory = Dir::open_ambient_dir(destination, ambient_authority())
        .map_err(|_| PackageStageError::QuarantineConflict)?;
    for file in snapshots {
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let mut staged = directory
            .open_with(&file.path, &options)
            .map_err(|_| PackageStageError::QuarantineConflict)?;
        let mut bytes = Vec::with_capacity(file.bytes.len());
        staged
            .read_to_end(&mut bytes)
            .map_err(|_| PackageStageError::QuarantineConflict)?;
        if sha256(&bytes) != file.digest {
            return Err(PackageStageError::QuarantineConflict);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<fs::File, std::io::Error> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> Result<fs::File, std::io::Error> {
    fs::OpenOptions::new().read(true).open(path)
}

#[cfg(unix)]
fn has_multiple_links(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink() != 1
}

#[cfg(not(unix))]
fn has_multiple_links(_metadata: &fs::Metadata) -> bool {
    false
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StableMetadata {
    len: u64,
    modified_nanos: u128,
    identity: u128,
}

impl From<&fs::Metadata> for StableMetadata {
    fn from(metadata: &fs::Metadata) -> Self {
        Self {
            len: metadata.len(),
            modified_nanos: metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |duration| duration.as_nanos()),
            identity: file_identity(metadata),
        }
    }
}

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> u128 {
    use std::os::unix::fs::MetadataExt;
    (u128::from(metadata.dev()) << 64) | u128::from(metadata.ino())
}

#[cfg(not(unix))]
fn file_identity(_metadata: &fs::Metadata) -> u128 {
    0
}
