//! Image and toolchain provenance.
//!
//! Every run records: guest-image digest, guest-kernel digest, rootfs
//! digest, toolchain manifest digest, and the sandbox policy version.
//! Images are promoted by digest only — never by floating tag — and every
//! manifest carries Ed25519 signatures from trusted release keys.
//!
//! Digest format throughout: `sha256:<64 hex chars>`.

use std::{
    collections::BTreeMap,
    fs::File,
    os::unix::fs::OpenOptionsExt,
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::SandboxdError;

/// Pinned toolchain that produced the guest image. Part of the signed
/// manifest so a run can be traced to an exact, reproducible build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainManifest {
    /// e.g. `lumen-image-builder`.
    pub builder: String,
    pub builder_version: String,
    /// Guest kernel release, e.g. `6.8.0-lumen`.
    pub kernel_version: String,
    /// sha256 of the kernel config used.
    pub kernel_config_digest: String,
    /// Tool -> pinned version (compiler, busybox, agent, ...).
    pub tool_versions: BTreeMap<String, String>,
    /// Whether the build claims reproducibility (two builds, same digest).
    pub reproducible: bool,
}

/// Signed image manifest. `image_digest` is the sha256 of the canonical
/// JSON of this struct *without* the `signatures` field (OCI-style).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageManifest {
    pub format_version: u32,
    /// sha256 of the guest kernel image bytes.
    pub kernel_digest: String,
    /// sha256 of the read-only guest rootfs bytes.
    pub rootfs_digest: String,
    /// sha256 of the read-only workspace template disk bytes.
    pub workspace_template_digest: String,
    /// Optional snapshot (mem + vmstate) for fast restore.
    pub snapshot: Option<SnapshotRef>,
    pub toolchain: ToolchainManifest,
    /// Sandbox policy document version this image was built/tested against.
    pub policy_version: String,
    pub created_unix: u64,
    #[serde(default)]
    pub signatures: Vec<ManifestSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRef {
    pub mem_digest: String,
    pub vmstate_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSignature {
    /// Key id (hex of the verifying key) that produced this signature.
    pub key_id: String,
    /// Raw 64-byte Ed25519 signature over the canonical manifest bytes.
    pub signature: String,
}

/// What gets journaled per run: the full provenance chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceRecord {
    pub image_digest: String,
    pub kernel_digest: String,
    pub rootfs_digest: String,
    pub workspace_template_digest: String,
    /// sha256 of the canonical toolchain manifest JSON.
    pub toolchain_digest: String,
    pub policy_version: String,
    /// sandboxd binary version that executed the run.
    pub sandboxd_version: String,
    pub firecracker_version: String,
}

impl ImageManifest {
    /// Canonical bytes covered by signatures: JSON of the manifest with
    /// `signatures` removed, keys sorted, no whitespace.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SandboxdError> {
        let mut unsigned = self.clone();
        unsigned.signatures = Vec::new();
        // BTreeMap-backed struct + serde_json with preserve order off:
        // serialize via a sorted Value to guarantee canonical form.
        let value = serde_json::to_value(&unsigned).map_err(SandboxdError::Json)?;
        let canonical = sort_value(value);
        serde_json::to_vec(&canonical).map_err(SandboxdError::Json)
    }

    /// `sha256:<hex>` of the canonical bytes.
    pub fn image_digest(&self) -> Result<String, SandboxdError> {
        Ok(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(self.canonical_bytes()?))
        ))
    }

    /// Sign with a release key; appends to `signatures`.
    pub fn sign(&mut self, key: &SigningKey) -> Result<(), SandboxdError> {
        let bytes = self.canonical_bytes()?;
        let sig: Signature = key.sign(&bytes);
        let verifying = key.verifying_key();
        self.signatures.push(ManifestSignature {
            key_id: hex::encode(verifying.as_bytes()),
            signature: hex::encode(sig.to_bytes()),
        });
        Ok(())
    }

    /// Verify that at least one signature validates against `trusted_keys`.
    /// Fails closed on: malformed digest, malformed signature, unknown key,
    /// or zero valid signatures.
    pub fn verify(&self, trusted_keys: &[VerifyingKey]) -> Result<(), SandboxdError> {
        if self.format_version != 1 {
            return Err(SandboxdError::BadSignature(format!(
                "unsupported format_version {}",
                self.format_version
            )));
        }
        let bytes = self.canonical_bytes()?;
        let expected_digest = self.image_digest()?;
        // The manifest does not self-carry its digest; callers compare the
        // computed digest against the requested one. Signatures bind the
        // content; the digest binds the reference.
        let _ = expected_digest;

        let mut ok = false;
        for sig in &self.signatures {
            let sig_bytes = hex::decode(&sig.signature)
                .map_err(|_| SandboxdError::BadSignature("bad signature hex".into()))?;
            let sig_bytes: [u8; 64] = sig_bytes
                .try_into()
                .map_err(|_| SandboxdError::BadSignature("bad signature length".into()))?;
            let signature = Signature::from_bytes(&sig_bytes);
            for key in trusted_keys {
                if hex::encode(key.as_bytes()) != sig.key_id {
                    continue;
                }
                if key.verify(&bytes, &signature).is_ok() {
                    ok = true;
                    break;
                }
            }
            if ok {
                break;
            }
        }
        if ok {
            Ok(())
        } else {
            Err(SandboxdError::BadSignature(
                "no valid signature from a trusted key".into(),
            ))
        }
    }

    /// sha256 of the canonical toolchain JSON.
    pub fn toolchain_digest(&self) -> Result<String, SandboxdError> {
        let value = serde_json::to_value(&self.toolchain).map_err(SandboxdError::Json)?;
        let canonical = sort_value(value);
        let bytes = serde_json::to_vec(&canonical).map_err(SandboxdError::Json)?;
        Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
    }
}

fn sort_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<String, serde_json::Value> =
                map.into_iter().map(|(k, v)| (k, sort_value(v))).collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(sort_value).collect())
        }
        other => other,
    }
}

/// sha256 of a file's bytes, as `sha256:<hex>`.
///
/// Opens the file with `O_NOFOLLOW`: a symlink at this path is rejected
/// instead of followed.
pub fn digest_file(path: &Path) -> Result<String, SandboxdError> {
    let file = open_nofollow(path)?;
    digest_open_file(&file)
}

/// sha256 of the bytes readable from an already-open file handle, as
/// `sha256:<hex>`. The handle's file offset is left untouched (a cloned
/// descriptor is hashed).
pub fn digest_open_file(file: &File) -> Result<String, SandboxdError> {
    use std::io::{Read, Seek};
    let mut view = file.try_clone().map_err(SandboxdError::Io)?;
    view.rewind().map_err(SandboxdError::Io)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = view.read(&mut buf).map_err(SandboxdError::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Open `path` for reading, refusing to follow a trailing symlink.
///
/// A symlink anywhere in the store is treated as hostile: resolution must
/// never silently read through one. `ELOOP` (symlink encountered) maps to
/// [`SandboxdError::UnapprovedImage`]; any other I/O failure maps to
/// [`SandboxdError::Io`].
pub fn open_nofollow(path: &Path) -> Result<File, SandboxdError> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                SandboxdError::UnapprovedImage(format!(
                    "symlink rejected in image store: {}",
                    path.display()
                ))
            } else {
                SandboxdError::Io(e)
            }
        })
}

/// Open a store entry directory itself, refusing a symlinked final
/// component. Artifact opens below go through `/proc/self/fd/<dirfd>/name`
/// so the directory cannot be swapped for a symlink between this open and
/// the artifact opens.
fn open_store_dir(dir: &Path) -> Result<File, SandboxdError> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(dir)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                SandboxdError::UnapprovedImage(format!(
                    "symlink rejected in image store: {}",
                    dir.display()
                ))
            } else {
                SandboxdError::UnapprovedImage(format!(
                    "image not in store: {} ({e})",
                    dir.display()
                ))
            }
        })
}

/// sha256 of in-memory bytes.
pub fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Read a key file and decide its format from the bytes: exactly 32 raw
/// bytes, or whitespace-trimmed 64-char hex. Bytes are read first (not
/// `read_to_string`) so raw keys containing invalid UTF-8 still load.
fn read_key_bytes(path: &Path) -> Result<[u8; 32], SandboxdError> {
    let bytes = std::fs::read(path)
        .map_err(|_| SandboxdError::State(format!("cannot read key {}", path.display())))?;
    if bytes.len() == 32 {
        // Raw 32-byte key file.
        return bytes
            .try_into()
            .map_err(|_| SandboxdError::State("key must be 32 bytes".into()));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| SandboxdError::State("key must be 32 raw bytes or 64 hex chars".into()))?;
    let text = text.trim();
    if text.len() != 64 {
        return Err(SandboxdError::State(
            "key must be 32 raw bytes or 64 hex chars".into(),
        ));
    }
    let decoded = hex::decode(text).map_err(|_| SandboxdError::State("bad key hex".into()))?;
    decoded
        .try_into()
        .map_err(|_| SandboxdError::State("key must be 32 bytes".into()))
}

/// Load a trusted Ed25519 public key from a file. Accepts raw 32 bytes or
/// 64-char hex.
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey, SandboxdError> {
    let arr = read_key_bytes(path)?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|_| SandboxdError::State("invalid ed25519 public key".into()))
}

/// Load a signing (private) key from a file: 64-char hex seed or 32 raw bytes.
pub fn load_signing_key(path: &Path) -> Result<SigningKey, SandboxdError> {
    let arr = read_key_bytes(path)?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Approved image on disk: `<store>/<image_digest>/`.
///
/// The `artifacts` are pinned open file descriptors (`O_NOFOLLOW`),
/// digest-verified at open time. Launch code must hand these descriptors
/// onward and re-hash them immediately before use — it must never re-join
/// `dir` by path, which would re-open the TOCTOU window between
/// verification and launch.
///
/// `File` is neither `Clone` nor `Debug`, so this struct is intentionally
/// neither: pinned descriptors are moved, never copied, and never logged.
pub struct StoredImage {
    pub dir: PathBuf,
    pub manifest: ImageManifest,
    pub image_digest: String,
    pub artifacts: Vec<PinnedArtifact>,
}

/// One launch artifact with its descriptor pinned.
///
/// `file` was opened `O_NOFOLLOW` (through a pinned, non-symlink store
/// directory) and its bytes hashed against `expected_digest` at open time.
/// The descriptor pins the exact inode that was verified: replacing the
/// path in the store afterwards does not affect this handle. Callers must
/// still re-hash via [`digest_open_file`] immediately before use, because
/// the bytes of a still-writable inode could change under the open handle.
pub struct PinnedArtifact {
    /// File name inside the store entry (`vmlinux`, `rootfs.ext4`, ...).
    pub name: String,
    /// Pinned open descriptor of the verified bytes.
    pub file: File,
    /// `sha256:<hex>` from the signed manifest.
    pub expected_digest: String,
}

impl PinnedArtifact {
    /// `/proc/self/fd/<n>` path for this pinned descriptor. Always resolves
    /// to the verified inode regardless of what the store directory
    /// contains now. For inspection only — hard links must go through
    /// [`Self::hard_link_into`], not this path.
    pub fn fd_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }

    /// Create a hard link to the pinned inode at `dst`.
    ///
    /// Uses `linkat(AT_EMPTY_PATH)` on the descriptor itself — never a
    /// path — so the link always refers to the verified inode even if the
    /// store changed underneath us. (Linking through the `/proc/self/fd`
    /// magic symlink is rejected with `EXDEV` by the kernel; `AT_EMPTY_PATH`
    /// is the supported API for descriptor-relative linking.)
    pub fn hard_link_into(&self, dst: &Path) -> Result<(), SandboxdError> {
        let c_dst = std::ffi::CString::new(dst.as_os_str().as_encoded_bytes())
            .map_err(|e| SandboxdError::Host(format!("link destination contains NUL: {e}")))?;
        // SAFETY: with AT_EMPTY_PATH, `oldfd` names the file to link and
        // the empty oldpath is ignored; c_dst is a valid NUL-terminated
        // path; AT_FDCWD interprets it relative to the cwd.
        let rc = unsafe {
            libc::linkat(
                self.file.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_FDCWD,
                c_dst.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        };
        if rc != 0 {
            return Err(SandboxdError::Host(format!(
                "hard-link {}: {}",
                self.name,
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
}

// Manual Debug: name the artifacts, never the descriptors.
impl std::fmt::Debug for PinnedArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedArtifact")
            .field("name", &self.name)
            .field("expected_digest", &self.expected_digest)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for StoredImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredImage")
            .field("dir", &self.dir)
            .field("image_digest", &self.image_digest)
            .field(
                "artifacts",
                &self
                    .artifacts
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// Open one artifact through the pinned store-directory descriptor and
/// verify its bytes against the manifest digest. The returned
/// [`PinnedArtifact`] pins the verified inode.
fn open_pinned_artifact(
    store_dir: &File,
    name: &str,
    expected_digest: &str,
) -> Result<PinnedArtifact, SandboxdError> {
    // Resolve `name` against the open directory descriptor: immune to
    // renames/symlink swaps of the store path after the dir was opened.
    // `name` is a fixed literal chosen by us, never caller input.
    let via_fd = PathBuf::from(format!("/proc/self/fd/{}/{}", store_dir.as_raw_fd(), name));
    let file = open_nofollow(&via_fd)?;
    let actual = digest_open_file(&file)?;
    if actual != expected_digest {
        return Err(SandboxdError::BadSignature(format!(
            "artifact {name} digest mismatch: {actual} != {expected_digest}"
        )));
    }
    Ok(PinnedArtifact {
        name: name.to_string(),
        file,
        expected_digest: expected_digest.to_string(),
    })
}

/// Harden one image-store entry: the daemon runs as root and the store is
/// a trust root, so every resolve re-asserts tight ownership and modes.
///
/// `store_dir` is the already-pinned entry descriptor (opened
/// `O_NOFOLLOW | O_DIRECTORY` by [`open_store_dir`]): every entry is
/// opened through it with `O_NOFOLLOW` and hardened via its own
/// descriptor (`fchown` / `fchmod`). The fd pins the exact inode that was
/// inspected, so an entry swapped for a symlink between the type check
/// and the chmod can no longer redirect the chmod at an attacker-chosen
/// target.
///
/// - Entry dir: root:root, 0755. Artifact/manifest files: root:root, 0644.
/// - Symlinks inside the entry are left untouched (never followed, never
///   re-owned); resolution rejects them anyway.
/// - When running as root, `chattr +i` is applied best-effort to the
///   artifact and manifest files so even a privileged writer cannot mutate
///   them without first clearing the flag. Filesystems that do not support
///   immutable flags (tmpfs, some overlays) simply skip it.
///
/// Assumption (documented, not enforced here): the store is populated by a
/// privileged promotion flow running under a restrictive umask (027), and
/// no uid other than root can write to the store. The jailer uids that run
/// guests never gain store write access.
pub fn harden_store_entry(store_dir: &File) -> Result<(), SandboxdError> {
    use std::os::unix::io::AsRawFd;

    let is_root = unsafe { libc::geteuid() } == 0;
    let dir_fd = store_dir.as_raw_fd();
    let err = |what: &str| {
        SandboxdError::Host(format!("cannot harden image store (fd {dir_fd}): {what}"))
    };

    // fchown/fchmod on a pinned descriptor: never follows a trailing
    // symlink. Best-effort: a failed chown/chmod must not break
    // resolution in odd environments (and chown is skipped entirely when
    // not root, e.g. dev-machine tests).
    let fchown = |file: &File| {
        if !is_root {
            return;
        }
        // SAFETY: as_raw_fd yields a valid open descriptor owned by `file`.
        let _ = unsafe { libc::fchown(file.as_raw_fd(), 0, 0) };
    };
    let fchmod = |file: &File, mode: u32| {
        // SAFETY: as_raw_fd yields a valid open descriptor owned by `file`.
        let _ = unsafe { libc::fchmod(file.as_raw_fd(), mode) };
    };

    fchown(store_dir);
    fchmod(store_dir, 0o755);

    // Enumerate through the pinned descriptor: the listing cannot be
    // redirected at a different directory after the pin.
    let via_fd = PathBuf::from(format!("/proc/self/fd/{dir_fd}"));
    let entries = std::fs::read_dir(&via_fd).map_err(|e| err(&e.to_string()))?;
    let mut immutables: Vec<File> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| err(&e.to_string()))?;
        // Open through the pinned dir with O_NOFOLLOW: a symlink entry
        // fails with ELOOP and is skipped untouched, and the returned fd
        // pins the inode that fstat/fchmod/fchown below all act on —
        // closing the stat-then-chmod swap window.
        let entry_path = via_fd.join(entry.file_name());
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&entry_path)
        {
            Ok(f) => f,
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => continue,
            Err(e) => return Err(err(&e.to_string())),
        };
        let ft = file
            .metadata()
            .map_err(|e| err(&e.to_string()))?
            .file_type();
        // Defense in depth: O_NOFOLLOW already rejected symlinks; never
        // touch one if it somehow got through.
        if ft.is_symlink() {
            continue;
        }
        fchown(&file);
        if ft.is_dir() {
            fchmod(&file, 0o755);
        } else if ft.is_file() {
            fchmod(&file, 0o644);
            immutables.push(file);
        }
        // Other types (fifo, socket, device): re-owned above, modes left
        // alone — same as before.
    }
    // Immutable flag where feasible: gated on root, best-effort, failures
    // ignored (unsupported fs, missing binary, containers, ...). Uses the
    // pinned /proc/self/fd path so the flag lands on the hardened inode,
    // not whatever the store path names now.
    if is_root {
        for file in &immutables {
            let fd_path = format!("/proc/self/fd/{}", file.as_raw_fd());
            let _ = std::process::Command::new("chattr")
                .args(["+i", &fd_path])
                .output();
        }
    }
    Ok(())
}

/// Resolve and authenticate an image by digest. Fails closed when: the
/// digest is malformed, the store entry is missing, the manifest signature
/// is invalid, the computed digest mismatches, or any artifact digest in
/// the manifest mismatches the bytes on disk.
///
/// Every open in this function is `O_NOFOLLOW` (symlinks rejected), the
/// store directory itself is pinned before artifacts are opened through
/// it, and the returned [`StoredImage`] carries pinned descriptors — not
/// paths — for the launch artifacts. [`harden_store_entry`] re-asserts
/// store ownership and modes on every successful resolve.
pub fn resolve_image(
    store: &Path,
    image_digest: &str,
    trusted_keys: &[VerifyingKey],
) -> Result<StoredImage, SandboxdError> {
    if !is_digest(image_digest) {
        return Err(SandboxdError::UnapprovedImage(format!(
            "malformed digest: {image_digest}"
        )));
    }
    // Digest is `[0-9a-f:]` only — safe to join as a path component, and it
    // cannot name a different directory. The dir itself is then opened
    // O_NOFOLLOW|O_DIRECTORY so a symlinked entry is rejected outright.
    let dir = store.join(image_digest);
    let store_dir = open_store_dir(&dir)?;
    let manifest_path = PathBuf::from(format!(
        "/proc/self/fd/{}/manifest.json",
        store_dir.as_raw_fd()
    ));
    let manifest_file = open_nofollow(&manifest_path)?;
    let text = std::io::read_to_string(manifest_file).map_err(|_| {
        SandboxdError::UnapprovedImage(format!("image not in store: {image_digest}"))
    })?;
    let manifest: ImageManifest = serde_json::from_str(&text)
        .map_err(|_| SandboxdError::BadSignature("manifest is not valid JSON".into()))?;
    manifest.verify(trusted_keys)?;

    let computed = manifest.image_digest()?;
    if computed != image_digest {
        return Err(SandboxdError::BadSignature(format!(
            "manifest digest mismatch: computed {computed} != requested {image_digest}"
        )));
    }

    // Verify every referenced artifact against the bytes on disk, pinning
    // the verified descriptors. This is what makes the digest a real
    // binding, not a label. Launch artifacts are pinned; snapshot files
    // (not used at launch — snapshots restore via the API load path, and
    // JailSpec carries `snapshot: None`) are digest-verified but not pinned.
    let mut artifacts = Vec::new();
    for (name, expected) in [
        ("vmlinux", manifest.kernel_digest.as_str()),
        ("rootfs.ext4", manifest.rootfs_digest.as_str()),
        (
            "workspace-template.raw",
            manifest.workspace_template_digest.as_str(),
        ),
    ] {
        artifacts.push(open_pinned_artifact(&store_dir, name, expected)?);
    }
    if let Some(snap) = &manifest.snapshot {
        // Snapshot files are digest-verified (not pinned: snapshots restore
        // via the API load path and JailSpec carries `snapshot: None`, so
        // they are not launch artifacts). Opened through the pinned store
        // dir like everything else — never via a re-joined mutable path.
        for (name, expected) in [
            ("snapshot.mem", snap.mem_digest.as_str()),
            ("snapshot.vmstate", snap.vmstate_digest.as_str()),
        ] {
            let _ = open_pinned_artifact(&store_dir, name, expected)?;
        }
    }

    harden_store_entry(&store_dir)?;

    Ok(StoredImage {
        dir,
        manifest,
        image_digest: image_digest.to_string(),
        artifacts,
    })
}

/// `sha256:` + 64 lowercase hex chars.
pub fn is_digest(s: &str) -> bool {
    let hex = s.strip_prefix("sha256:").unwrap_or("");
    hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn test_manifest() -> ImageManifest {
        let mut tools = BTreeMap::new();
        tools.insert("gcc".into(), "13.2.0".into());
        tools.insert("busybox".into(), "1.36.1".into());
        tools.insert("lumen-guest-agent".into(), "0.1.0".into());
        ImageManifest {
            format_version: 1,
            kernel_digest: "sha256:".to_string() + &"a".repeat(64),
            rootfs_digest: "sha256:".to_string() + &"b".repeat(64),
            workspace_template_digest: "sha256:".to_string() + &"c".repeat(64),
            snapshot: None,
            toolchain: ToolchainManifest {
                builder: "lumen-image-builder".into(),
                builder_version: "0.1.0".into(),
                kernel_version: "6.8.0-lumen".into(),
                kernel_config_digest: "sha256:".to_string() + &"d".repeat(64),
                tool_versions: tools,
                reproducible: true,
            },
            policy_version: "sandbox-policy-v1".into(),
            created_unix: 1_700_000_000,
            signatures: vec![],
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = key(0x11);
        let mut m = test_manifest();
        m.sign(&key).unwrap();
        assert!(m.verify(&[key.verifying_key()]).is_ok());
    }

    #[test]
    fn tampered_manifest_fails_verification() {
        let key = key(0x11);
        let mut m = test_manifest();
        m.sign(&key).unwrap();
        m.policy_version = "sandbox-policy-EVIL".into();
        assert!(m.verify(&[key.verifying_key()]).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let signing_key = key(0x11);
        let other = key(0x22);
        let mut m = test_manifest();
        m.sign(&signing_key).unwrap();
        assert!(m.verify(&[other.verifying_key()]).is_err());
    }

    #[test]
    fn unsigned_manifest_fails_verification() {
        let key = key(0x11);
        let m = test_manifest();
        assert!(m.verify(&[key.verifying_key()]).is_err());
    }

    #[test]
    fn canonical_bytes_are_stable() {
        let m = test_manifest();
        assert_eq!(m.canonical_bytes().unwrap(), m.canonical_bytes().unwrap());
        // Field order in JSON must not matter.
        let json = serde_json::to_string(&m).unwrap();
        let reparsed: ImageManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(
            m.canonical_bytes().unwrap(),
            reparsed.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn resolve_image_verifies_artifact_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let key = key(0x11);

        let kernel = b"fake-kernel";
        let rootfs = b"fake-rootfs";
        let ws = b"fake-workspace-template";
        let mut m = test_manifest();
        m.kernel_digest = digest_bytes(kernel);
        m.rootfs_digest = digest_bytes(rootfs);
        m.workspace_template_digest = digest_bytes(ws);
        m.sign(&key).unwrap();
        let digest = m.image_digest().unwrap();

        let dir = tmp.path().join(&digest);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("manifest.json"), serde_json::to_vec(&m).unwrap()).unwrap();
        std::fs::write(dir.join("vmlinux"), kernel).unwrap();
        std::fs::write(dir.join("rootfs.ext4"), rootfs).unwrap();
        std::fs::write(dir.join("workspace-template.raw"), ws).unwrap();

        let resolved = resolve_image(tmp.path(), &digest, &[key.verifying_key()]).unwrap();
        assert_eq!(resolved.image_digest, digest);

        // Tamper with one artifact: resolution must fail.
        std::fs::write(dir.join("rootfs.ext4"), b"tampered").unwrap();
        assert!(resolve_image(tmp.path(), &digest, &[key.verifying_key()]).is_err());
    }

    #[test]
    fn resolve_rejects_unknown_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let key = key(0x11);
        let digest = "sha256:".to_string() + &"f".repeat(64);
        assert!(resolve_image(tmp.path(), &digest, &[key.verifying_key()]).is_err());
    }

    #[test]
    fn resolve_rejects_malformed_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let key = key(0x11);
        // Path traversal attempt disguised as a digest.
        assert!(resolve_image(tmp.path(), "../../etc", &[key.verifying_key()]).is_err());
    }

    #[test]
    fn is_digest_strict() {
        assert!(is_digest(&("sha256:".to_string() + &"a".repeat(64))));
        assert!(!is_digest("sha256:abc"));
        assert!(!is_digest("md5:"));
        assert!(!is_digest(
            "../sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }

    /// Build a fully valid store entry; returns (store tmpdir, image
    /// digest, signing key).
    fn valid_store() -> (tempfile::TempDir, String, SigningKey) {
        let tmp = tempfile::tempdir().unwrap();
        let k = key(0x77);
        let kernel = b"vmlinux-bytes";
        let rootfs = b"rootfs-bytes";
        let ws = b"workspace-bytes";
        let mut m = test_manifest();
        m.kernel_digest = digest_bytes(kernel);
        m.rootfs_digest = digest_bytes(rootfs);
        m.workspace_template_digest = digest_bytes(ws);
        m.sign(&k).unwrap();
        let digest = m.image_digest().unwrap();
        let dir = tmp.path().join(&digest);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("manifest.json"), serde_json::to_vec(&m).unwrap()).unwrap();
        std::fs::write(dir.join("vmlinux"), kernel).unwrap();
        std::fs::write(dir.join("rootfs.ext4"), rootfs).unwrap();
        std::fs::write(dir.join("workspace-template.raw"), ws).unwrap();
        (tmp, digest, k)
    }

    #[test]
    fn resolve_image_rejects_symlinked_artifact() {
        let (store, digest, k) = valid_store();
        let dir = store.path().join(&digest);
        // Swap one artifact for a symlink: resolution must fail closed
        // instead of following it.
        std::fs::remove_file(dir.join("vmlinux")).unwrap();
        std::os::unix::fs::symlink(dir.join("rootfs.ext4"), dir.join("vmlinux")).unwrap();
        let err = resolve_image(store.path(), &digest, &[k.verifying_key()]).unwrap_err();
        assert!(
            matches!(err, SandboxdError::UnapprovedImage(_)),
            "expected UnapprovedImage, got {err:?}"
        );
    }

    #[test]
    fn resolve_image_rejects_symlinked_store_dir() {
        let (store, digest, k) = valid_store();
        let dir = store.path().join(&digest);
        let real = store.path().join("real-entry");
        std::fs::rename(&dir, &real).unwrap();
        std::os::unix::fs::symlink(&real, &dir).unwrap();
        let err = resolve_image(store.path(), &digest, &[k.verifying_key()]).unwrap_err();
        assert!(
            matches!(err, SandboxdError::UnapprovedImage(_)),
            "expected UnapprovedImage, got {err:?}"
        );
    }

    #[test]
    fn resolve_image_rejects_symlinked_manifest() {
        let (store, digest, k) = valid_store();
        let dir = store.path().join(&digest);
        std::fs::rename(dir.join("manifest.json"), dir.join("manifest.json.real")).unwrap();
        std::os::unix::fs::symlink(dir.join("manifest.json.real"), dir.join("manifest.json"))
            .unwrap();
        assert!(resolve_image(store.path(), &digest, &[k.verifying_key()]).is_err());
    }

    #[test]
    fn open_nofollow_rejects_symlink_directly() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        std::fs::write(&target, b"data").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = open_nofollow(&link).unwrap_err();
        assert!(
            matches!(err, SandboxdError::UnapprovedImage(_)),
            "expected UnapprovedImage, got {err:?}"
        );
        // A regular file still opens.
        assert!(open_nofollow(&target).is_ok());
    }

    #[test]
    fn raw_key_with_invalid_utf8_loads() {
        // Regression: the loaders used read_to_string first, so a raw
        // 32-byte key containing invalid UTF-8 failed before the raw
        // fallback ran. Most random keys are invalid UTF-8.
        let tmp = tempfile::tempdir().unwrap();
        let seed = [0xffu8; 32]; // invalid UTF-8
        assert!(std::str::from_utf8(&seed).is_err());
        let raw_path = tmp.path().join("signing.raw");
        std::fs::write(&raw_path, seed).unwrap();
        let sk = load_signing_key(&raw_path).unwrap();
        assert_eq!(sk.to_bytes(), seed);

        let vk_path = tmp.path().join("verify.raw");
        let vk_bytes = sk.verifying_key().to_bytes();
        std::fs::write(&vk_path, vk_bytes).unwrap();
        let vk = load_verifying_key(&vk_path).unwrap();
        assert_eq!(vk.to_bytes(), vk_bytes);
    }

    #[test]
    fn hex_key_still_loads() {
        let tmp = tempfile::tempdir().unwrap();
        let seed = [0x11u8; 32];
        let hex_path = tmp.path().join("signing.hex");
        // Trailing newline, as written by shell redirection.
        std::fs::write(&hex_path, format!("{}\n", hex::encode(seed))).unwrap();
        let sk = load_signing_key(&hex_path).unwrap();
        assert_eq!(sk.to_bytes(), seed);
    }

    #[test]
    fn malformed_key_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let bad = tmp.path().join("bad");
        std::fs::write(&bad, b"too short").unwrap();
        assert!(load_signing_key(&bad).is_err());
        assert!(load_verifying_key(&bad).is_err());
        let bad_hex = tmp.path().join("badhex");
        std::fs::write(&bad_hex, "zz".repeat(32)).unwrap();
        assert!(load_signing_key(&bad_hex).is_err());
    }

    #[test]
    fn resolve_image_pins_verified_descriptors() {
        let (store, digest, k) = valid_store();
        let stored = resolve_image(store.path(), &digest, &[k.verifying_key()]).unwrap();
        assert_eq!(stored.artifacts.len(), 3);
        let names: Vec<&str> = stored.artifacts.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["vmlinux", "rootfs.ext4", "workspace-template.raw"]);
        // The pinned descriptors hash to the manifest digests, and their
        // /proc/self/fd paths resolve to real files.
        for a in &stored.artifacts {
            assert_eq!(digest_open_file(&a.file).unwrap(), a.expected_digest);
            assert!(a.fd_path().exists());
        }
        assert_eq!(
            stored.artifacts[0].expected_digest,
            stored.manifest.kernel_digest
        );
    }

    #[test]
    fn harden_store_entry_sets_modes() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("entry");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("vmlinux");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let pinned = open_store_dir(&dir).unwrap();
        harden_store_entry(&pinned).unwrap();
        let fm = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        let dm = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(fm, 0o644, "file mode");
        assert_eq!(dm, 0o755, "dir mode");
    }

    #[test]
    fn harden_store_entry_skips_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("entry");
        std::fs::create_dir_all(&dir).unwrap();
        let outside = tmp.path().join("outside");
        std::fs::write(&outside, b"secret").unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("evil-link")).unwrap();
        // Must not fail, and must not touch the link target's mode.
        let pinned = open_store_dir(&dir).unwrap();
        harden_store_entry(&pinned).unwrap();
        let m = std::fs::metadata(&outside).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o600, "link target must be untouched");
    }

    #[test]
    fn harden_store_entry_uses_pinned_fd_not_path() {
        // Pin the entry, then swap the path for a different directory
        // before hardening: the modes must land on the pinned inodes,
        // not on whatever the path names at hardening time.
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("entry");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vmlinux"), b"x").unwrap();
        std::fs::set_permissions(dir.join("vmlinux"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let pinned = open_store_dir(&dir).unwrap();
        let swapped = tmp.path().join("swapped");
        std::fs::create_dir_all(&swapped).unwrap();
        std::fs::write(swapped.join("vmlinux"), b"y").unwrap();
        std::fs::set_permissions(
            swapped.join("vmlinux"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::rename(&dir, tmp.path().join("entry-orig")).unwrap();
        std::fs::rename(&swapped, &dir).unwrap();

        harden_store_entry(&pinned).unwrap();

        // The pinned (original) entry was hardened...
        let orig = tmp.path().join("entry-orig").join("vmlinux");
        let fm = std::fs::metadata(&orig).unwrap().permissions().mode() & 0o777;
        assert_eq!(fm, 0o644, "pinned entry hardened");
        // ...and the swapped-in directory was NOT touched.
        let sm = std::fs::metadata(dir.join("vmlinux"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(sm, 0o600, "swapped-in path untouched");
    }
}
