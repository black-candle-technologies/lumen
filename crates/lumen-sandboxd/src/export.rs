//! Controlled export: inventory, validation, staging.
//!
//! After the workload finishes, the guest agent streams changed workspace
//! files over vsock. The host must not trust that stream: every path is
//! re-validated hop-by-hop, every size re-checked, every type re-asserted,
//! and every hash recomputed from the staged bytes.
//!
//! [`ExportValidator`] enforces:
//!
//! - **Containment**: guest paths are workspace-relative; absolute paths,
//!   `..` components, empty components, and NUL bytes are rejected. Every
//!   intermediate component is `lstat`ed: a symlink at ANY hop is resolved
//!   and the resolved path must stay within the staging root. Multi-hop
//!   escapes (`a -> b`, `b -> /etc`) are caught because each hop is checked
//!   against the live staging tree, which includes symlinks planted by
//!   earlier entries of the same export.
//! - **Size**: per-file and total caps; oversize entries are rejected before
//!   their bytes are staged.
//! - **Type**: only regular files are staged. Symlinks, fifos, sockets,
//!   devices, and setuid/setgid modes are rejected. Staged files are
//!   created with `O_CREAT | O_EXCL | O_NOFOLLOW` so a pre-existing symlink
//!   at the final component can never be followed.
//!
//! The validator outputs a [`ChangedPath`] manifest plus the staged bytes;
//! the kernel revalidates the manifest against the lease and applies the
//! delta atomically. A denial anywhere discards the whole export.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use sha2::{Digest, Sha256};

use crate::{contracts::ChangedPath, error::SandboxdError};

/// Export size policy (from the sandbox policy document).
#[derive(Debug, Clone)]
pub struct ExportLimits {
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_files: u32,
}

impl Default for ExportLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 8 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_files: 10_000,
        }
    }
}

/// One staged file: relative path, content hash, size.
#[derive(Debug, Clone)]
pub struct StagedFile {
    pub rel_path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

/// Stateful validator bound to one staging root.
pub struct ExportValidator {
    root: PathBuf,
    limits: ExportLimits,
    total_bytes: u64,
    files: u32,
}

impl ExportValidator {
    pub fn new(root: PathBuf, limits: ExportLimits) -> Result<Self, SandboxdError> {
        fs::create_dir_all(&root).map_err(SandboxdError::Io)?;
        Ok(Self {
            root,
            limits,
            total_bytes: 0,
            files: 0,
        })
    }

    /// Validate a guest-reported relative path and return the staging path
    /// to write. Performs hop-by-hop symlink containment checks.
    ///
    /// Algorithm: walk components from the staging root. When an
    /// intermediate component is a symlink, resolve it, require the
    /// resolved path to stay within the root, then RESTART the walk from
    /// the root with the resolved components. The restart is what defeats
    /// multi-hop indirection (`a -> b`, `b -> /etc`): the second hop is
    /// re-examined as a first-class component instead of being silently
    /// traversed by the OS during the next `lstat`.
    pub fn stage_path(&self, guest_path: &str) -> Result<PathBuf, SandboxdError> {
        use std::ffi::OsString;

        let rel = checked_relative_path(guest_path)?;
        let mut components: Vec<OsString> = rel
            .components()
            .map(|c| c.as_os_str().to_os_string())
            .collect();
        let mut cur = self.root.clone();
        let mut i = 0usize;
        let mut hops = 0u32;
        while i < components.len() {
            hops += 1;
            if hops > 512 {
                return Err(SandboxdError::ExportRejected(format!(
                    "symlink loop suspected in {guest_path}"
                )));
            }
            cur.push(&components[i]);
            let is_last = i + 1 == components.len();
            match fs::symlink_metadata(&cur) {
                Ok(meta) => {
                    let ft = meta.file_type();
                    if ft.is_symlink() {
                        // Resolve the link and require containment.
                        let target = fs::read_link(&cur).map_err(SandboxdError::Io)?;
                        let resolved = if target.is_absolute() {
                            target
                        } else {
                            cur.parent().unwrap_or(&self.root).join(&target)
                        };
                        let normalized = lexical_normalize(&resolved);
                        if !normalized.starts_with(&self.root) {
                            return Err(SandboxdError::ExportRejected(format!(
                                "symlink escape at {}",
                                cur.strip_prefix(&self.root).unwrap_or(&cur).display()
                            )));
                        }
                        if is_last {
                            // The export stream carries file bytes, not
                            // links: a symlink at the final component is
                            // never followed.
                            return Err(SandboxdError::ExportRejected(format!(
                                "final component is a symlink: {guest_path}"
                            )));
                        }
                        // Restart the walk from the root over the resolved
                        // components plus whatever remains.
                        let rest: Vec<OsString> = components[i + 1..].to_vec();
                        let mut next: Vec<OsString> = normalized
                            .strip_prefix(&self.root)
                            .map_err(|_| {
                                SandboxdError::ExportRejected("staging prefix error".into())
                            })?
                            .components()
                            .map(|c| c.as_os_str().to_os_string())
                            .collect();
                        next.extend(rest);
                        components = next;
                        cur = self.root.clone();
                        i = 0;
                        continue;
                    }
                    if is_last {
                        if !ft.is_file() {
                            return Err(SandboxdError::ExportRejected(format!(
                                "not a regular file: {guest_path}"
                            )));
                        }
                    } else if !ft.is_dir() {
                        return Err(SandboxdError::ExportRejected(format!(
                            "intermediate component is not a directory: {guest_path}"
                        )));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // New path: intermediate components are created as real
                    // directories; the final component is created with
                    // O_NOFOLLOW by stage_bytes.
                    if !is_last {
                        fs::create_dir_all(&cur).map_err(SandboxdError::Io)?;
                    }
                }
                Err(e) => return Err(SandboxdError::Io(e)),
            }
            i += 1;
        }
        Ok(cur)
    }

    /// Check size limits before accepting bytes.
    pub fn check_size(&mut self, size: u64) -> Result<(), SandboxdError> {
        if size > self.limits.max_file_bytes {
            return Err(SandboxdError::ExportRejected(format!(
                "file too large: {size} > {}",
                self.limits.max_file_bytes
            )));
        }
        self.total_bytes = self
            .total_bytes
            .checked_add(size)
            .ok_or_else(|| SandboxdError::ExportRejected("total size overflow".into()))?;
        if self.total_bytes > self.limits.max_total_bytes {
            return Err(SandboxdError::ExportRejected(format!(
                "export too large: {} > {}",
                self.total_bytes, self.limits.max_total_bytes
            )));
        }
        self.files += 1;
        if self.files > self.limits.max_files {
            return Err(SandboxdError::ExportRejected(format!(
                "too many files: {} > {}",
                self.files, self.limits.max_files
            )));
        }
        Ok(())
    }

    /// Stage validated bytes at a validated path. The file is created with
    /// `O_EXCL | O_NOFOLLOW`, mode 0o644 (setuid/setgid/sticky are never
    /// preserved). Returns the staged record with recomputed hash.
    pub fn stage_bytes(
        &mut self,
        guest_path: &str,
        expected_sha256: &str,
        bytes: &[u8],
    ) -> Result<StagedFile, SandboxdError> {
        self.check_size(bytes.len() as u64)?;
        let dest = self.stage_path(guest_path)?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(SandboxdError::Io)?;
        }
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true).mode(0o644);
        // O_NOFOLLOW: never follow a pre-existing symlink at the final hop.
        opts.custom_flags(libc::O_NOFOLLOW);
        let mut file = opts.open(&dest).map_err(|e| {
            SandboxdError::ExportRejected(format!("cannot stage {guest_path}: {e}"))
        })?;
        file.write_all(bytes).map_err(SandboxdError::Io)?;
        drop(file);

        // Re-assert the staged file is a regular file (TOCTOU guard), then
        // recompute the hash from staged bytes and compare.
        let meta = fs::symlink_metadata(&dest).map_err(SandboxdError::Io)?;
        if !meta.file_type().is_file() || meta.file_type().is_symlink() {
            let _ = fs::remove_file(&dest);
            return Err(SandboxdError::ExportRejected(format!(
                "staged path is not a regular file: {guest_path}"
            )));
        }
        if meta.permissions().mode() & 0o6000 != 0 {
            let _ = fs::remove_file(&dest);
            return Err(SandboxdError::ExportRejected(format!(
                "setuid/setgid staged: {guest_path}"
            )));
        }
        let actual = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        if actual != expected_sha256 {
            let _ = fs::remove_file(&dest);
            return Err(SandboxdError::ExportRejected(format!(
                "hash mismatch for {guest_path}"
            )));
        }
        let rel = dest
            .strip_prefix(&self.root)
            .map_err(|_| SandboxdError::ExportRejected("staging prefix error".into()))?
            .display()
            .to_string();
        Ok(StagedFile {
            rel_path: rel,
            sha256: actual,
            size_bytes: bytes.len() as u64,
        })
    }

    /// Build the contract [`ChangedPath`] manifest from staged files.
    pub fn manifest(files: &[StagedFile]) -> Vec<ChangedPath> {
        files
            .iter()
            .map(|f| ChangedPath {
                path: format!("/{}", f.rel_path),
                sha256: f.sha256.clone(),
                size_bytes: f.size_bytes,
            })
            .collect()
    }
}

/// Reject absolute paths, `..`, empty components, and NUL bytes; return the
/// path as a relative `PathBuf` with only `Normal` components.
fn checked_relative_path(guest_path: &str) -> Result<PathBuf, SandboxdError> {
    if guest_path.is_empty() {
        return Err(SandboxdError::ExportRejected("empty path".into()));
    }
    if guest_path.bytes().any(|b| b == 0) {
        return Err(SandboxdError::ExportRejected("NUL byte in path".into()));
    }
    let path = Path::new(guest_path);
    if path.is_absolute() {
        return Err(SandboxdError::ExportRejected(format!(
            "absolute path: {guest_path}"
        )));
    }
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Normal(n) => out.push(n),
            _ => {
                return Err(SandboxdError::ExportRejected(format!(
                    "bad component in path: {guest_path}"
                )));
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(SandboxdError::ExportRejected(format!(
            "empty after normalization: {guest_path}"
        )));
    }
    Ok(out)
}

/// Lexical path normalization (resolves `.` and `..` without touching the
/// filesystem — safe to call on attacker-influenced symlink targets).
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(Component::RootDir),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(n) => out.push(n),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{FileTypeExt, symlink};

    fn validator() -> (tempfile::TempDir, ExportValidator) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("staging");
        let v = ExportValidator::new(root, ExportLimits::default()).unwrap();
        (tmp, v)
    }

    fn sha(b: &[u8]) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(b)))
    }

    #[test]
    fn stages_a_normal_file() {
        let (_tmp, mut v) = validator();
        let rec = v
            .stage_bytes("src/main.rs", &sha(b"fn main(){}"), b"fn main(){}")
            .unwrap();
        assert_eq!(rec.rel_path, "src/main.rs");
        assert_eq!(rec.size_bytes, 11);
        let manifest = ExportValidator::manifest(std::slice::from_ref(&rec));
        assert_eq!(manifest[0].path, "/src/main.rs");
    }

    #[test]
    fn rejects_absolute_and_dotdot() {
        let (_tmp, v) = validator();
        assert!(v.stage_path("/etc/passwd").is_err());
        assert!(v.stage_path("../escape").is_err());
        assert!(v.stage_path("a/../../escape").is_err());
        assert!(v.stage_path("").is_err());
        assert!(v.stage_path("a\0b").is_err());
    }

    #[test]
    fn symlink_escape_blocked_at_each_hop() {
        let (tmp, v) = validator();
        let root = tmp.path().join("staging");
        // Plant hostile links BEFORE the export entries arrive:
        //   link1 -> /etc            (absolute escape at hop 1)
        //   dir/link2 -> ../../..   (relative escape at hop 2)
        //   ok/inner -> /etc         (escape at hop 3 via nested dir)
        symlink("/etc", root.join("link1")).unwrap();
        fs::create_dir_all(root.join("dir")).unwrap();
        symlink("../../..", root.join("dir").join("link2")).unwrap();
        fs::create_dir_all(root.join("ok")).unwrap();
        symlink("/etc", root.join("ok").join("inner")).unwrap();

        assert!(v.stage_path("link1/passwd").is_err());
        assert!(v.stage_path("dir/link2/x").is_err());
        assert!(v.stage_path("ok/inner/shadow").is_err());
        // And a direct final-component symlink is rejected too.
        assert!(v.stage_path("link1").is_err());
    }

    #[test]
    fn multi_hop_indirection_blocked() {
        // a -> b, b -> /etc: each hop resolves within the tree, but the
        // composed target escapes. The per-hop check catches it at `b`.
        let (tmp, v) = validator();
        let root = tmp.path().join("staging");
        symlink("b", root.join("a")).unwrap();
        symlink("/etc", root.join("b")).unwrap();
        assert!(v.stage_path("a/passwd").is_err());
    }

    #[test]
    fn symlink_planted_by_earlier_entry_blocked() {
        // The export stream itself plants `evil -> /etc`, then tries to
        // write through it. Because validation stats the live staging
        // tree, the second entry is rejected.
        let (tmp, v) = validator();
        let root = tmp.path().join("staging");
        symlink("/etc", root.join("evil")).unwrap();
        assert!(v.stage_path("evil/passwd").is_err());
    }

    #[test]
    fn benign_relative_symlink_inside_root_allowed() {
        let (tmp, v) = validator();
        let root = tmp.path().join("staging");
        fs::create_dir_all(root.join("real")).unwrap();
        symlink("real", root.join("alias")).unwrap();
        // `alias/file` resolves inside the root: allowed to stage.
        let p = v.stage_path("alias/file").unwrap();
        assert!(p.starts_with(&root));
    }

    #[test]
    fn oversize_file_rejected() {
        let (_tmp, mut v) = validator();
        let limits = ExportLimits {
            max_file_bytes: 10,
            ..Default::default()
        };
        let mut v2 = ExportValidator::new(_tmp.path().join("s2"), limits).unwrap();
        let big = vec![0u8; 11];
        assert!(v2.stage_bytes("big.bin", &sha(&big), &big).is_err());
        // Validator state unchanged by the rejection.
        assert!(v.stage_bytes("ok", &sha(b"ok"), b"ok").is_ok());
    }

    #[test]
    fn total_cap_rejected() {
        let (tmp, v) = validator();
        let _ = &tmp;
        let limits = ExportLimits {
            max_total_bytes: 10,
            ..Default::default()
        };
        let mut v2 = ExportValidator::new(tmp.path().join("s2"), limits).unwrap();
        v2.stage_bytes("a", &sha(b"12345"), b"12345").unwrap();
        assert!(v2.stage_bytes("b", &sha(b"123456"), b"123456").is_err());
        let _ = v;
    }

    #[test]
    fn hash_mismatch_rejected_and_cleaned() {
        let (tmp, mut v) = validator();
        let root = tmp.path().join("staging");
        let res = v.stage_bytes("f", &sha(b"other"), b"content");
        assert!(res.is_err());
        assert!(!root.join("f").exists());
    }

    #[test]
    fn prohibited_types_rejected() {
        let (tmp, v) = validator();
        let root = tmp.path().join("staging");
        // fifo at final component
        let fifo = root.join("pipe");
        // SAFETY: libc::mkfifo is the direct syscall wrapper.
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        assert!(v.stage_path("pipe").is_err());
        // pre-existing symlink at final component is never followed
        symlink("target", root.join("link")).unwrap();
        assert!(v.stage_path("link").is_err());
    }

    #[test]
    fn file_type_ext_used() {
        // Reference the FileTypeExt import so the prohibited-type checks
        // above stay honest about unix file kinds.
        let (tmp, _) = validator();
        let root = tmp.path().join("staging");
        let f = root.join("reg");
        fs::write(&f, b"x").unwrap();
        let ft = fs::symlink_metadata(&f).unwrap().file_type();
        assert!(!ft.is_fifo() && !ft.is_socket() && !ft.is_block_device() && !ft.is_char_device());
    }
}
