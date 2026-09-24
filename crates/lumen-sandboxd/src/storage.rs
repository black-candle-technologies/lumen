//! Per-run workspace disk.
//!
//! Firecracker's virtio-blk only supports raw images, so the workspace is a
//! raw ext4 filesystem. Each run gets its own copy of the read-only
//! template from the signed image, made with a single `cp` that prefers
//! filesystem-level copy-on-write and falls back to a sparse copy:
//!
//! ```text
//! cp --reflink=auto --sparse=always <template> <run>/workspace.raw
//! ```
//!
//! The guest NEVER gets a writable bind mount into the host project, and
//! the template is never hard-linked (a hard link would let guest block
//! writes dirty the template for every later run). Guest writes land in
//! the per-run copy; after execution the guest agent streams changed files
//! over vsock and the host validates + stages them ([`crate::export`]).
//! `destroy` deletes the copy; a failed or denied commit leaves the host
//! workspace unchanged because the copy is simply discarded.
//!
//! Disk quota: the host watches the copy's allocated blocks during the run
//! ([`crate::cgroups::check_quotas`]); the guest cannot exceed `disk_mib`
//! no matter what its own `df` claims. Allocated blocks (not apparent
//! size) are measured, because the template is a sparse file whose
//! apparent size is the full filesystem size.

use std::{os::unix::fs::MetadataExt, path::Path, process::Command};

use crate::error::SandboxdError;

/// Create the per-run workspace: a sparse (reflink-preferring) copy of the
/// template. The template must already be verified by
/// [`crate::provenance::resolve_image`].
///
/// Refuses to proceed if the destination would be a hard link to the
/// template: guest writes through the block device would then corrupt the
/// shared template.
pub fn create_workspace_copy(template: &Path, dest: &Path) -> Result<(), SandboxdError> {
    let out = Command::new("cp")
        .args([
            "--reflink=auto",
            "--sparse=always",
            &template.display().to_string(),
            &dest.display().to_string(),
        ])
        .output()
        .map_err(|e| SandboxdError::Host(format!("workspace copy failed to run: {e}")))?;
    if !out.status.success() {
        return Err(SandboxdError::Host(format!(
            "workspace copy failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    // The copy must be a distinct file: same (dev, ino) would mean the
    // guest could dirty the template through the block device.
    let t = std::fs::metadata(template).map_err(SandboxdError::Io)?;
    let d = std::fs::metadata(dest).map_err(SandboxdError::Io)?;
    if t.dev() == d.dev() && t.ino() == d.ino() {
        return Err(SandboxdError::Host(
            "workspace copy is a hard link to the template".into(),
        ));
    }
    Ok(())
}

/// Current host-side disk usage of the run's workspace copy, in bytes.
///
/// Measures allocated blocks (`st_blocks`), not apparent size: the copy is
/// sparse, so `metadata.len()` would report the full filesystem size even
/// when the guest has written nothing.
pub fn delta_bytes(dest: &Path) -> Result<u64, SandboxdError> {
    let md = std::fs::metadata(dest).map_err(SandboxdError::Io)?;
    Ok(md.blocks() * 512)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn copy_is_not_a_hard_link_and_delta_counts_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let template = dir.path().join("template.raw");
        // Sparse 16 MiB file with a little real data.
        let f = std::fs::File::create(&template).unwrap();
        f.set_len(16 * 1024 * 1024).unwrap();
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&template)
                .unwrap();
            f.write_all(b"hello template").unwrap();
        }
        let dest = dir.path().join("ws.raw");
        create_workspace_copy(&template, &dest).unwrap();

        // Distinct inode.
        let (t, d) = (
            std::fs::metadata(&template).unwrap(),
            std::fs::metadata(&dest).unwrap(),
        );
        assert!(!(t.dev() == d.dev() && t.ino() == d.ino()));

        // Same content.
        assert_eq!(
            std::fs::read(&template).unwrap(),
            std::fs::read(&dest).unwrap()
        );

        // Delta measures blocks, not apparent size: well under 16 MiB.
        let bytes = delta_bytes(&dest).unwrap();
        assert!(bytes < 16 * 1024 * 1024, "delta_bytes={bytes}");
        assert!(bytes > 0, "template data must occupy blocks");
    }
}
