//! Copy-on-write workspace layer.
//!
//! The guest NEVER gets a writable bind mount into the host project.
//! Instead each run gets a qcow2 overlay whose backing file is the
//! read-only workspace template from the signed image:
//!
//! ```text
//! qemu-img create -f qcow2 -b <template> -F qcow2 <run>/workspace.qcow2
//! ```
//!
//! Guest writes land in the per-run delta; the template is never modified.
//! After execution the guest agent streams changed files over vsock and the
//! host validates + stages them ([`crate::export`]). `destroy` deletes the
//! delta; a failed or denied commit leaves the host workspace unchanged
//! because the delta is simply discarded.
//!
//! Disk quota: the host watches the delta file size during the run
//! ([`crate::cgroups::check_quotas`]); the guest cannot exceed `disk_mib`
//! no matter what its own `df` claims.

use std::{path::Path, process::Command};

use crate::error::SandboxdError;

/// Build the `qemu-img create` argv. Pure: unit-tested.
pub fn qemu_img_create_args(template: &Path, dest: &Path) -> Vec<String> {
    vec![
        "create".into(),
        "-f".into(),
        "qcow2".into(),
        "-b".into(),
        template.display().to_string(),
        "-F".into(),
        "qcow2".into(),
        dest.display().to_string(),
    ]
}

/// Create the per-run CoW delta. The template must already be verified by
/// [`crate::provenance::resolve_image`].
pub fn create_workspace_disk(
    qemu_img: &Path,
    template: &Path,
    dest: &Path,
) -> Result<(), SandboxdError> {
    let args = qemu_img_create_args(template, dest);
    let out = Command::new(qemu_img)
        .args(&args)
        .output()
        .map_err(|e| SandboxdError::Host(format!("qemu-img not runnable: {e}")))?;
    if !out.status.success() {
        return Err(SandboxdError::Host(format!(
            "qemu-img create failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    // The delta must reference the template as its backing file — a delta
    // without a backing file would be a blank disk, not a CoW layer.
    verify_backing_file(qemu_img, dest, template)
}

/// Confirm `qemu-img info` reports the expected backing file.
fn verify_backing_file(qemu_img: &Path, dest: &Path, template: &Path) -> Result<(), SandboxdError> {
    let out = Command::new(qemu_img)
        .args(["info", &dest.display().to_string()])
        .output()
        .map_err(|e| SandboxdError::Host(format!("qemu-img not runnable: {e}")))?;
    let info = String::from_utf8_lossy(&out.stdout);
    let template_str = template.display().to_string();
    if !info.contains(&template_str) {
        return Err(SandboxdError::Host(format!(
            "workspace delta is not backed by the template ({template_str})"
        )));
    }
    Ok(())
}

/// Current delta size in bytes (host-side disk usage of the run).
pub fn delta_bytes(dest: &Path) -> Result<u64, SandboxdError> {
    Ok(std::fs::metadata(dest).map_err(SandboxdError::Io)?.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qemu_img_args_use_backing_file() {
        let args = qemu_img_create_args(
            Path::new("/images/tmpl.qcow2"),
            Path::new("/runs/lmn-1/ws.qcow2"),
        );
        assert_eq!(
            args,
            vec![
                "create",
                "-f",
                "qcow2",
                "-b",
                "/images/tmpl.qcow2",
                "-F",
                "qcow2",
                "/runs/lmn-1/ws.qcow2"
            ]
        );
        // Backing format pinned: a raw backing file would reinterpret bytes.
        assert!(args.contains(&"-F".to_string()));
    }
}
