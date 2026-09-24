//! Attachment quarantine: type, size, and sandbox checks before content
//! reaches Pi.
//!
//! Attachments never travel as raw bytes in a [`crate::envelope::MessageEnvelope`];
//! they travel as [`AttachmentRef`]s pointing at quarantined content. Release
//! requires passing the policy checks below and (when configured) a sandbox
//! scan. Export of quarantined content is governed by the same policy.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Default per-attachment size cap: 25 MiB.
pub const DEFAULT_MAX_ATTACHMENT_BYTES: u64 = 25 * 1024 * 1024;

/// Media types that are never admitted, regardless of allowlists.
/// Executables and active script containers have no place in agent input.
pub const ALWAYS_BLOCKED_MEDIA_TYPES: &[&str] = &[
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-executable",
    "application/x-elf",
    "application/x-mach-binary",
    "application/x-sh",
    "application/x-bat",
    "application/vnd.microsoft.portable-executable",
];

/// Opaque reference to a quarantined attachment. The envelope carries this,
/// never the bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttachmentRef {
    /// Opaque handle the host uses to locate the quarantined bytes.
    pub reference_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    pub media_type: String,
    pub size_bytes: u64,
    /// SHA-256 hex of the received bytes, computed at quarantine time.
    pub sha256: String,
    pub quarantine: QuarantineStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    /// Held; not yet cleared for use.
    Held,
    /// Passed policy + scan; may be referenced by tools.
    Released,
    /// Rejected with a reason; bytes are dropped.
    Rejected { reason: String },
}

/// Policy for admitting attachments.
#[derive(Clone, Debug)]
pub struct AttachmentPolicy {
    pub max_bytes: u64,
    /// If set, only media types with one of these prefixes are admitted
    /// (e.g. `image/`, `text/`). Checked after the always-blocked list.
    pub allowed_media_type_prefixes: Option<Vec<String>>,
    /// Additional blocked prefixes beyond [`ALWAYS_BLOCKED_MEDIA_TYPES`].
    pub blocked_media_type_prefixes: Vec<String>,
}

impl Default for AttachmentPolicy {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
            allowed_media_type_prefixes: None,
            blocked_media_type_prefixes: Vec::new(),
        }
    }
}

impl AttachmentPolicy {
    /// A conservative default for agent input: images, text, and PDFs only.
    pub fn conservative() -> Self {
        Self {
            max_bytes: 10 * 1024 * 1024,
            allowed_media_type_prefixes: Some(vec![
                "image/".to_owned(),
                "text/".to_owned(),
                "application/pdf".to_owned(),
            ]),
            blocked_media_type_prefixes: Vec::new(),
        }
    }
}

/// Result of a sandbox scan of attachment bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScanVerdict {
    Clean,
    Malicious {
        reason: String,
    },
    /// The scanner could not decide. Fail closed: the attachment stays held.
    Inconclusive {
        reason: String,
    },
}

/// Pluggable sandbox scanner. The host wires in the real scanner (sandbox
/// execution of type-specific validators); the default posture without a
/// scanner is to hold.
pub trait AttachmentScanner: Send + Sync {
    fn scan(&self, attachment: &AttachmentRef, bytes: &[u8]) -> ScanVerdict;
}

/// A scanner that always reports inconclusive, forcing hold.
#[derive(Clone, Copy, Debug, Default)]
pub struct HoldAllScanner;

impl AttachmentScanner for HoldAllScanner {
    fn scan(&self, _attachment: &AttachmentRef, _bytes: &[u8]) -> ScanVerdict {
        ScanVerdict::Inconclusive {
            reason: "no sandbox scanner configured".to_owned(),
        }
    }
}

/// The quarantined attachment: bytes plus their admission state.
#[derive(Clone, Debug)]
pub struct QuarantinedAttachment {
    pub reference: AttachmentRef,
    /// Bytes are present only while held/released; dropped on rejection.
    pub bytes: Option<Vec<u8>>,
}

/// Quarantines received attachment bytes: enforces size and media-type
/// policy, computes the digest, then runs the sandbox scanner.
///
/// Fail-closed ordering: policy violations reject immediately; a
/// [`ScanVerdict::Inconclusive`] or [`ScanVerdict::Malicious`] keeps the
/// attachment held/rejected — it is never released on scanner uncertainty.
pub fn quarantine<S: AttachmentScanner>(
    policy: &AttachmentPolicy,
    reference_id: impl Into<String>,
    filename: Option<String>,
    media_type: impl Into<String>,
    bytes: Vec<u8>,
    scanner: &S,
) -> Result<QuarantinedAttachment, QuarantineError> {
    let reference_id = reference_id.into();
    if reference_id.is_empty() || reference_id.len() > 256 {
        return Err(QuarantineError::InvalidReferenceId);
    }
    let media_type = normalize_media_type(media_type.into());

    if bytes.len() as u64 > policy.max_bytes {
        return Err(QuarantineError::TooLarge {
            size_bytes: bytes.len() as u64,
            max_bytes: policy.max_bytes,
        });
    }
    if let Some(reason) = blocked_reason(policy, &media_type) {
        return Err(QuarantineError::BlockedMediaType { reason });
    }

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256 = format!("{:x}", hasher.finalize());

    let mut reference = AttachmentRef {
        reference_id,
        filename,
        media_type,
        size_bytes: bytes.len() as u64,
        sha256,
        quarantine: QuarantineStatus::Held,
    };

    match scanner.scan(&reference, &bytes) {
        ScanVerdict::Clean => {
            reference.quarantine = QuarantineStatus::Released;
            Ok(QuarantinedAttachment {
                reference,
                bytes: Some(bytes),
            })
        }
        ScanVerdict::Malicious { reason } => {
            reference.quarantine = QuarantineStatus::Rejected {
                reason: format!("scanner: {reason}"),
            };
            Ok(QuarantinedAttachment {
                reference,
                bytes: None,
            })
        }
        ScanVerdict::Inconclusive { reason: _reason } => {
            // Fail closed: the scanner could not decide, so the attachment
            // stays Held (bytes retained for operator review). The reason is
            // intentionally not propagated to callers that might log it.
            reference.quarantine = QuarantineStatus::Held;
            Ok(QuarantinedAttachment {
                reference,
                bytes: Some(bytes),
            })
        }
    }
    // Note: the `Inconclusive` arm keeps the attachment Held (bytes retained
    // for operator review); only `Clean` releases it.
}

fn normalize_media_type(media_type: String) -> String {
    media_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn blocked_reason(policy: &AttachmentPolicy, media_type: &str) -> Option<String> {
    if media_type.is_empty() {
        return Some("missing media type".to_owned());
    }
    if ALWAYS_BLOCKED_MEDIA_TYPES.contains(&media_type) {
        return Some(format!("always-blocked media type: {media_type}"));
    }
    if policy
        .blocked_media_type_prefixes
        .iter()
        .any(|prefix| media_type.starts_with(prefix.as_str()))
    {
        return Some(format!("blocked media type: {media_type}"));
    }
    if let Some(allowed) = &policy.allowed_media_type_prefixes
        && !allowed
            .iter()
            .any(|prefix| media_type.starts_with(prefix.as_str()))
    {
        return Some(format!("media type not allowlisted: {media_type}"));
    }
    None
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum QuarantineError {
    #[error("reference id must be non-empty and at most 256 bytes")]
    InvalidReferenceId,
    #[error("attachment too large: {size_bytes} bytes (max {max_bytes})")]
    TooLarge { size_bytes: u64, max_bytes: u64 },
    #[error("blocked media type: {reason}")]
    BlockedMediaType { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CleanScanner;

    impl AttachmentScanner for CleanScanner {
        fn scan(&self, _attachment: &AttachmentRef, _bytes: &[u8]) -> ScanVerdict {
            ScanVerdict::Clean
        }
    }

    struct EvilScanner;

    impl AttachmentScanner for EvilScanner {
        fn scan(&self, _attachment: &AttachmentRef, _bytes: &[u8]) -> ScanVerdict {
            ScanVerdict::Malicious {
                reason: "eicar-like signature".to_owned(),
            }
        }
    }

    fn policy() -> AttachmentPolicy {
        AttachmentPolicy::default()
    }

    #[test]
    fn clean_attachment_is_released_with_digest() {
        let q = quarantine(
            &policy(),
            "ref-1",
            Some("photo.png".to_owned()),
            "image/png",
            b"png-bytes".to_vec(),
            &CleanScanner,
        )
        .unwrap();
        assert_eq!(q.reference.quarantine, QuarantineStatus::Released);
        assert_eq!(q.reference.size_bytes, 9);
        assert_eq!(q.reference.sha256.len(), 64);
        assert!(q.bytes.is_some());
    }

    #[test]
    fn executables_are_always_blocked() {
        let err = quarantine(
            &policy(),
            "ref-2",
            Some("run.exe".to_owned()),
            "application/x-msdownload",
            b"MZ".to_vec(),
            &CleanScanner,
        )
        .unwrap_err();
        assert!(matches!(err, QuarantineError::BlockedMediaType { .. }));
    }

    #[test]
    fn oversize_is_rejected_before_scan() {
        let small = AttachmentPolicy {
            max_bytes: 4,
            ..AttachmentPolicy::default()
        };
        let err = quarantine(
            &small,
            "ref-3",
            None,
            "text/plain",
            b"hello world".to_vec(),
            &CleanScanner,
        )
        .unwrap_err();
        assert_eq!(
            err,
            QuarantineError::TooLarge {
                size_bytes: 11,
                max_bytes: 4
            }
        );
    }

    #[test]
    fn allowlist_is_enforced() {
        let conservative = AttachmentPolicy::conservative();
        let err = quarantine(
            &conservative,
            "ref-4",
            None,
            "application/zip",
            b"zip".to_vec(),
            &CleanScanner,
        )
        .unwrap_err();
        assert!(matches!(err, QuarantineError::BlockedMediaType { .. }));
        assert!(
            quarantine(
                &conservative,
                "ref-5",
                None,
                "text/plain; charset=utf-8",
                b"hi".to_vec(),
                &CleanScanner,
            )
            .is_ok()
        );
    }

    #[test]
    fn malicious_scan_rejects_and_drops_bytes() {
        let q = quarantine(
            &policy(),
            "ref-6",
            None,
            "text/plain",
            b"evil".to_vec(),
            &EvilScanner,
        )
        .unwrap();
        assert!(matches!(
            q.reference.quarantine,
            QuarantineStatus::Rejected { .. }
        ));
        assert!(q.bytes.is_none());
    }

    #[test]
    fn inconclusive_scan_keeps_attachment_held() {
        let q = quarantine(
            &policy(),
            "ref-7",
            None,
            "text/plain",
            b"maybe".to_vec(),
            &HoldAllScanner,
        )
        .unwrap();
        // Fail closed: uncertainty never releases.
        assert_eq!(q.reference.quarantine, QuarantineStatus::Held);
        assert!(q.bytes.is_some());
    }
}
