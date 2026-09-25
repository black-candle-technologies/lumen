//! Plugin admission workflow: submit → inspect → test → approve → enable.
//!
//! This module owns the admission *record* format and its verification rules.
//! The record is the immutable, digest-pinned review artifact for one plugin
//! package:
//!
//! - **Locked source.** The only representable source kind is a local
//!   directory snapshot. There is deliberately no URL, Git ref, npm tag, or
//!   "runtime discovery" variant: the type system makes floating sources
//!   unrepresentable, so an admission can never silently re-point at new
//!   bytes.
//! - **Content digests.** Package, manifest, and artifact digests pin the
//!   exact bytes that were reviewed. Every update is a new submission with a
//!   new digest and an independent review decision.
//! - **Declared permissions.** The manifest's per-component capability
//!   requests are copied into the record at submit time; verification
//!   rejects any drift between the record and the staged bytes.
//! - **Review status.** Decisions form an append-only history
//!   (submitted → tested → approved → enabled, with revocation as a terminal
//!   overlay). The store refuses to persist a record whose history does not
//!   extend the stored one, so prior decisions — including revocations —
//!   cannot be rewritten.
//!
//! Revocation disables the digest: once a revocation decision is recorded,
//! the digest can never be approved or enabled again. Prior audit records are
//! untouched; the revocation is itself a new record.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use lumen_core::extension::Sha256Digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Version of the admission record format. Bumped only with a migration plan.
pub const ADMISSION_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdmissionDigests {
    pub package: String,
    pub manifest: String,
    pub artifact: String,
}

impl AdmissionDigests {
    pub fn new(package: &Sha256Digest, manifest: &Sha256Digest, artifact: &Sha256Digest) -> Self {
        Self {
            package: package.to_string(),
            manifest: manifest.to_string(),
            artifact: artifact.to_string(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeclaredPermission {
    pub component_id: String,
    pub capability: String,
    pub scope: String,
}

/// The only source kind the admission workflow accepts.
///
/// A local directory is canonicalized at submit time; the snapshot digest is
/// what gets reviewed, so later edits to the source directory cannot affect
/// the admission. Floating references (npm tags, Git branches, URLs, runtime
/// discovery) have no representation here and are rejected at the CLI
/// boundary before a record is ever created.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LockedSource {
    LocalDirectory { canonical_path: String },
}

impl LockedSource {
    /// Lock a local directory as an admission source.
    ///
    /// Rejects anything that is not a plain local directory path: URLs,
    /// `..` escapes, and non-directories are refused. The returned source
    /// carries the canonicalized path for operator display; the digest pin
    /// (not the path) is what the review covers.
    pub fn lock_local_directory(path: &Path) -> Result<Self, AdmissionError> {
        let raw = path.to_string_lossy();
        if raw.is_empty()
            || raw.contains("://")
            || raw.starts_with("npm:")
            || raw.starts_with("git:")
            || raw.starts_with("github:")
        {
            return Err(AdmissionError::FloatingSource(raw.into_owned()));
        }
        let canonical = fs::canonicalize(path).map_err(|_| {
            AdmissionError::InvalidSource(format!(
                "source is not an accessible directory: {}",
                path.display()
            ))
        })?;
        if !canonical.is_dir() {
            return Err(AdmissionError::InvalidSource(format!(
                "source is not a directory: {}",
                path.display()
            )));
        }
        let canonical_str = canonical.to_string_lossy().into_owned();
        if canonical_str.contains("..") {
            return Err(AdmissionError::InvalidSource(
                "canonical source path escapes".into(),
            ));
        }
        Ok(Self::LocalDirectory {
            canonical_path: canonical_str,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Submitted,
    TestPassed,
    TestFailed,
    Approved,
    Enabled,
    Revoked,
}

impl DecisionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::TestPassed => "test_passed",
            Self::TestFailed => "test_failed",
            Self::Approved => "approved",
            Self::Enabled => "enabled",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionDecision {
    pub kind: DecisionKind,
    /// Operator principal as `provider:subject`.
    pub decided_by: String,
    pub decided_at: u64,
    pub reason: String,
    /// Digest of the supporting artifact (e.g. the test report), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail_digest: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewStatus {
    Submitted,
    Tested { passed: bool },
    Approved,
    Enabled,
    Revoked,
}

impl ReviewStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Tested { passed: true } => "tested_passed",
            Self::Tested { passed: false } => "tested_failed",
            Self::Approved => "approved",
            Self::Enabled => "enabled",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRecord {
    pub admission_version: u16,
    pub plugin_id: String,
    pub version: String,
    pub digests: AdmissionDigests,
    pub declared_permissions: Vec<DeclaredPermission>,
    pub source: LockedSource,
    /// Append-only decision history. The last entry determines the status.
    pub decisions: Vec<AdmissionDecision>,
}

impl AdmissionRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plugin_id: String,
        version: String,
        digests: AdmissionDigests,
        declared_permissions: Vec<DeclaredPermission>,
        source: LockedSource,
        submitted_by: String,
        submitted_at: u64,
        reason: String,
    ) -> Result<Self, AdmissionError> {
        if plugin_id.is_empty() || version.is_empty() {
            return Err(AdmissionError::InvalidIdentity(
                "plugin id and version are required".into(),
            ));
        }
        if reason.trim().is_empty() || reason.len() > 2048 {
            return Err(AdmissionError::InvalidReason);
        }
        let mut record = Self {
            admission_version: ADMISSION_VERSION,
            plugin_id,
            version,
            digests,
            declared_permissions,
            source,
            decisions: Vec::new(),
        };
        record.push_decision(AdmissionDecision {
            kind: DecisionKind::Submitted,
            decided_by: submitted_by,
            decided_at: submitted_at,
            reason,
            detail_digest: None,
        })?;
        Ok(record)
    }

    fn push_decision(&mut self, decision: AdmissionDecision) -> Result<(), AdmissionError> {
        let allowed = match self.status() {
            // Fresh record: only submission is allowed.
            _ if self.decisions.is_empty() => decision.kind == DecisionKind::Submitted,
            ReviewStatus::Submitted => matches!(
                decision.kind,
                DecisionKind::TestPassed | DecisionKind::TestFailed
            ),
            ReviewStatus::Tested { passed: true } => matches!(
                decision.kind,
                DecisionKind::Approved | DecisionKind::Revoked
            ),
            // A failed test run must be re-tested; approval is refused.
            ReviewStatus::Tested { passed: false } => matches!(
                decision.kind,
                DecisionKind::TestPassed | DecisionKind::TestFailed | DecisionKind::Revoked
            ),
            ReviewStatus::Approved => {
                matches!(decision.kind, DecisionKind::Enabled | DecisionKind::Revoked)
            }
            // Enabled digests can still be revoked (compromise response).
            ReviewStatus::Enabled => decision.kind == DecisionKind::Revoked,
            // Revocation is terminal: the digest stays revoked forever.
            ReviewStatus::Revoked => false,
        };
        if !allowed {
            return Err(AdmissionError::IllegalTransition {
                from: self.status().as_str().into(),
                to: decision.kind.as_str().into(),
            });
        }
        if decision.decided_by.trim().is_empty() || decision.decided_by.len() > 256 {
            return Err(AdmissionError::InvalidPrincipal);
        }
        self.decisions.push(decision);
        Ok(())
    }

    /// Current review status, derived from the append-only decision history.
    pub fn status(&self) -> ReviewStatus {
        let mut status = ReviewStatus::Submitted;
        for decision in &self.decisions {
            status = match decision.kind {
                DecisionKind::Submitted => ReviewStatus::Submitted,
                DecisionKind::TestPassed => ReviewStatus::Tested { passed: true },
                DecisionKind::TestFailed => ReviewStatus::Tested { passed: false },
                DecisionKind::Approved => ReviewStatus::Approved,
                DecisionKind::Enabled => ReviewStatus::Enabled,
                DecisionKind::Revoked => ReviewStatus::Revoked,
            };
        }
        status
    }

    pub fn record_test(
        &mut self,
        report: &AdmissionTestReport,
        decided_by: String,
        decided_at: u64,
    ) -> Result<(), AdmissionError> {
        if report.package_digest != self.digests.package {
            return Err(AdmissionError::DigestMismatch(
                "test report targets a different package digest".into(),
            ));
        }
        let passed = report.passed();
        self.push_decision(AdmissionDecision {
            kind: if passed {
                DecisionKind::TestPassed
            } else {
                DecisionKind::TestFailed
            },
            decided_by,
            decided_at,
            reason: format!(
                "admission tests {} ({} legs)",
                if passed { "passed" } else { "failed" },
                report.legs.len()
            ),
            detail_digest: Some(report.digest()),
        })
    }

    pub fn approve(
        &mut self,
        decided_by: String,
        decided_at: u64,
        reason: String,
    ) -> Result<(), AdmissionError> {
        if !matches!(self.status(), ReviewStatus::Tested { passed: true }) {
            return Err(AdmissionError::IllegalTransition {
                from: self.status().as_str().into(),
                to: DecisionKind::Approved.as_str().into(),
            });
        }
        if reason.trim().is_empty() || reason.len() > 2048 {
            return Err(AdmissionError::InvalidReason);
        }
        self.push_decision(AdmissionDecision {
            kind: DecisionKind::Approved,
            decided_by,
            decided_at,
            reason,
            detail_digest: None,
        })
    }

    pub fn mark_enabled(
        &mut self,
        decided_by: String,
        decided_at: u64,
    ) -> Result<(), AdmissionError> {
        // Idempotent: re-enabling an already-enabled digest is a no-op.
        // The deployment state doesn't change, so no new decision is recorded.
        if matches!(self.status(), ReviewStatus::Enabled) {
            return Ok(());
        }
        self.push_decision(AdmissionDecision {
            kind: DecisionKind::Enabled,
            decided_by,
            decided_at,
            reason: "digest enabled for deployment".into(),
            detail_digest: None,
        })
    }

    pub fn revoke(
        &mut self,
        decided_by: String,
        decided_at: u64,
        reason: String,
    ) -> Result<(), AdmissionError> {
        if reason.trim().is_empty() || reason.len() > 2048 {
            return Err(AdmissionError::InvalidReason);
        }
        self.push_decision(AdmissionDecision {
            kind: DecisionKind::Revoked,
            decided_by,
            decided_at,
            reason,
            detail_digest: None,
        })
    }

    /// Verify the record still pins the given staged package: digests and
    /// declared permissions must match exactly. Any drift fails closed.
    pub fn verify_against(
        &self,
        digests: &AdmissionDigests,
        declared_permissions: &[DeclaredPermission],
    ) -> Result<(), AdmissionError> {
        if self.admission_version != ADMISSION_VERSION {
            return Err(AdmissionError::UnsupportedVersion(self.admission_version));
        }
        if &self.digests != digests {
            return Err(AdmissionError::DigestMismatch(
                "staged package digests do not match the admission record".into(),
            ));
        }
        if self.declared_permissions.as_slice() != declared_permissions {
            return Err(AdmissionError::PermissionDrift(
                "declared permissions do not match the admission record".into(),
            ));
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, AdmissionError> {
        serde_json::to_vec(self).map_err(AdmissionError::Serialization)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionTestLeg {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionTestReport {
    pub report_version: u16,
    pub stage_id: String,
    pub package_digest: String,
    pub tested_at: u64,
    pub legs: Vec<AdmissionTestLeg>,
}

impl AdmissionTestReport {
    pub fn new(
        stage_id: Uuid,
        package_digest: String,
        tested_at: u64,
        legs: Vec<AdmissionTestLeg>,
    ) -> Self {
        Self {
            report_version: 1,
            stage_id: stage_id.to_string(),
            package_digest,
            tested_at,
            legs,
        }
    }

    pub fn passed(&self) -> bool {
        !self.legs.is_empty() && self.legs.iter().all(|leg| leg.passed)
    }

    /// Content digest of the canonical report bytes. Stored on the
    /// `TestPassed`/`TestFailed` decision so the approval can be audited
    /// against the exact report that was reviewed.
    pub fn digest(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("admission test report serializes");
        format!("{:x}", Sha256::digest(bytes))
    }
}

/// File-backed store for admission records.
///
/// Layout under `root`:
/// - `records/<package-digest>.json` — the immutable record, keyed by digest.
/// - `index.json` — maps `"<plugin-id>@<version>"` to the package digest.
///
/// Writes are atomic (temp file + rename). Saving a record whose decision
/// history does not extend the stored history is refused: decisions are
/// append-only, so revocations and approvals cannot be rewritten.
pub struct AdmissionStore {
    root: PathBuf,
}

impl AdmissionStore {
    pub fn open(root: &Path) -> Result<Self, AdmissionError> {
        let records = root.join("records");
        fs::create_dir_all(&records).map_err(AdmissionError::Io)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    fn record_path(&self, package_digest: &str) -> PathBuf {
        self.root
            .join("records")
            .join(format!("{package_digest}.json"))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn index_key(plugin_id: &str, version: &str) -> String {
        format!("{plugin_id}@{version}")
    }

    pub fn save(&self, record: &AdmissionRecord) -> Result<(), AdmissionError> {
        validate_digest_key(&record.digests.package)?;
        // Serialize the read-check-write under an exclusive lock so two
        // processes cannot interleave their history checks.
        let lock_path = self.root.join("admission.lock");
        let lock_file = std::fs::File::create(&lock_path).map_err(AdmissionError::Io)?;
        lock_file
            .try_lock()
            .map_err(|error| AdmissionError::Io(error.into()))?;
        let result = self.save_locked(record);
        // Unlock before returning; the lock file persists for reuse.
        let _ = lock_file.unlock();
        result
    }

    fn save_locked(&self, record: &AdmissionRecord) -> Result<(), AdmissionError> {
        if let Some(stored) = self.load(&record.digests.package)? {
            if record.decisions.len() < stored.decisions.len()
                || record.decisions[..stored.decisions.len()] != stored.decisions[..]
            {
                return Err(AdmissionError::HistoryRewrite(
                    "admission decision history is append-only".into(),
                ));
            }
            if record.decisions.len() == stored.decisions.len() {
                return Ok(()); // idempotent re-save
            }
        }
        let bytes = record.canonical_json()?;
        atomic_write(&self.record_path(&record.digests.package), &bytes)?;
        let mut index = self.read_index()?;
        index.insert(
            Self::index_key(&record.plugin_id, &record.version),
            record.digests.package.clone(),
        );
        atomic_write(
            &self.index_path(),
            &serde_json::to_vec_pretty(&index).map_err(AdmissionError::Serialization)?,
        )?;
        Ok(())
    }

    pub fn load(&self, package_digest: &str) -> Result<Option<AdmissionRecord>, AdmissionError> {
        validate_digest_key(package_digest)?;
        let path = self.record_path(package_digest);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(AdmissionError::Io(error)),
        };
        let record: AdmissionRecord =
            serde_json::from_slice(&bytes).map_err(AdmissionError::Serialization)?;
        if record.admission_version != ADMISSION_VERSION {
            return Err(AdmissionError::UnsupportedVersion(record.admission_version));
        }
        if record.digests.package != package_digest {
            return Err(AdmissionError::DigestMismatch(
                "record filename does not match its package digest".into(),
            ));
        }
        Ok(Some(record))
    }

    pub fn load_by_plugin(
        &self,
        plugin_id: &str,
        version: &str,
    ) -> Result<Option<AdmissionRecord>, AdmissionError> {
        let index = self.read_index()?;
        match index.get(&Self::index_key(plugin_id, version)) {
            Some(digest) => self.load(digest),
            None => Ok(None),
        }
    }

    pub fn list(&self) -> Result<Vec<AdmissionSummary>, AdmissionError> {
        let mut summaries = Vec::new();
        let records = self.root.join("records");
        let entries = match fs::read_dir(&records) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(summaries),
            Err(error) => return Err(AdmissionError::Io(error)),
        };
        for entry in entries {
            let entry = entry.map_err(AdmissionError::Io)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(digest) = name.strip_suffix(".json") else {
                continue;
            };
            if let Some(record) = self.load(digest)? {
                summaries.push(AdmissionSummary {
                    plugin_id: record.plugin_id.clone(),
                    version: record.version.clone(),
                    package_digest: record.digests.package.clone(),
                    status: record.status().as_str().into(),
                    decisions: record.decisions.len(),
                });
            }
        }
        summaries.sort_by(|a, b| (&a.plugin_id, &a.version).cmp(&(&b.plugin_id, &b.version)));
        Ok(summaries)
    }

    fn read_index(&self) -> Result<BTreeMap<String, String>, AdmissionError> {
        let bytes = match fs::read(self.index_path()) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new());
            }
            Err(error) => return Err(AdmissionError::Io(error)),
        };
        serde_json::from_slice(&bytes).map_err(AdmissionError::Serialization)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdmissionSummary {
    pub plugin_id: String,
    pub version: String,
    pub package_digest: String,
    pub status: String,
    pub decisions: usize,
}

fn validate_digest_key(digest: &str) -> Result<(), AdmissionError> {
    if digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(AdmissionError::DigestMismatch(
            "package digest is not a 64-character hex string".into(),
        ))
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), AdmissionError> {
    let parent = path
        .parent()
        .ok_or_else(|| AdmissionError::Io(std::io::Error::other("record path has no parent")))?;
    let temp = parent.join(format!(".tmp-{}", Uuid::new_v4()));
    fs::write(&temp, bytes).map_err(AdmissionError::Io)?;
    fs::rename(&temp, path).map_err(AdmissionError::Io)?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum AdmissionError {
    #[error(
        "admission source must be a locked local directory; floating sources are rejected: {0}"
    )]
    FloatingSource(String),
    #[error("invalid admission source: {0}")]
    InvalidSource(String),
    #[error("invalid plugin identity: {0}")]
    InvalidIdentity(String),
    #[error("admission reason must be non-empty and at most 2048 characters")]
    InvalidReason,
    #[error("admission principal must be non-empty and at most 256 characters")]
    InvalidPrincipal,
    #[error("illegal admission transition: {from} -> {to}")]
    IllegalTransition { from: String, to: String },
    #[error("admission digest mismatch: {0}")]
    DigestMismatch(String),
    #[error("admission permission drift: {0}")]
    PermissionDrift(String),
    #[error("admission decision history rewrite refused: {0}")]
    HistoryRewrite(String),
    #[error("unsupported admission record version: {0}")]
    UnsupportedVersion(u16),
    #[error("admission serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digests() -> AdmissionDigests {
        AdmissionDigests {
            package: "a".repeat(64),
            manifest: "b".repeat(64),
            artifact: "c".repeat(64),
        }
    }

    fn source() -> LockedSource {
        LockedSource::LocalDirectory {
            canonical_path: "/tmp/fixture".into(),
        }
    }

    fn record() -> AdmissionRecord {
        AdmissionRecord::new(
            "dev.example.fixture".into(),
            "1.0.0".into(),
            digests(),
            vec![DeclaredPermission {
                component_id: "echo".into(),
                capability: "fs.read".into(),
                scope: "workspace".into(),
            }],
            source(),
            "local:operator".into(),
            1,
            "initial submission".into(),
        )
        .expect("record builds")
    }

    #[test]
    fn floating_sources_are_rejected() {
        for floating in [
            "https://example.com/plugin.zip",
            "npm:@example/plugin@latest",
            "git:github.com/example/plugin#main",
            "github:example/plugin",
        ] {
            assert!(
                LockedSource::lock_local_directory(Path::new(floating)).is_err(),
                "floating source accepted: {floating}"
            );
        }
    }

    #[test]
    fn approval_requires_passing_tests() {
        let mut record = record();
        assert!(
            record
                .approve("local:operator".into(), 2, "looks fine".into())
                .is_err()
        );
        let report = AdmissionTestReport::new(
            Uuid::new_v4(),
            "a".repeat(64),
            2,
            vec![AdmissionTestLeg {
                name: "digest".into(),
                passed: true,
                detail: "ok".into(),
            }],
        );
        record
            .record_test(&report, "local:operator".into(), 2)
            .expect("test recorded");
        record
            .approve(
                "local:operator".into(),
                3,
                "reviewed digests and permissions".into(),
            )
            .expect("approved");
        assert_eq!(record.status(), ReviewStatus::Approved);
    }

    #[test]
    fn failed_tests_block_approval_until_retest() {
        let mut record = record();
        let failed = AdmissionTestReport::new(
            Uuid::new_v4(),
            "a".repeat(64),
            2,
            vec![AdmissionTestLeg {
                name: "digest".into(),
                passed: false,
                detail: "mismatch".into(),
            }],
        );
        record
            .record_test(&failed, "local:operator".into(), 2)
            .expect("test recorded");
        assert_eq!(record.status(), ReviewStatus::Tested { passed: false });
        assert!(
            record
                .approve("local:operator".into(), 3, "nope".into())
                .is_err()
        );
        let passed = AdmissionTestReport::new(
            Uuid::new_v4(),
            "a".repeat(64),
            3,
            vec![AdmissionTestLeg {
                name: "digest".into(),
                passed: true,
                detail: "ok".into(),
            }],
        );
        record
            .record_test(&passed, "local:operator".into(), 3)
            .expect("retest recorded");
        record
            .approve("local:operator".into(), 4, "fixed and reviewed".into())
            .expect("approved");
    }

    #[test]
    fn revocation_is_terminal_and_preserves_history() {
        let mut record = record();
        let report = AdmissionTestReport::new(
            Uuid::new_v4(),
            "a".repeat(64),
            2,
            vec![AdmissionTestLeg {
                name: "digest".into(),
                passed: true,
                detail: "ok".into(),
            }],
        );
        record
            .record_test(&report, "local:operator".into(), 2)
            .expect("test");
        record
            .approve("local:operator".into(), 3, "ok".into())
            .expect("approve");
        record
            .mark_enabled("local:operator".into(), 4)
            .expect("enabled");
        record
            .revoke("local:operator".into(), 5, "compromised upstream".into())
            .expect("revoked");
        assert_eq!(record.status(), ReviewStatus::Revoked);
        assert_eq!(record.decisions.len(), 5);
        // No transition out of revoked.
        assert!(
            record
                .approve("local:operator".into(), 6, "regret".into())
                .is_err()
        );
        assert!(record.mark_enabled("local:operator".into(), 6).is_err());
        // The approval decision is still in the history.
        assert!(
            record
                .decisions
                .iter()
                .any(|d| d.kind == DecisionKind::Approved)
        );
    }

    #[test]
    fn store_refuses_history_rewrites() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = AdmissionStore::open(root.path()).expect("store opens");
        let mut record = record();
        store.save(&record).expect("first save");
        // Append a decision so a truncation is a real rewrite, not a no-op.
        let report = AdmissionTestReport::new(
            Uuid::new_v4(),
            "a".repeat(64),
            2,
            vec![AdmissionTestLeg {
                name: "digest".into(),
                passed: true,
                detail: "ok".into(),
            }],
        );
        record
            .record_test(&report, "local:operator".into(), 2)
            .expect("test");
        store.save(&record).expect("append saves");
        // A forged record that drops the test decision must be refused.
        let mut forged = record.clone();
        forged.decisions.truncate(1);
        assert_eq!(forged.decisions.len(), 1);
        assert!(store.save(&forged).is_err());
        // The stored record is untouched.
        let loaded = store.load(&"a".repeat(64)).expect("load").expect("record");
        assert_eq!(loaded.status(), ReviewStatus::Tested { passed: true });
        assert_eq!(loaded.decisions.len(), 2);
        assert!(
            store
                .load_by_plugin("dev.example.fixture", "1.0.0")
                .expect("index")
                .is_some()
        );
    }

    #[test]
    fn digest_and_permission_drift_fail_verification() {
        let record = record();
        let mut other_digests = digests();
        other_digests.package = "d".repeat(64);
        assert!(
            record
                .verify_against(&other_digests, &record.declared_permissions)
                .is_err()
        );
        assert!(record.verify_against(&digests(), &[]).is_err());
        assert!(
            record
                .verify_against(&digests(), &record.declared_permissions)
                .is_ok()
        );
    }
}
