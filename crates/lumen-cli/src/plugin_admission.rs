//! Plugin admission workflow implementation for the CLI.
//!
//! Implements the submit → inspect → test → approve → enable flow on top of
//! the content-addressed staging primitives. Every step pins the exact
//! digest under review; approval is refused unless the admission tests pass;
//! install and enable are refused unless the digest is approved and not
//! revoked.

use std::path::{Path, PathBuf};

use lumen_core::{
    approval::TimestampMillis,
    extension::{ManifestCapabilityScope, PluginManifest, Sha256Digest},
};
use lumen_db::{Database, StagedPluginPackage};
use lumen_integrations::{
    admission::{
        AdmissionDecision, AdmissionDigests, AdmissionError, AdmissionRecord, AdmissionStore,
        AdmissionTestLeg, AdmissionTestReport, DeclaredPermission, LockedSource, ReviewStatus,
    },
    extension_package::PackageStager,
};
use thiserror::Error;
use uuid::Uuid;

use crate::config::Config;

#[derive(Debug, Error)]
pub enum AdmissionCommandError {
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    #[error(transparent)]
    Database(#[from] lumen_db::RepositoryError),
    #[error(transparent)]
    Stage(#[from] lumen_integrations::extension_package::PackageStageError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Refused(String),
}

pub type Result<T> = std::result::Result<T, AdmissionCommandError>;

/// Root of the admission store: `<data>/plugins/admissions`.
pub fn admission_store(config: &Config) -> std::result::Result<AdmissionStore, AdmissionError> {
    admission_store_at(&config.runtime.data_directory)
}

pub fn admission_store_at(data_root: &Path) -> std::result::Result<AdmissionStore, AdmissionError> {
    AdmissionStore::open(&data_root.join("plugins/admissions"))
}

fn decided_by(config: &Config, override_principal: Option<&str>) -> String {
    match override_principal {
        Some(principal) => principal.to_owned(),
        None => {
            let principal = config.bootstrap_principal();
            format!("{}:{}", principal.provider(), principal.subject())
        }
    }
}

pub fn declared_permissions(manifest: &PluginManifest) -> Vec<DeclaredPermission> {
    manifest
        .components()
        .iter()
        .flat_map(|component| {
            component.capabilities().iter().map(move |request| {
                let scope = match request.scope() {
                    ManifestCapabilityScope::Workspace => "workspace",
                };
                DeclaredPermission {
                    component_id: component.id().to_string(),
                    capability: request.name().as_str().to_owned(),
                    scope: scope.to_owned(),
                }
            })
        })
        .collect()
}

fn admission_digests(staged: &StagedPluginPackage) -> AdmissionDigests {
    AdmissionDigests {
        package: staged.package_digest().to_string(),
        manifest: staged.manifest_digest().to_string(),
        artifact: staged.manifest().integrity().artifact().to_string(),
    }
}

/// Submit a local directory: stage it (content-addressed, quarantined) and
/// open an admission record pinning the digests under review.
pub async fn submit(
    config: &Config,
    database: &Database,
    directory: &Path,
    reason: &str,
    as_principal: Option<&str>,
    now: TimestampMillis,
) -> Result<Submission> {
    if reason.trim().is_empty() {
        return Err(AdmissionCommandError::Refused(
            "a submission reason is required".into(),
        ));
    }
    // Floating sources are rejected before any bytes are staged.
    let source = LockedSource::lock_local_directory(directory)?;
    let quarantine = config.runtime.data_directory.join("plugins/quarantine");
    let staged = PackageStager::default().stage(directory, &quarantine)?;
    let data_root = std::fs::canonicalize(&config.runtime.data_directory)?;
    let relative = staged
        .quarantine_path()
        .strip_prefix(&data_root)
        .map_err(|_| {
            AdmissionCommandError::Refused("quarantine escaped the data directory".into())
        })?;
    let relative = crate::relative_storage_path(relative)
        .ok_or_else(|| AdmissionCommandError::Refused("quarantine path is not portable".into()))?;
    let stage_id = Uuid::new_v4();
    let manifest = staged.manifest().clone();
    let permissions = declared_permissions(&manifest);
    let digests = AdmissionDigests::new(
        staged.package_digest(),
        staged.manifest_digest(),
        staged.manifest().integrity().artifact(),
    );
    let record = AdmissionRecord::new(
        manifest.id().to_string(),
        manifest.version().to_string(),
        digests.clone(),
        permissions,
        source,
        decided_by(config, as_principal),
        now.as_u64(),
        reason.to_owned(),
    )?;
    let staged_record = StagedPluginPackage::new(
        stage_id,
        manifest,
        relative,
        staged.files().clone(),
        staged.package_digest().clone(),
        staged.manifest_digest().clone(),
        config.bootstrap_principal(),
        now,
    )
    .map_err(|error| AdmissionCommandError::Refused(error.to_string()))?;
    database
        .insert_staged_plugin_package(&staged_record)
        .await?;
    let store = admission_store(config)?;
    store.save(&record)?;
    Ok(Submission {
        stage_id,
        plugin_id: staged_record.manifest().id().to_string(),
        version: staged_record.manifest().version().to_string(),
        package_digest: digests.package,
        status: record.status().as_str().to_owned(),
    })
}

#[derive(Clone, Debug)]
pub struct Submission {
    pub stage_id: Uuid,
    pub plugin_id: String,
    pub version: String,
    pub package_digest: String,
    pub status: String,
}

async fn load_staged(database: &Database, stage_id: Uuid) -> Result<StagedPluginPackage> {
    database
        .staged_plugin_package(stage_id)
        .await?
        .ok_or_else(|| AdmissionCommandError::Refused("staged plugin package was not found".into()))
}

fn load_admission(config: &Config, staged: &StagedPluginPackage) -> Result<AdmissionRecord> {
    let store = admission_store(config)?;
    let digests = admission_digests(staged);
    let record = store.load(&digests.package)?.ok_or_else(|| {
        AdmissionCommandError::Refused(
            "no admission record for this staged package; submit it first".into(),
        )
    })?;
    record.verify_against(&digests, &declared_permissions(staged.manifest()))?;
    Ok(record)
}

/// Run the admission test suite against a staged package and record the
/// result on the admission record.
pub async fn test(
    config: &Config,
    database: &Database,
    stage_id: Uuid,
    as_principal: Option<&str>,
    now: TimestampMillis,
) -> Result<TestOutcome> {
    let staged = load_staged(database, stage_id).await?;
    let mut record = load_admission(config, &staged)?;
    let legs = run_test_legs(config, &staged)?;
    let report = AdmissionTestReport::new(
        stage_id,
        staged.package_digest().to_string(),
        now.as_u64(),
        legs,
    );
    let passed = report.passed();
    record.record_test(&report, decided_by(config, as_principal), now.as_u64())?;
    admission_store(config)?.save(&record)?;
    Ok(TestOutcome {
        stage_id,
        plugin_id: staged.manifest().id().to_string(),
        version: staged.manifest().version().to_string(),
        package_digest: staged.package_digest().to_string(),
        report_digest: report.digest(),
        passed,
        legs: report.legs,
        status: record.status().as_str().to_owned(),
    })
}

#[derive(Clone, Debug)]
pub struct TestOutcome {
    pub stage_id: Uuid,
    pub plugin_id: String,
    pub version: String,
    pub package_digest: String,
    pub report_digest: String,
    pub passed: bool,
    pub legs: Vec<AdmissionTestLeg>,
    pub status: String,
}

#[derive(Debug, serde::Deserialize)]
struct AdmissionPolicyFile {
    #[serde(default)]
    allowed_capabilities: Vec<String>,
    #[serde(default)]
    denied_capabilities: Vec<String>,
}

fn load_admission_policy(config: &Config) -> Option<AdmissionPolicyFile> {
    let path = config
        .runtime
        .data_directory
        .join("plugins/admission-policy.toml");
    let bytes = std::fs::read(path).ok()?;
    toml::from_slice(&bytes).ok()
}

/// The admission test suite. Every leg re-derives its result from the staged
/// bytes and the admission record; nothing is trusted from memory.
fn run_test_legs(config: &Config, staged: &StagedPluginPackage) -> Result<Vec<AdmissionTestLeg>> {
    let mut legs = Vec::new();

    // Leg 1: digest re-verification. Re-stage the quarantined bytes and
    // require identical digests, catching any tampering after submit.
    let quarantine_dir = quarantine_dir(config, staged);
    let restaged = PackageStager::default()
        .stage(
            &quarantine_dir,
            config.runtime.data_directory.join("plugins/quarantine"),
        )
        .map_err(|error| {
            AdmissionCommandError::Refused(format!("quarantined bytes failed re-staging: {error}"))
        })?;
    let digests_match = restaged.package_digest() == staged.package_digest()
        && restaged.manifest_digest() == staged.manifest_digest()
        && restaged.manifest().integrity().artifact() == staged.manifest().integrity().artifact();
    legs.push(AdmissionTestLeg {
        name: "digest-reverification".into(),
        passed: digests_match,
        detail: if digests_match {
            format!(
                "re-staged package digest {} matches the admission pin",
                staged.package_digest()
            )
        } else {
            "re-staged digests differ from the admission pin; the quarantined bytes changed after submit".into()
        },
    });

    // Leg 2: source lock. The record type only represents local-directory
    // snapshots, so floating sources are unrepresentable by construction.
    legs.push(AdmissionTestLeg {
        name: "source-lock".into(),
        passed: true,
        detail: "admission source is a locked local-directory snapshot; npm tags, git branches, URLs, and runtime discovery are unrepresentable".into(),
    });

    // Leg 3: static manifest checks on the staged bytes.
    let manifest_ok = {
        let components = staged.manifest().components();
        let entrypoint_digest = staged
            .file_hashes()
            .iter()
            .find(|(path, _)| path.ends_with(staged.manifest().runtime().entrypoint().as_str()))
            .map(|(_, digest)| digest.to_string());
        !components.is_empty()
            && components.len() <= 128
            && components
                .iter()
                .all(|c| c.capabilities().len() <= 128 && c.action_kinds().len() <= 128)
            && entrypoint_digest.as_deref()
                == Some(staged.manifest().integrity().artifact().as_str())
    };
    legs.push(AdmissionTestLeg {
        name: "static-manifest".into(),
        passed: manifest_ok,
        detail: if manifest_ok {
            format!(
                "manifest v1 with {} component(s); entrypoint digest matches the integrity pin",
                staged.manifest().components().len()
            )
        } else {
            "manifest failed static checks: component bounds or entrypoint digest mismatch".into()
        },
    });

    // Leg 4: capability policy. An operator policy file may allow/deny
    // capability names; without one, the declared set is surfaced for the
    // human approval step, which remains the enforcement point.
    let permissions = declared_permissions(staged.manifest());
    let (policy_ok, policy_detail) = match load_admission_policy(config) {
        Some(policy) => {
            let denied: Vec<_> = permissions
                .iter()
                .filter(|p| {
                    policy
                        .denied_capabilities
                        .iter()
                        .any(|d| d == &p.capability)
                })
                .map(|p| format!("{}:{}", p.component_id, p.capability))
                .collect();
            let unlisted: Vec<_> = if policy.allowed_capabilities.is_empty() {
                Vec::new()
            } else {
                permissions
                    .iter()
                    .filter(|p| {
                        !policy
                            .allowed_capabilities
                            .iter()
                            .any(|a| a == &p.capability)
                    })
                    .map(|p| format!("{}:{}", p.component_id, p.capability))
                    .collect()
            };
            if denied.is_empty() && unlisted.is_empty() {
                (
                    true,
                    format!(
                        "{} declared permission(s) satisfy the admission policy",
                        permissions.len()
                    ),
                )
            } else {
                let mut reasons = Vec::new();
                if !denied.is_empty() {
                    reasons.push(format!("denied: {}", denied.join(", ")));
                }
                if !unlisted.is_empty() {
                    reasons.push(format!("not in allowlist: {}", unlisted.join(", ")));
                }
                (false, reasons.join("; "))
            }
        }
        None => (
            true,
            format!(
                "no admission-policy.toml configured; {} declared permission(s) surfaced for human review",
                permissions.len()
            ),
        ),
    };
    legs.push(AdmissionTestLeg {
        name: "capability-policy".into(),
        passed: policy_ok,
        detail: policy_detail,
    });

    Ok(legs)
}

/// Approve a tested digest. Requires passing tests and an explicit reason;
/// refuses otherwise.
pub async fn approve(
    config: &Config,
    database: &Database,
    stage_id: Uuid,
    reason: &str,
    as_principal: Option<&str>,
    now: TimestampMillis,
) -> Result<Approval> {
    if reason.trim().is_empty() {
        return Err(AdmissionCommandError::Refused(
            "an approval reason is required".into(),
        ));
    }
    let staged = load_staged(database, stage_id).await?;
    let mut record = load_admission(config, &staged)?;
    record.approve(
        decided_by(config, as_principal),
        now.as_u64(),
        reason.to_owned(),
    )?;
    admission_store(config)?.save(&record)?;
    Ok(Approval {
        stage_id,
        plugin_id: staged.manifest().id().to_string(),
        version: staged.manifest().version().to_string(),
        package_digest: staged.package_digest().to_string(),
        status: record.status().as_str().to_owned(),
    })
}

#[derive(Clone, Debug)]
pub struct Approval {
    pub stage_id: Uuid,
    pub plugin_id: String,
    pub version: String,
    pub package_digest: String,
    pub status: String,
}

/// Gate for install/enable: the digest must be approved and not revoked.
pub fn require_installable(
    config: &Config,
    plugin_id: &str,
    version: &str,
    package_digest: &Sha256Digest,
) -> Result<()> {
    require_installable_at(
        &config.runtime.data_directory,
        plugin_id,
        version,
        &package_digest.to_string(),
    )
}

/// Path-based variant for the action executors (defense in depth: the
/// kernel re-checks the admission gate at execution time, even if the
/// request came through another surface).
pub fn require_installable_at(
    data_root: &Path,
    plugin_id: &str,
    version: &str,
    package_digest: &str,
) -> Result<()> {
    let store = admission_store_at(data_root)?;
    let record = store.load(package_digest)?.ok_or_else(|| {
        AdmissionCommandError::Refused(format!(
            "digest {package_digest} has no admission record; submit, test, and approve it first"
        ))
    })?;
    if record.plugin_id != plugin_id || record.version != version {
        return Err(AdmissionCommandError::Refused(
            "admission record identity does not match the requested plugin".into(),
        ));
    }
    match record.status() {
        ReviewStatus::Approved | ReviewStatus::Enabled => Ok(()),
        ReviewStatus::Revoked => Err(AdmissionCommandError::Refused(format!(
            "digest {package_digest} was revoked and can never be installed or enabled again"
        ))),
        other => Err(AdmissionCommandError::Refused(format!(
            "digest {package_digest} is '{}'; install and enable require an approved digest",
            other.as_str()
        ))),
    }
}

/// Revoke a digest: terminal. Also returns the identity so the caller can
/// request a disable of any enabled deployment.
pub fn revoke(
    config: &Config,
    plugin_id: &str,
    version: &str,
    reason: &str,
    as_principal: Option<&str>,
    now: TimestampMillis,
) -> Result<Revocation> {
    if reason.trim().is_empty() {
        return Err(AdmissionCommandError::Refused(
            "a revocation reason is required".into(),
        ));
    }
    let store = admission_store(config)?;
    let mut record = store.load_by_plugin(plugin_id, version)?.ok_or_else(|| {
        AdmissionCommandError::Refused(format!(
            "no admission record for {plugin_id} {version}; nothing to revoke"
        ))
    })?;
    record.revoke(
        decided_by(config, as_principal),
        now.as_u64(),
        reason.to_owned(),
    )?;
    let package_digest = record.digests.package.clone();
    store.save(&record)?;
    Ok(Revocation {
        plugin_id: plugin_id.to_owned(),
        version: version.to_owned(),
        package_digest,
    })
}

#[derive(Clone, Debug)]
pub struct Revocation {
    pub plugin_id: String,
    pub version: String,
    pub package_digest: String,
}

/// Gate for enable by plugin identity: resolves the digest through the
/// admission index and requires it to be approved and not revoked.
pub fn require_enabled_at(data_root: &Path, plugin_id: &str, version: &str) -> Result<String> {
    let store = admission_store_at(data_root)?;
    let record = store.load_by_plugin(plugin_id, version)?.ok_or_else(|| {
        AdmissionCommandError::Refused(format!(
            "no admission record for {plugin_id} {version}; submit, test, and approve it first"
        ))
    })?;
    match record.status() {
        ReviewStatus::Approved | ReviewStatus::Enabled => Ok(record.digests.package.clone()),
        ReviewStatus::Revoked => Err(AdmissionCommandError::Refused(format!(
            "digest {} was revoked and can never be enabled again",
            record.digests.package
        ))),
        other => Err(AdmissionCommandError::Refused(format!(
            "digest {} is '{}'; enable requires an approved digest",
            record.digests.package,
            other.as_str()
        ))),
    }
}

/// Path-based variant for the action executors: records the Approved →
/// Enabled transition when the kernel actually enables the digest.
pub fn mark_enabled_at(
    data_root: &Path,
    plugin_id: &str,
    version: &str,
    decided_by: &str,
    now: u64,
) -> Result<()> {
    let store = admission_store_at(data_root)?;
    let mut record = store.load_by_plugin(plugin_id, version)?.ok_or_else(|| {
        AdmissionCommandError::Refused(format!("no admission record for {plugin_id} {version}"))
    })?;
    record.mark_enabled(decided_by.to_owned(), now)?;
    store.save(&record)?;
    Ok(())
}

/// Inspection view: staged identity plus the admission record status and
/// decision history.
pub struct Inspection {
    pub stage_id: Uuid,
    pub plugin_id: String,
    pub version: String,
    pub runtime: String,
    pub name: String,
    pub description: String,
    pub package_digest: String,
    pub manifest_digest: String,
    pub artifact_digest: String,
    pub file_hashes: Vec<(String, String)>,
    pub requested_capabilities: Vec<String>,
    pub admission_status: String,
    pub decisions: Vec<AdmissionDecision>,
}

pub async fn inspect(config: &Config, database: &Database, stage_id: Uuid) -> Result<Inspection> {
    let staged = load_staged(database, stage_id).await?;
    let record = load_admission(config, &staged)?;
    let requested_capabilities = declared_permissions(staged.manifest())
        .into_iter()
        .map(|p| format!("{}:{}:{}", p.component_id, p.capability, p.scope))
        .collect();
    Ok(Inspection {
        stage_id,
        plugin_id: staged.manifest().id().to_string(),
        version: staged.manifest().version().to_string(),
        runtime: staged.manifest().runtime().runtime().as_str().to_owned(),
        name: staged.manifest().name().to_owned(),
        description: staged.manifest().description().to_owned(),
        package_digest: staged.package_digest().to_string(),
        manifest_digest: staged.manifest_digest().to_string(),
        artifact_digest: staged.manifest().integrity().artifact().to_string(),
        file_hashes: staged
            .file_hashes()
            .iter()
            .map(|(path, digest)| (path.clone(), digest.to_string()))
            .collect(),
        requested_capabilities,
        admission_status: record.status().as_str().to_owned(),
        decisions: record.decisions,
    })
}

pub fn list(config: &Config) -> Result<Vec<lumen_integrations::admission::AdmissionSummary>> {
    Ok(admission_store(config)?.list()?)
}

/// Absolute path of the quarantined package directory for a staged record.
pub fn quarantine_dir(config: &Config, staged: &StagedPluginPackage) -> PathBuf {
    config.runtime.data_directory.join(staged.quarantine_path())
}
