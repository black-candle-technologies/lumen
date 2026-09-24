pub mod config;
mod extension_runtime;
mod health;
mod plugin_admission;
mod runtime;
mod support_bundle;

use std::{
    collections::{BTreeMap, BTreeSet},
    future::{Future, IntoFuture},
    io::Read,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use clap::{Parser, Subcommand};
use config::{Config, ConfigError};
use lumen_control_plane::{
    BootstrapOperatorAuthority, DatabaseCandidateCatalog, DatabaseWorkerMaterializer,
    JsonModelPlanner, OrchestrationControl,
};
use lumen_core::audit::AuditIntegrityError;
use lumen_core::{
    action::{CanonicalValue, RunId},
    audit::{AuditEvent, AuditEventId, AuditEventKind, AuditOutcome},
    secret::SecretRefId,
    worker::WorkerRunBudget,
};
use lumen_db::{Database, RepositoryError, SecretReference, SecretReferenceError};
use lumen_integrations::{
    extension_package::PackageStageError,
    sandbox::{SandboxBackend, SandboxReport, SystemSandbox},
    secrets::{OsKeyringSecretStore, SecretStore, SecretStoreError},
};
use lumen_server::{ApiState, EventBroker, SandboxCapabilityReport, router};
use lumen_worker_runtime::{WorkerScheduler, WorkerSchedulerConfig};
use sha2::Digest as _;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

pub(crate) fn relative_storage_path(path: &Path) -> Option<String> {
    let segments = path
        .components()
        .map(|component| match component {
            Component::Normal(segment) => segment.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    (!segments.is_empty()).then(|| segments.join("/"))
}

#[derive(Clone, Debug, Eq, Parser, PartialEq)]
#[command(name = "lumen", version, about = "Local-first AI agent runtime")]
pub struct Cli {
    #[arg(long, global = true, default_value = "lumen.toml")]
    pub config: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum Command {
    Migrate,
    Serve,
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    Approvals {
        #[command(subcommand)]
        command: ApprovalsCommand,
    },
    Run {
        #[command(subcommand)]
        command: RunCommand,
    },
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    Lease {
        #[command(subcommand)]
        command: LeaseCommand,
    },
    /// Run health and diagnostics checks against the configured state.
    Health,
    /// Export a deterministic, redacted support bundle. The export is
    /// deleted if the secret scan finds anything.
    SupportBundle {
        #[arg(long)]
        out: PathBuf,
        /// Export only the audit trail (plus health and manifest).
        #[arg(long, default_value_t = false)]
        audit_only: bool,
    },
    Sandbox {
        #[command(subcommand)]
        command: SandboxCommand,
    },
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    Plugin {
        #[command(subcommand)]
        command: PluginCommand,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum PluginCommand {
    /// Submit a local plugin directory for admission. Pins the content
    /// digests and opens an admission record (status: submitted).
    #[command(alias = "stage")]
    Submit {
        #[arg(value_parser = parse_local_plugin_directory)]
        directory: PathBuf,
        /// Why this plugin is being submitted (recorded on the admission).
        #[arg(long)]
        reason: String,
        /// Operator principal recorded on the admission; defaults to the
        /// configured bootstrap principal.
        #[arg(long)]
        as_principal: Option<String>,
    },
    /// Inspect a staged package: manifest, digests, declared permissions,
    /// and the admission review status.
    #[command(alias = "review")]
    Inspect {
        stage_id: uuid::Uuid,
    },
    /// Run the admission test suite against a staged package and record
    /// the result on its admission record.
    Test {
        stage_id: uuid::Uuid,
    },
    /// Approve a tested digest for deployment. Requires passing admission
    /// tests, an explicit reason, and confirmation.
    Approve {
        stage_id: uuid::Uuid,
        #[arg(long)]
        reason: String,
        #[arg(long, default_value_t = false)]
        yes: bool,
        #[arg(long)]
        as_principal: Option<String>,
    },
    /// List admission records and their review status.
    List,
    Install {
        stage_id: uuid::Uuid,
    },
    Enable {
        plugin_id: String,
        version: String,
    },
    Disable {
        plugin_id: String,
        version: String,
    },
    /// Revoke a digest: terminal. Blocks reinstall/re-enable of the digest
    /// and requests disable of any enabled deployment. Prior audit records
    /// are preserved.
    Revoke {
        plugin_id: String,
        version: String,
        #[arg(long)]
        reason: String,
        #[arg(long, default_value_t = false)]
        yes: bool,
        #[arg(long)]
        as_principal: Option<String>,
    },
    Invoke {
        plugin_id: String,
        version: String,
        component_id: String,
        #[arg(long)]
        input: PathBuf,
    },
    CapabilitiesSet {
        plugin_id: String,
        version: String,
        component_id: String,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        expected_revision: Option<u64>,
        #[arg(long)]
        grants: PathBuf,
    },
    SettingsSet {
        plugin_id: String,
        version: String,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        scope_id: Option<String>,
        #[arg(long)]
        expected_version: Option<u64>,
        #[arg(long)]
        config: PathBuf,
    },
    QuarantineRelease {
        plugin_id: String,
        version: String,
        #[arg(long)]
        kind: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum AuditCommand {
    Verify,
    /// List audit events (newest last), with allow/deny/approval decisions
    /// and their reasons.
    List {
        #[arg(long)]
        kind: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: u16,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum ApprovalsCommand {
    /// List pending approval requests with their exact normalized
    /// arguments, capabilities, fingerprint, and expiry.
    List,
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum RunCommand {
    /// Show a run's lifecycle state and diagnostics.
    Show {
        #[arg(value_parser = parse_run_id)]
        run_id: RunId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum SessionCommand {
    /// List Pi agent sessions.
    ///
    /// Sessions are a Phase-1 surface: the lease/session store does not
    /// exist in this tree yet, so this command reports that explicitly
    /// instead of inventing session data.
    List,
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum LeaseCommand {
    /// Show a lease.
    ///
    /// Leases are a Phase-1 surface: the lease/session store does not
    /// exist in this tree yet, so this command reports that explicitly
    /// instead of inventing lease data.
    Show { lease_id: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum SandboxCommand {
    Report,
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum SecretCommand {
    Create {
        #[arg(long)]
        label: String,
        #[arg(long)]
        program: PathBuf,
        #[arg(long)]
        environment: String,
    },
    List,
    Delete {
        #[arg(long)]
        id: SecretRefId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandOutput {
    Migrated,
    AuditVerified,
    AuditListed(Vec<AuditEventSummary>),
    ServerStopped,
    SandboxReport(SandboxReport),
    SecretCreated(SecretReference),
    SecretReferences(Vec<SecretReference>),
    SecretDeleted(SecretRefId),
    PluginSubmitted(PluginSubmissionSummary),
    PluginInspected(PluginInspectionSummary),
    PluginTested(PluginTestSummary),
    PluginApproved(PluginApprovalSummary),
    PluginAdmissionsListed(Vec<AdmissionRecordSummary>),
    PluginRevoked(PluginRevocationSummary),
    PluginActionRequested(PluginActionRequest),
    ApprovalsListed(Vec<PendingApprovalSummary>),
    RunShown(RunSummary),
    HealthReported(HealthSummary),
    SupportBundleExported(SupportBundleSummary),
    Unavailable(UnavailableSurface),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginSubmissionSummary {
    pub stage_id: uuid::Uuid,
    pub plugin_id: String,
    pub version: String,
    pub package_digest: String,
    pub admission_status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionDecisionSummary {
    pub kind: String,
    pub decided_by: String,
    pub decided_at: u64,
    pub reason: String,
    pub detail_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginInspectionSummary {
    pub stage_id: uuid::Uuid,
    pub plugin_id: String,
    pub version: String,
    pub runtime: String,
    pub name: String,
    pub description: String,
    pub package_digest: String,
    pub manifest_digest: String,
    pub artifact_digest: String,
    pub file_hashes: BTreeMap<String, String>,
    pub requested_capabilities: Vec<String>,
    pub admission_status: String,
    pub decisions: Vec<AdmissionDecisionSummary>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginTestLegSummary {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginTestSummary {
    pub stage_id: uuid::Uuid,
    pub plugin_id: String,
    pub version: String,
    pub package_digest: String,
    pub report_digest: String,
    pub passed: bool,
    pub legs: Vec<PluginTestLegSummary>,
    pub admission_status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginApprovalSummary {
    pub stage_id: uuid::Uuid,
    pub plugin_id: String,
    pub version: String,
    pub package_digest: String,
    pub admission_status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionRecordSummary {
    pub plugin_id: String,
    pub version: String,
    pub package_digest: String,
    pub status: String,
    pub decisions: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginRevocationSummary {
    pub plugin_id: String,
    pub version: String,
    pub package_digest: String,
    pub disable_run_id: RunId,
    pub disable_approval_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginActionRequest {
    pub run_id: RunId,
    /// The pending approval the operator must decide (web UI / API) before
    /// the action executes. `None` when no approval was created.
    pub approval_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingApprovalSummary {
    pub approval_id: String,
    pub run_id: String,
    pub kind: String,
    pub fingerprint: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub arguments: String,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEventSummary {
    pub sequence: i64,
    pub event_id: String,
    pub timestamp: u64,
    pub kind: String,
    pub outcome: String,
    pub payload: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunSummary {
    pub run_id: String,
    pub phase: String,
    pub effect_certainty: String,
    pub terminal_code: Option<String>,
    pub primary_diagnostic: Option<String>,
    pub secondary_diagnostic: Option<String>,
    pub terminal_audit_pending: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthCheckSummary {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthSummary {
    pub healthy: bool,
    pub checks: Vec<HealthCheckSummary>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportBundleSummary {
    pub path: String,
    pub files: usize,
    pub audit_events: usize,
    pub redactions: usize,
    pub scanned_bytes: u64,
}

/// A CLI surface that has no backing store yet. Rendered explicitly instead
/// of inventing data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnavailableSurface {
    pub surface: String,
    pub detail: String,
}

impl CommandOutput {
    /// Human-readable rendering. Every state — including deny, pending,
    /// and unavailable — renders as plain text with its reason.
    pub fn render(&self) -> String {
        match self {
            Self::Migrated => "database migrated\n".into(),
            Self::AuditVerified => "audit chain verified\n".into(),
            Self::AuditListed(events) => {
                let mut out = String::new();
                for event in events {
                    out.push_str(&format!(
                        "#{} {} {} outcome={}\n    {}\n",
                        event.sequence, event.timestamp, event.kind, event.outcome, event.payload
                    ));
                }
                if events.is_empty() {
                    out.push_str("no audit events\n");
                }
                out
            }
            Self::ServerStopped => "server stopped\n".into(),
            Self::SandboxReport(report) => {
                format!(
                    "sandbox backend: {}\nstrength: {:?}\n{}\n",
                    report.backend(),
                    report.strength(),
                    report.detail().unwrap_or("")
                )
            }
            Self::SecretCreated(reference) => {
                format!("secret created: {}\n", reference.id())
            }
            Self::SecretReferences(references) => {
                let mut out = String::new();
                for reference in references {
                    out.push_str(&format!("{}\n", reference.id()));
                }
                if references.is_empty() {
                    out.push_str("no secret references\n");
                }
                out
            }
            Self::SecretDeleted(id) => format!("secret deleted: {id}\n"),
            Self::PluginSubmitted(summary) => format!(
                "submitted {} {} (stage {})\npackage digest: {}\nadmission status: {}\nnext: lumen plugin inspect {}\n",
                summary.plugin_id,
                summary.version,
                summary.stage_id,
                summary.package_digest,
                summary.admission_status,
                summary.stage_id
            ),
            Self::PluginInspected(inspection) => {
                let mut out = format!(
                    "plugin: {} {}\nname: {}\nruntime: {}\ndescription: {}\npackage digest:  {}\nmanifest digest: {}\nartifact digest: {}\nadmission status: {}\n",
                    inspection.plugin_id,
                    inspection.version,
                    inspection.name,
                    inspection.runtime,
                    inspection.description,
                    inspection.package_digest,
                    inspection.manifest_digest,
                    inspection.artifact_digest,
                    inspection.admission_status
                );
                out.push_str("declared permissions:\n");
                for capability in &inspection.requested_capabilities {
                    out.push_str(&format!("  - {capability}\n"));
                }
                out.push_str("files:\n");
                let mut files: Vec<_> = inspection.file_hashes.iter().collect();
                files.sort_by_key(|(path, _)| *path);
                for (path, digest) in files {
                    out.push_str(&format!("  {path}: {digest}\n"));
                }
                out.push_str("admission decisions:\n");
                for decision in &inspection.decisions {
                    out.push_str(&format!(
                        "  - {} by {} at {}: {}{}\n",
                        decision.kind,
                        decision.decided_by,
                        decision.decided_at,
                        decision.reason,
                        decision
                            .detail_digest
                            .as_ref()
                            .map(|digest| format!(" (detail {digest})"))
                            .unwrap_or_default()
                    ));
                }
                out
            }
            Self::PluginTested(summary) => {
                let mut out = format!(
                    "admission tests {} for {} {} ({})\nreport digest: {}\nadmission status: {}\n",
                    if summary.passed { "PASSED" } else { "FAILED" },
                    summary.plugin_id,
                    summary.version,
                    summary.package_digest,
                    summary.report_digest,
                    summary.admission_status
                );
                for leg in &summary.legs {
                    out.push_str(&format!(
                        "  [{}] {}\n      {}\n",
                        if leg.passed { "pass" } else { "FAIL" },
                        leg.name,
                        leg.detail
                    ));
                }
                if summary.passed {
                    out.push_str(&format!(
                        "next: lumen plugin approve {} --reason \"...\" --yes\n",
                        summary.stage_id
                    ));
                }
                out
            }
            Self::PluginApproved(summary) => format!(
                "approved {} {} ({})\nadmission status: {}\nnext: lumen plugin install {} (requests approval-bound install)\n",
                summary.plugin_id,
                summary.version,
                summary.package_digest,
                summary.admission_status,
                summary.stage_id
            ),
            Self::PluginAdmissionsListed(records) => {
                let mut out = String::new();
                for record in records {
                    out.push_str(&format!(
                        "{} {} {} status={} decisions={}\n",
                        record.plugin_id,
                        record.version,
                        record.package_digest,
                        record.status,
                        record.decisions
                    ));
                }
                if records.is_empty() {
                    out.push_str("no admission records\n");
                }
                out
            }
            Self::PluginRevoked(summary) => format!(
                "revoked {} {} ({})\nThis digest can never be installed or enabled again.\nDisable requested: run {}{}\n",
                summary.plugin_id,
                summary.version,
                summary.package_digest,
                summary.disable_run_id,
                summary
                    .disable_approval_id
                    .as_ref()
                    .map(|id| format!(" (approval {id} pending)"))
                    .unwrap_or_default()
            ),
            Self::PluginActionRequested(request) => format!(
                "action requested: run {}\n{}{}\n",
                request.run_id,
                request
                    .approval_id
                    .as_ref()
                    .map(|id| format!("approval {id} is PENDING"))
                    .unwrap_or_else(|| "no approval was created".into()),
                request.approval_id.as_ref().map(|_| "\nDecide it in the web UI approvals page or via the API; the action executes after approval.").unwrap_or("")
            ),
            Self::ApprovalsListed(approvals) => {
                let mut out = String::new();
                for approval in approvals {
                    out.push_str(&format!(
                        "approval: {}\n  run: {}\n  kind: {}\n  fingerprint: {}\n  created: {} expires: {}\n  capabilities:\n",
                        approval.approval_id,
                        approval.run_id,
                        approval.kind,
                        approval.fingerprint,
                        approval.created_at,
                        approval.expires_at
                    ));
                    for capability in &approval.capabilities {
                        out.push_str(&format!("    - {capability}\n"));
                    }
                    out.push_str(&format!("  arguments: {}\n", approval.arguments));
                }
                if approvals.is_empty() {
                    out.push_str("no pending approvals\n");
                }
                out
            }
            Self::RunShown(summary) => format!(
                "run: {}\nphase: {}\neffect certainty: {}\nterminal code: {}\nprimary diagnostic: {}\nsecondary diagnostic: {}\nterminal audit pending: {}\n",
                summary.run_id,
                summary.phase,
                summary.effect_certainty,
                summary.terminal_code.as_deref().unwrap_or("-"),
                summary.primary_diagnostic.as_deref().unwrap_or("-"),
                summary.secondary_diagnostic.as_deref().unwrap_or("-"),
                summary.terminal_audit_pending
            ),
            Self::HealthReported(summary) => {
                let mut out = String::new();
                for check in &summary.checks {
                    out.push_str(&format!(
                        "[{}] {}\n    {}\n",
                        if check.passed { "ok" } else { "FAIL" },
                        check.name,
                        check.detail
                    ));
                }
                out.push_str(if summary.healthy {
                    "overall: healthy\n"
                } else {
                    "overall: UNHEALTHY\n"
                });
                out
            }
            Self::SupportBundleExported(summary) => format!(
                "support bundle exported to {}\nfiles: {}  audit events: {}  redactions: {}  scanned bytes: {}\n",
                summary.path, summary.files, summary.audit_events, summary.redactions, summary.scanned_bytes
            ),
            Self::Unavailable(surface) => {
                format!("{} is unavailable: {}\n", surface.surface, surface.detail)
            }
        }
    }
}

pub async fn execute(cli: Cli) -> Result<CommandOutput, CliError> {
    if matches!(
        &cli.command,
        Command::Sandbox {
            command: SandboxCommand::Report
        }
    ) {
        return Ok(CommandOutput::SandboxReport(
            SystemSandbox::detect().report(),
        ));
    }
    let secret_input = if matches!(
        &cli.command,
        Command::Secret {
            command: SecretCommand::Create { .. }
        }
    ) {
        Some(
            tokio::task::spawn_blocking(read_secret_standard_input)
                .await
                .map_err(|error| CliError::Runtime(error.to_string()))??,
        )
    } else {
        None
    };
    let store = Arc::new(OsKeyringSecretStore::new("dev.lumen.runtime")?);
    execute_with_secret_store(cli, store, secret_input).await
}

#[doc(hidden)]
pub async fn execute_with_secret_store(
    cli: Cli,
    secret_store: Arc<dyn SecretStore>,
    secret_input: Option<Vec<u8>>,
) -> Result<CommandOutput, CliError> {
    if matches!(
        &cli.command,
        Command::Sandbox {
            command: SandboxCommand::Report
        }
    ) {
        return Ok(CommandOutput::SandboxReport(
            SystemSandbox::detect().report(),
        ));
    }
    let config = Config::load(&cli.config)?;
    prepare_directories(&config)?;
    match cli.command {
        Command::Migrate => {
            let database = Database::connect(&config.database.path).await?;
            database.close().await;
            Ok(CommandOutput::Migrated)
        }
        Command::Audit {
            command: AuditCommand::Verify,
        } => {
            if !config.database.path.is_file() {
                return Err(CliError::MissingDatabase(config.database.path));
            }
            let database = Database::connect(&config.database.path).await?;
            database.verify_audit_chain().await?;
            database.close().await;
            Ok(CommandOutput::AuditVerified)
        }
        Command::Audit {
            command: AuditCommand::List { kind, limit },
        } => {
            if !config.database.path.is_file() {
                return Err(CliError::MissingDatabase(config.database.path));
            }
            let database = Database::connect(&config.database.path).await?;
            let limit = limit.max(1);
            let mut events = Vec::new();
            let mut after: i64 = -1;
            loop {
                let batch = database
                    .list_audit_records(config.workspace_id(), after, limit.min(500))
                    .await?;
                if batch.is_empty() {
                    break;
                }
                for record in &batch {
                    after = after.max(record.sequence());
                    let matches_kind = kind
                        .as_ref()
                        .is_none_or(|wanted| record.event().kind().as_str() == wanted.as_str());
                    if !matches_kind {
                        continue;
                    }
                    events.push(AuditEventSummary {
                        sequence: record.sequence(),
                        event_id: record.event().id().to_string(),
                        timestamp: record.event().timestamp().as_u64(),
                        kind: record.event().kind().as_str().to_owned(),
                        outcome: serde_json::to_value(record.event().outcome())
                            .map(|value| value.as_str().unwrap_or("unknown").to_owned())
                            .unwrap_or_else(|_| "unknown".into()),
                        payload: serde_json::to_string(record.event().payload())
                            .unwrap_or_else(|_| "{}".into()),
                    });
                    if events.len() >= usize::from(limit) {
                        break;
                    }
                }
                if events.len() >= usize::from(limit) {
                    break;
                }
            }
            database.close().await;
            Ok(CommandOutput::AuditListed(events))
        }
        Command::Approvals {
            command: ApprovalsCommand::List,
        } => {
            if !config.database.path.is_file() {
                return Err(CliError::MissingDatabase(config.database.path));
            }
            let database = Database::connect(&config.database.path).await?;
            let pending = database
                .list_pending_approvals(config.workspace_id(), runtime::now())
                .await?;
            let summaries = pending
                .iter()
                .map(|approval| PendingApprovalSummary {
                    approval_id: approval.approval_id().to_string(),
                    run_id: approval.run_id().to_string(),
                    kind: approval.kind().to_owned(),
                    fingerprint: approval.fingerprint().to_owned(),
                    created_at: approval.created_at().as_u64(),
                    expires_at: approval.expires_at().as_u64(),
                    arguments: serde_json::to_string(approval.arguments())
                        .unwrap_or_else(|_| "{}".into()),
                    capabilities: approval
                        .capabilities()
                        .iter()
                        .map(|capability| {
                            serde_json::to_string(capability).unwrap_or_else(|_| "{}".into())
                        })
                        .collect(),
                })
                .collect();
            database.close().await;
            Ok(CommandOutput::ApprovalsListed(summaries))
        }
        Command::Run {
            command: RunCommand::Show { run_id },
        } => {
            if !config.database.path.is_file() {
                return Err(CliError::MissingDatabase(config.database.path));
            }
            let database = Database::connect(&config.database.path).await?;
            let lifecycle = database
                .get_run_lifecycle(config.workspace_id(), run_id)
                .await?
                .ok_or_else(|| CliError::Runtime("run was not found".into()))?;
            let summary = RunSummary {
                run_id: run_id.to_string(),
                phase: lifecycle.phase().to_owned(),
                effect_certainty: lifecycle.effect_certainty().as_str().to_owned(),
                terminal_code: lifecycle.terminal_code().map(str::to_owned),
                primary_diagnostic: lifecycle.primary_diagnostic().map(str::to_owned),
                secondary_diagnostic: lifecycle.secondary_diagnostic().map(str::to_owned),
                terminal_audit_pending: lifecycle.terminal_audit_pending(),
            };
            database.close().await;
            Ok(CommandOutput::RunShown(summary))
        }
        Command::Session {
            command: SessionCommand::List,
        } => Ok(CommandOutput::Unavailable(UnavailableSurface {
            surface: "session list".into(),
            detail: "Pi agent sessions are a Phase-1 surface: the lease/session store \
                     does not exist in this tree yet, so there is nothing to list. \
                     This command will be wired to the Phase-1 session store when it lands."
                .into(),
        })),
        Command::Lease {
            command: LeaseCommand::Show { lease_id },
        } => Ok(CommandOutput::Unavailable(UnavailableSurface {
            surface: format!("lease show {lease_id}"),
            detail: "Leases are a Phase-1 surface: the lease store does not exist in \
                     this tree yet, so there is nothing to show. This command will \
                     be wired to the Phase-1 lease store when it lands."
                .into(),
        })),
        Command::Health => {
            if !config.database.path.is_file() {
                return Err(CliError::MissingDatabase(config.database.path));
            }
            let database = Database::connect(&config.database.path).await?;
            let report = health::collect(&config, &database)
                .await
                .map_err(|error| CliError::Runtime(error.to_string()))?;
            let summary = HealthSummary {
                healthy: report.healthy,
                checks: report
                    .checks
                    .into_iter()
                    .map(|check| HealthCheckSummary {
                        name: check.name,
                        passed: check.passed,
                        detail: check.detail,
                    })
                    .collect(),
            };
            database.close().await;
            Ok(CommandOutput::HealthReported(summary))
        }
        Command::SupportBundle { out, audit_only } => {
            if !config.database.path.is_file() {
                return Err(CliError::MissingDatabase(config.database.path));
            }
            let database = Database::connect(&config.database.path).await?;
            let report =
                support_bundle::export_bundle(&config, &database, &cli.config, &out, audit_only)
                    .await
                    .map_err(|error| CliError::Runtime(error.to_string()))?;
            database.close().await;
            Ok(CommandOutput::SupportBundleExported(SupportBundleSummary {
                path: report.path.display().to_string(),
                files: report.files,
                audit_events: report.audit_events,
                redactions: report.redactions,
                scanned_bytes: report.scanned_bytes,
            }))
        }
        Command::Sandbox {
            command: SandboxCommand::Report,
        } => Ok(CommandOutput::SandboxReport(
            SystemSandbox::detect().report(),
        )),
        Command::Secret { command } => {
            execute_secret_command(&config, command, secret_store, secret_input).await
        }
        Command::Plugin { command } => execute_plugin_command(&config, command, secret_store).await,
        Command::Serve => serve(config, secret_store, &cli.config).await,
    }
}

fn parse_local_plugin_directory(value: &str) -> Result<PathBuf, String> {
    if value.is_empty() || value.contains("://") {
        return Err("plugin stage accepts a local directory only".into());
    }
    Ok(PathBuf::from(value))
}

fn parse_run_id(value: &str) -> Result<RunId, String> {
    uuid::Uuid::parse_str(value)
        .map(RunId::from_uuid)
        .map_err(|_| "run id must be a UUID".into())
}

async fn execute_plugin_command(
    config: &Config,
    command: PluginCommand,
    secret_store: Arc<dyn SecretStore>,
) -> Result<CommandOutput, CliError> {
    let database = Database::connect(&config.database.path).await?;
    let now = runtime::now();
    database
        .bootstrap_workspace(
            config.workspace_id(),
            &config.workspace.name,
            &config.bootstrap_principal(),
            now,
        )
        .await?;
    let output = match command {
        PluginCommand::Submit {
            directory,
            reason,
            as_principal,
        } => {
            let submission = plugin_admission::submit(
                config,
                &database,
                &directory,
                &reason,
                as_principal.as_deref(),
                now,
            )
            .await
            .map_err(|error| CliError::Runtime(error.to_string()))?;
            database
                .append_audit_event(AuditEvent::new(
                    AuditEventId::new(),
                    now,
                    AuditEventKind::PluginStaged,
                    AuditOutcome::Success,
                    Some(config.workspace_id()),
                    CanonicalValue::object([
                        (
                            "stage_id",
                            CanonicalValue::from(submission.stage_id.to_string()),
                        ),
                        (
                            "plugin_id",
                            CanonicalValue::from(submission.plugin_id.clone()),
                        ),
                        ("version", CanonicalValue::from(submission.version.clone())),
                        (
                            "package_digest",
                            CanonicalValue::from(submission.package_digest.clone()),
                        ),
                    ]),
                ))
                .await?;
            CommandOutput::PluginSubmitted(PluginSubmissionSummary {
                stage_id: submission.stage_id,
                plugin_id: submission.plugin_id,
                version: submission.version,
                package_digest: submission.package_digest,
                admission_status: submission.status,
            })
        }
        PluginCommand::Inspect { stage_id } => {
            let inspection = plugin_admission::inspect(config, &database, stage_id)
                .await
                .map_err(|error| CliError::Runtime(error.to_string()))?;
            CommandOutput::PluginInspected(PluginInspectionSummary {
                stage_id: inspection.stage_id,
                plugin_id: inspection.plugin_id,
                version: inspection.version,
                runtime: inspection.runtime,
                name: inspection.name,
                description: inspection.description,
                package_digest: inspection.package_digest,
                manifest_digest: inspection.manifest_digest,
                artifact_digest: inspection.artifact_digest,
                file_hashes: inspection.file_hashes.into_iter().collect(),
                requested_capabilities: inspection.requested_capabilities,
                admission_status: inspection.admission_status,
                decisions: inspection
                    .decisions
                    .into_iter()
                    .map(|decision| AdmissionDecisionSummary {
                        kind: decision.kind.as_str().to_owned(),
                        decided_by: decision.decided_by,
                        decided_at: decision.decided_at,
                        reason: decision.reason,
                        detail_digest: decision.detail_digest,
                    })
                    .collect(),
            })
        }
        PluginCommand::Test { stage_id } => {
            let outcome = plugin_admission::test(config, &database, stage_id, None, now)
                .await
                .map_err(|error| CliError::Runtime(error.to_string()))?;
            CommandOutput::PluginTested(PluginTestSummary {
                stage_id: outcome.stage_id,
                plugin_id: outcome.plugin_id,
                version: outcome.version,
                package_digest: outcome.package_digest,
                report_digest: outcome.report_digest,
                passed: outcome.passed,
                legs: outcome
                    .legs
                    .into_iter()
                    .map(|leg| PluginTestLegSummary {
                        name: leg.name,
                        passed: leg.passed,
                        detail: leg.detail,
                    })
                    .collect(),
                admission_status: outcome.status,
            })
        }
        PluginCommand::Approve {
            stage_id,
            reason,
            yes,
            as_principal,
        } => {
            if !yes && !confirm_dangerous_action("approve this plugin digest for deployment")? {
                return Err(CliError::Runtime("approval cancelled".into()));
            }
            let approval = plugin_admission::approve(
                config,
                &database,
                stage_id,
                &reason,
                as_principal.as_deref(),
                now,
            )
            .await
            .map_err(|error| CliError::Runtime(error.to_string()))?;
            CommandOutput::PluginApproved(PluginApprovalSummary {
                stage_id: approval.stage_id,
                plugin_id: approval.plugin_id,
                version: approval.version,
                package_digest: approval.package_digest,
                admission_status: approval.status,
            })
        }
        PluginCommand::List => {
            let records = plugin_admission::list(config)
                .map_err(|error| CliError::Runtime(error.to_string()))?;
            CommandOutput::PluginAdmissionsListed(
                records
                    .into_iter()
                    .map(|summary| AdmissionRecordSummary {
                        plugin_id: summary.plugin_id,
                        version: summary.version,
                        package_digest: summary.package_digest,
                        status: summary.status,
                        decisions: summary.decisions,
                    })
                    .collect(),
            )
        }
        PluginCommand::Revoke {
            plugin_id,
            version,
            reason,
            yes,
            as_principal,
        } => {
            if !yes && !confirm_dangerous_action("revoke this plugin digest (terminal)")? {
                return Err(CliError::Runtime("revocation cancelled".into()));
            }
            let revocation = plugin_admission::revoke(
                config,
                &plugin_id,
                &version,
                &reason,
                as_principal.as_deref(),
                now,
            )
            .map_err(|error| CliError::Runtime(error.to_string()))?;
            // Request disable of any enabled deployment through the normal
            // approval-bound machinery; the digest itself is already revoked
            // above and can never be re-enabled.
            let proposal = extension_action_proposal(
                config,
                &database,
                PluginCommand::Disable {
                    plugin_id: plugin_id.clone(),
                    version: version.clone(),
                },
            )
            .await?;
            let capabilities = lumen_core::capability::CapabilitySet::new(
                extension_runtime::admin_capabilities(&plugin_id, &version)
                    .map_err(|error| CliError::Runtime(error.to_string()))?,
            );
            let sandbox: Arc<dyn SandboxBackend> = Arc::new(SystemSandbox::detect());
            let service = runtime::LocalRuntimeService::build_with_secret_store(
                config,
                database.clone(),
                EventBroker::new(64),
                sandbox,
                Vec::new(),
                secret_store,
            )
            .await?;
            let run_id = service
                .request_extension_action(
                    config.workspace_id(),
                    config.bootstrap_principal(),
                    proposal.0,
                    capabilities,
                )
                .await
                .map_err(|error| CliError::Runtime(error.to_string()))?;
            let approval_id = wait_for_pending_approval(&database, config, run_id).await?;
            CommandOutput::PluginRevoked(PluginRevocationSummary {
                plugin_id: revocation.plugin_id,
                version: revocation.version,
                package_digest: revocation.package_digest,
                disable_run_id: run_id,
                disable_approval_id: approval_id,
            })
        }
        PluginCommand::Invoke {
            plugin_id,
            version,
            component_id,
            input,
        } => {
            let input: CanonicalValue = serde_json::from_slice(&std::fs::read(input)?)
                .map_err(|error| CliError::Runtime(format!("invalid plugin input: {error}")))?;
            let sandbox: Arc<dyn SandboxBackend> = Arc::new(SystemSandbox::detect());
            let service = runtime::LocalRuntimeService::build_with_secret_store(
                config,
                database.clone(),
                EventBroker::new(64),
                sandbox,
                Vec::new(),
                secret_store,
            )
            .await?;
            let run_id = service
                .request_plugin_invocation(
                    config.workspace_id(),
                    config.bootstrap_principal(),
                    &plugin_id,
                    &version,
                    &component_id,
                    input,
                )
                .await
                .map_err(|error| CliError::Runtime(error.to_string()))?;
            // The request is approval-bound: the run parks awaiting the
            // operator's decision. The CLI must not drain-and-cancel it —
            // the approval stays pending for the web UI / API.
            let approval_id = wait_for_pending_approval(&database, config, run_id).await?;
            CommandOutput::PluginActionRequested(PluginActionRequest {
                run_id,
                approval_id,
            })
        }
        command => {
            let (proposal, plugin_id, version) =
                extension_action_proposal(config, &database, command).await?;
            // Install and enable are gated on the admission workflow: the
            // digest must be approved and not revoked. Install arguments
            // carry the staged digest; enable resolves it via the index.
            if proposal.kind() == "plugin.enable" {
                plugin_admission::require_enabled_at(
                    &config.runtime.data_directory,
                    &plugin_id,
                    &version,
                )
                .map_err(|error| CliError::Runtime(error.to_string()))?;
            }
            let capabilities = lumen_core::capability::CapabilitySet::new(
                extension_runtime::admin_capabilities(&plugin_id, &version)
                    .map_err(|error| CliError::Runtime(error.to_string()))?,
            );
            let sandbox: Arc<dyn SandboxBackend> = Arc::new(SystemSandbox::detect());
            let service = runtime::LocalRuntimeService::build_with_secret_store(
                config,
                database.clone(),
                EventBroker::new(64),
                sandbox,
                Vec::new(),
                secret_store,
            )
            .await?;
            let run_id = service
                .request_extension_action(
                    config.workspace_id(),
                    config.bootstrap_principal(),
                    proposal,
                    capabilities,
                )
                .await
                .map_err(|error| CliError::Runtime(error.to_string()))?;
            // The request is approval-bound: the run parks awaiting the
            // operator's decision. The CLI must not drain-and-cancel it —
            // the approval stays pending for the web UI / API.
            let approval_id = wait_for_pending_approval(&database, config, run_id).await?;
            CommandOutput::PluginActionRequested(PluginActionRequest {
                run_id,
                approval_id,
            })
        }
    };
    database.close().await;
    Ok(output)
}

async fn extension_action_proposal(
    config: &Config,
    database: &Database,
    command: PluginCommand,
) -> Result<(lumen_core::model::ActionProposal, String, String), CliError> {
    use extension_runtime::{
        GrantArguments, GrantInput, InstallArguments, QuarantineReleaseArguments, SettingArguments,
        VersionArguments, action_proposal,
    };

    let result = match command {
        PluginCommand::Install { stage_id } => {
            let staged = database
                .staged_plugin_package(stage_id)
                .await?
                .ok_or_else(|| CliError::Runtime("staged plugin package was not found".into()))?;
            // Admission gate: only an approved, unrevoked digest may be
            // installed.
            plugin_admission::require_installable(
                config,
                staged.manifest().id().as_str(),
                staged.manifest().version().as_str(),
                staged.package_digest(),
            )
            .map_err(|error| CliError::Runtime(error.to_string()))?;
            let arguments = InstallArguments {
                stage_id,
                plugin_id: staged.manifest().id().to_string(),
                plugin_version: staged.manifest().version().to_string(),
                package_digest: staged.package_digest().to_string(),
                manifest_digest: staged.manifest_digest().to_string(),
                artifact_digest: staged.manifest().integrity().artifact().to_string(),
            };
            let plugin = arguments.plugin_id.clone();
            let version = arguments.plugin_version.clone();
            (
                action_proposal("plugin.install", &arguments),
                plugin,
                version,
            )
        }
        PluginCommand::Enable { plugin_id, version } => {
            let arguments = VersionArguments {
                plugin_id: plugin_id.clone(),
                plugin_version: version.clone(),
            };
            (
                action_proposal("plugin.enable", &arguments),
                plugin_id,
                version,
            )
        }
        PluginCommand::Disable { plugin_id, version } => {
            let arguments = VersionArguments {
                plugin_id: plugin_id.clone(),
                plugin_version: version.clone(),
            };
            (
                action_proposal("plugin.disable", &arguments),
                plugin_id,
                version,
            )
        }
        PluginCommand::CapabilitiesSet {
            plugin_id,
            version,
            component_id,
            scope,
            expected_revision,
            grants,
        } => {
            let grants: Vec<GrantInput> = serde_json::from_slice(&std::fs::read(grants)?)
                .map_err(|error| CliError::Runtime(format!("invalid grants file: {error}")))?;
            let scope_id = match scope.as_str() {
                "global" => "*".to_owned(),
                "workspace" => config.workspace_id().to_string(),
                _ => {
                    return Err(CliError::Runtime(
                        "grant scope must be global or workspace".into(),
                    ));
                }
            };
            let arguments = GrantArguments {
                plugin_id: plugin_id.clone(),
                plugin_version: version.clone(),
                component_id,
                scope_type: scope,
                scope_id,
                expected_revision,
                grants,
            };
            (
                action_proposal("plugin.capabilities.set", &arguments),
                plugin_id,
                version,
            )
        }
        PluginCommand::SettingsSet {
            plugin_id,
            version,
            scope,
            scope_id,
            expected_version,
            config: config_path,
        } => {
            let installed = database
                .installed_plugin_version(
                    lumen_core::extension::PluginId::parse(&plugin_id)
                        .map_err(|error| CliError::Runtime(error.to_string()))?,
                    lumen_core::extension::PluginVersion::parse(&version)
                        .map_err(|error| CliError::Runtime(error.to_string()))?,
                )
                .await?
                .ok_or_else(|| {
                    CliError::Runtime("installed plugin version was not found".into())
                })?;
            let settings = installed
                .manifest()
                .settings()
                .ok_or_else(|| CliError::Runtime("plugin does not declare settings".into()))?;
            let package_root = config
                .runtime
                .data_directory
                .join(installed.artifact_path())
                .parent()
                .ok_or_else(|| CliError::Runtime("installed artifact has no package root".into()))?
                .to_path_buf();
            let schema = std::fs::read(package_root.join(settings.schema().as_str()))?;
            let schema_digest = format!("{:x}", sha2::Sha256::digest(schema));
            let config_value: CanonicalValue = serde_json::from_slice(&std::fs::read(config_path)?)
                .map_err(|error| CliError::Runtime(format!("invalid settings file: {error}")))?;
            let scope_id = match (scope.as_str(), scope_id) {
                ("global", None) => "*".to_owned(),
                ("workspace", None) => config.workspace_id().to_string(),
                ("user", None) => format!(
                    "{}:{}",
                    config.bootstrap_principal().provider(),
                    config.bootstrap_principal().subject()
                ),
                ("agent", Some(id)) => id,
                _ => {
                    return Err(CliError::Runtime(
                        "invalid settings scope or scope ID".into(),
                    ));
                }
            };
            let arguments = SettingArguments {
                plugin_id: plugin_id.clone(),
                plugin_version: version.clone(),
                scope_type: scope,
                scope_id,
                expected_version,
                config: config_value,
                schema_digest,
            };
            (
                action_proposal("plugin.settings.set", &arguments),
                plugin_id,
                version,
            )
        }
        PluginCommand::QuarantineRelease {
            plugin_id,
            version,
            kind,
        } => {
            let arguments = QuarantineReleaseArguments {
                plugin_id: plugin_id.clone(),
                plugin_version: version.clone(),
                quarantine_type: kind,
            };
            (
                action_proposal("plugin.quarantine.release", &arguments),
                plugin_id,
                version,
            )
        }
        PluginCommand::Submit { .. }
        | PluginCommand::Inspect { .. }
        | PluginCommand::Test { .. }
        | PluginCommand::Approve { .. }
        | PluginCommand::List
        | PluginCommand::Revoke { .. }
        | PluginCommand::Invoke { .. } => {
            return Err(CliError::Runtime(
                "command is not an extension action".into(),
            ));
        }
    };
    Ok((
        result
            .0
            .map_err(|error| CliError::Runtime(error.to_string()))?,
        result.1,
        result.2,
    ))
}

/// Find the pending approval request for a run, if any.
///
/// Approval-bound CLI requests park the run awaiting the operator's
/// decision; this resolves the approval the operator must decide in the
/// web UI or API.
async fn pending_approval_for_run(
    database: &Database,
    config: &Config,
    run_id: RunId,
) -> Result<Option<String>, CliError> {
    let now = runtime::now();
    let pending = database
        .list_pending_approvals(config.workspace_id(), now)
        .await?;
    Ok(pending
        .iter()
        .find(|approval| approval.run_id() == run_id)
        .map(|approval| approval.approval_id().to_string()))
}

/// Wait for the background run to durably create its approval request.
/// The run executes asynchronously; the CLI must not exit until the
/// approval is in the database, otherwise the request would be lost
/// with the transient runtime. The run itself stays parked — this
/// waits for creation, never for resolution.
async fn wait_for_pending_approval(
    database: &Database,
    config: &Config,
    run_id: RunId,
) -> Result<Option<String>, CliError> {
    use std::time::Duration;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(approval_id) = pending_approval_for_run(database, config, run_id).await? {
            return Ok(Some(approval_id));
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Interactive confirmation for dangerous actions. Returns true when the
/// operator explicitly confirms. Non-tty stdin fails closed.
fn confirm_dangerous_action(action: &str) -> Result<bool, CliError> {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Runtime(
            "refusing dangerous action without a terminal; pass --yes to confirm".into(),
        ));
    }
    print!("Confirm: {action}? [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().eq_ignore_ascii_case("y"))
}

async fn execute_secret_command(
    config: &Config,
    command: SecretCommand,
    store: Arc<dyn SecretStore>,
    input: Option<Vec<u8>>,
) -> Result<CommandOutput, CliError> {
    let database = Database::connect(&config.database.path).await?;
    database
        .bootstrap_workspace(
            config.workspace_id(),
            &config.workspace.name,
            &config.bootstrap_principal(),
            runtime::now(),
        )
        .await?;
    let result = match command {
        SecretCommand::Create {
            label,
            program,
            environment,
        } => {
            let value = input.ok_or(CliError::MissingSecretInput)?;
            validate_secret_input(&value)?;
            let executable = std::fs::canonicalize(program)?
                .to_string_lossy()
                .into_owned();
            let reference = SecretReference::new(
                SecretRefId::new(),
                config.workspace_id(),
                label,
                executable,
                environment,
                runtime::now(),
            )?;
            store.put(reference.keychain_account(), value).await?;
            if let Err(error) = database.insert_secret_reference(&reference).await {
                let _ = store.delete(reference.keychain_account()).await;
                return Err(error.into());
            }
            CommandOutput::SecretCreated(reference)
        }
        SecretCommand::List => CommandOutput::SecretReferences(
            database
                .list_secret_references(config.workspace_id())
                .await?,
        ),
        SecretCommand::Delete { id } => {
            let reference = database
                .get_secret_reference(config.workspace_id(), id)
                .await?
                .ok_or(CliError::SecretNotFound(id))?;
            store.delete(reference.keychain_account()).await?;
            if !database
                .delete_secret_reference(config.workspace_id(), id)
                .await?
            {
                return Err(CliError::SecretNotFound(id));
            }
            CommandOutput::SecretDeleted(id)
        }
    };
    database.close().await;
    Ok(result)
}

const SECRET_INPUT_LIMIT: u64 = 64 * 1024;

fn read_secret_standard_input() -> Result<Vec<u8>, CliError> {
    let mut value = Vec::new();
    std::io::stdin()
        .take(SECRET_INPUT_LIMIT + 1)
        .read_to_end(&mut value)?;
    validate_secret_input(&value)?;
    Ok(value)
}

fn validate_secret_input(value: &[u8]) -> Result<(), CliError> {
    if value.is_empty()
        || u64::try_from(value.len()).unwrap_or(u64::MAX) > SECRET_INPUT_LIMIT
        || value.contains(&0)
        || std::str::from_utf8(value).is_err()
    {
        return Err(CliError::InvalidSecretInput);
    }
    Ok(())
}

async fn serve(
    config: Config,
    secret_store: Arc<dyn SecretStore>,
    config_path: &Path,
) -> Result<CommandOutput, CliError> {
    let sandbox: Arc<dyn SandboxBackend> = Arc::new(SystemSandbox::detect());
    let sandbox_report = sandbox.report();
    eprintln!(
        "event=server_starting bind={} config={config_path:?} workspace={} backend={} strength={} pid={}",
        config.server.bind,
        config.workspace_id(),
        sandbox_report.backend(),
        sandbox_report.strength().as_str(),
        std::process::id()
    );
    config.validate_sandbox(&sandbox_report)?;
    let token = std::env::var(&config.authentication.token_environment).map_err(|_| {
        CliError::MissingEnvironment(config.authentication.token_environment.clone())
    })?;
    let owner_guard = Arc::new(acquire_runtime_ownership(&config.database.path)?);
    let database = Database::connect(&config.database.path).await?;
    database.verify_audit_chain().await?;
    let now = runtime::now();
    database
        .bootstrap_workspace(
            config.workspace_id(),
            &config.workspace.name,
            &config.bootstrap_principal(),
            now,
        )
        .await?;
    let recovered = database.recover_incomplete_executions(now).await?;
    for execution in recovered {
        database
            .append_audit_event(AuditEvent::new(
                AuditEventId::new(),
                now,
                AuditEventKind::ExecutionUnknown,
                AuditOutcome::Unknown,
                Some(execution.workspace_id()),
                CanonicalValue::object([
                    (
                        "run_id",
                        CanonicalValue::from(execution.run_id().to_string()),
                    ),
                    (
                        "action_id",
                        CanonicalValue::from(execution.action_id().to_string()),
                    ),
                    (
                        "attempt_id",
                        CanonicalValue::from(execution.attempt_id().to_string()),
                    ),
                ]),
            ))
            .await?;
    }

    let listener = match tokio::net::TcpListener::bind(config.server.bind).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!(
                "event=server_bind_failed bind={} config={config_path:?} workspace={} pid={} error={error}",
                config.server.bind,
                config.workspace_id(),
                std::process::id()
            );
            database.close().await;
            return Err(CliError::Io(error));
        }
    };

    let events = EventBroker::new(1024);
    let service = Arc::new(
        runtime::LocalRuntimeService::build_with_runtime_owner(
            &config,
            database.clone(),
            events.clone(),
            Arc::clone(&sandbox),
            vec![token.clone()],
            Arc::clone(&secret_store),
            Arc::clone(&owner_guard),
        )
        .await?,
    );
    let profiles = database.list_latest_model_profiles().await?;
    let mut provider_limits = BTreeMap::<String, usize>::new();
    for profile in &profiles {
        *provider_limits
            .entry(profile.provider_id().as_str().to_owned())
            .or_default() += usize::try_from(profile.concurrency_limit()).unwrap_or(usize::MAX / 4);
    }
    let mut state = ApiState::new(
        service.clone(),
        events.clone(),
        token,
        config.bootstrap_principal(),
        BTreeSet::from([config.workspace_id()]),
        api_sandbox_report(&sandbox_report),
    )?;
    if !provider_limits.is_empty() {
        let global = provider_limits
            .values()
            .copied()
            .fold(0usize, usize::saturating_add)
            .max(1);
        let scheduler = WorkerScheduler::new(
            database.clone(),
            Arc::new(DatabaseWorkerMaterializer::new(
                database.clone(),
                Arc::clone(&secret_store),
            )),
            service.worker_kernel_ports(),
            WorkerSchedulerConfig::new(global, provider_limits, Duration::from_secs(30))
                .map_err(|error| CliError::Runtime(error.to_string()))?,
            service.worker_owner_id(),
        );
        service
            .attach_worker_scheduler(Arc::clone(&scheduler))
            .await;
        let budget = WorkerRunBudget::new(
            config.runtime.max_model_turns,
            config.runtime.max_actions,
            config.runtime.max_wall_time_seconds.saturating_mul(1_000),
            config.runtime.max_captured_result_bytes,
        )
        .map_err(|error| CliError::Runtime(error.to_string()))?;
        let control = Arc::new(OrchestrationControl::new(
            database.clone(),
            scheduler,
            Arc::new(JsonModelPlanner::new(
                service.planner_model(config.workspace_id()),
            )),
            Arc::new(BootstrapOperatorAuthority::new(
                config.bootstrap_principal(),
                config.workspace_id(),
            )),
            DatabaseCandidateCatalog::new(database.clone(), service.worker_grants()?, budget),
            config.workspace_id(),
        ));
        control
            .recover(lumen_core::approval::TimestampMillis::new(0))
            .await
            .map_err(|error| CliError::Runtime(error.to_string()))?;
        state = state.with_orchestration_service(control);
    }
    let server_result = serve_listener_until_shutdown(
        listener,
        router(state),
        events,
        service,
        (
            config_path,
            &config.workspace_id().to_string(),
            &sandbox_report,
        ),
        shutdown_signal(),
    )
    .await;
    let close_result =
        tokio::time::timeout(std::time::Duration::from_millis(500), database.close()).await;
    let outcome = match (server_result, close_result) {
        (Err(error), _) => Err(CliError::Io(error)),
        (_, Err(_)) => Err(CliError::Runtime("database close deadline exceeded".into())),
        (Ok(()), Ok(())) => Ok(()),
    };
    if outcome.is_err() {
        // An aborted native worker may still be running until bounded Tokio teardown.
        // Keep the process-held ownership lock until process exit in that case.
        std::mem::forget(owner_guard);
    }
    outcome?;
    Ok(CommandOutput::ServerStopped)
}

async fn serve_listener_until_shutdown(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    events: EventBroker,
    service: Arc<runtime::LocalRuntimeService>,
    diagnostics: (&Path, &str, &SandboxReport),
    signal: impl Future<Output = ()>,
) -> Result<(), std::io::Error> {
    let (config_path, workspace_id, sandbox_report) = diagnostics;
    let bind = listener.local_addr()?;
    eprintln!(
        "event=server_started bind={bind} config={config_path:?} workspace={workspace_id} backend={} strength={} pid={}",
        sandbox_report.backend(),
        sandbox_report.strength().as_str(),
        std::process::id()
    );
    let stop_accepting = CancellationToken::new();
    let server_result = {
        let shutdown = stop_accepting.clone();
        let server = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown.cancelled().await;
            })
            .into_future();
        tokio::pin!(server);
        tokio::select! {
            result = &mut server => result,
            () = signal => {
                eprintln!("event=server_stopping bind={bind} pid={}", std::process::id());
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(6);
                stop_accepting.cancel();
                events.close();
                let report = service.shutdown().await;
                let drained = match tokio::time::timeout_at(deadline, &mut server).await {
                    Ok(result) => result,
                    Err(_) => {
                        eprintln!("event=server_shutdown_forced bind={bind} pid={}", std::process::id());
                        Err(std::io::Error::other("HTTP drain deadline exceeded"))
                    }
                };
                if !report.is_clean() {
                    Err(std::io::Error::other("runtime shutdown left unresolved work"))
                } else { drained }
            }
        }
    };
    stop_accepting.cancel();
    events.close();
    let report = service.shutdown().await;
    let server_result = if report.is_clean() {
        server_result
    } else {
        Err(std::io::Error::other(
            "runtime shutdown left unresolved work",
        ))
    };
    eprintln!(
        "event=server_stopped bind={bind} pid={} result={}",
        std::process::id(),
        if server_result.is_ok() { "ok" } else { "error" }
    );
    server_result
}

fn api_sandbox_report(report: &SandboxReport) -> SandboxCapabilityReport {
    SandboxCapabilityReport::new(
        report.backend(),
        report.strength().as_str(),
        report
            .guarantees()
            .iter()
            .map(|guarantee| guarantee.as_str()),
        report.detail().map(str::to_owned),
    )
}

fn prepare_directories(config: &Config) -> Result<(), CliError> {
    std::fs::create_dir_all(&config.runtime.data_directory)?;
    if let Some(parent) = config.database.path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn acquire_runtime_ownership(database_path: &Path) -> Result<std::fs::File, CliError> {
    if std::fs::symlink_metadata(database_path)
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(CliError::Runtime(
            "database path must not be a symlink".into(),
        ));
    }
    let parent = database_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = std::fs::canonicalize(parent)?;
    let name = database_path
        .file_name()
        .ok_or_else(|| CliError::Runtime("database path has no file name".into()))?;
    let lock_path = parent.join(format!(".{}.lumen-owner.lock", name.to_string_lossy()));
    if std::fs::symlink_metadata(&lock_path).is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(CliError::Runtime(
            "runtime lock path must not be a symlink".into(),
        ));
    }
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    lock.try_lock().map_err(|error| {
        CliError::Runtime(format!(
            "runtime ownership unavailable for {}: {error}",
            database_path.display()
        ))
    })?;
    Ok(lock)
}

#[cfg(test)]
mod runtime_ownership_tests {
    use super::acquire_runtime_ownership;

    #[test]
    fn a_second_runtime_cannot_own_the_same_database_until_the_first_releases_it() {
        let directory = tempfile::tempdir().expect("directory");
        let database = directory.path().join("lumen.sqlite3");
        let first = acquire_runtime_ownership(&database).expect("first owner");
        assert!(acquire_runtime_ownership(&database).is_err());
        drop(first);
        acquire_runtime_ownership(&database).expect("owner after release");
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    result = tokio::signal::ctrl_c() => {
                        if let Err(error) = result {
                            eprintln!("event=shutdown_signal_failed signal=ctrl_c diagnostic={error:?}");
                        }
                    }
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                eprintln!("event=shutdown_signal_failed signal=terminate diagnostic={error:?}");
                if let Err(error) = tokio::signal::ctrl_c().await {
                    eprintln!("event=shutdown_signal_failed signal=ctrl_c diagnostic={error:?}");
                }
            }
        }
    }
    #[cfg(not(unix))]
    if let Err(error) = tokio::signal::ctrl_c().await {
        eprintln!("event=shutdown_signal_failed signal=ctrl_c diagnostic={error:?}");
    }
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    AuditIntegrity(#[from] AuditIntegrityError),
    #[error(transparent)]
    SecretReference(#[from] SecretReferenceError),
    #[error(transparent)]
    SecretStore(#[from] SecretStoreError),
    #[error(transparent)]
    PackageStage(#[from] PackageStageError),
    #[error(transparent)]
    ApiState(#[from] lumen_server::ApiStateError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("required environment variable is missing: {0}")]
    MissingEnvironment(String),
    #[error("database does not exist: {0}")]
    MissingDatabase(PathBuf),
    #[error("runtime composition failed: {0}")]
    Runtime(String),
    #[error("secret creation requires a value on standard input")]
    MissingSecretInput,
    #[error("secret input must be non-empty UTF-8 without NUL bytes and at most 64 KiB")]
    InvalidSecretInput,
    #[error("secret reference was not found: {0}")]
    SecretNotFound(SecretRefId),
}
