pub mod config;
mod runtime;

use std::{collections::BTreeSet, path::PathBuf, sync::Arc};

use clap::{Parser, Subcommand};
use config::{Config, ConfigError};
use lumen_core::audit::AuditIntegrityError;
use lumen_core::{
    action::CanonicalValue,
    audit::{AuditEvent, AuditEventId, AuditEventKind, AuditOutcome},
};
use lumen_db::{Database, RepositoryError};
use lumen_integrations::sandbox::{SandboxBackend, SandboxReport, SystemSandbox};
use lumen_server::{ApiState, EventBroker, SandboxCapabilityReport, router};
use thiserror::Error;

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
    Sandbox {
        #[command(subcommand)]
        command: SandboxCommand,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum AuditCommand {
    Verify,
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum SandboxCommand {
    Report,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandOutput {
    Migrated,
    AuditVerified,
    ServerStopped,
    SandboxReport(SandboxReport),
}

pub async fn execute(cli: Cli) -> Result<CommandOutput, CliError> {
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
        Command::Sandbox {
            command: SandboxCommand::Report,
        } => Ok(CommandOutput::SandboxReport(
            SystemSandbox::detect().report(),
        )),
        Command::Serve => serve(config).await,
    }
}

async fn serve(config: Config) -> Result<CommandOutput, CliError> {
    let sandbox: Arc<dyn SandboxBackend> = Arc::new(SystemSandbox::detect());
    config.validate_sandbox(&sandbox.report())?;
    let token = std::env::var(&config.authentication.token_environment).map_err(|_| {
        CliError::MissingEnvironment(config.authentication.token_environment.clone())
    })?;
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

    let events = EventBroker::new(1024);
    let service = Arc::new(runtime::LocalRuntimeService::build_with_secrets(
        &config,
        database.clone(),
        events.clone(),
        Arc::clone(&sandbox),
        vec![token.clone()],
    )?);
    let state = ApiState::new(
        service.clone(),
        events,
        token,
        config.bootstrap_principal(),
        BTreeSet::from([config.workspace_id()]),
        api_sandbox_report(&sandbox.report()),
    )?;
    let listener = tokio::net::TcpListener::bind(config.server.bind).await?;
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    service.shutdown().await;
    database.close().await;
    Ok(CommandOutput::ServerStopped)
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

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
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
    ApiState(#[from] lumen_server::ApiStateError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("required environment variable is missing: {0}")]
    MissingEnvironment(String),
    #[error("database does not exist: {0}")]
    MissingDatabase(PathBuf),
    #[error("runtime composition failed: {0}")]
    Runtime(String),
}
