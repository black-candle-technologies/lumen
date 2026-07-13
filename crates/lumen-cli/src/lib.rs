pub mod config;
mod runtime;

use std::{collections::BTreeSet, io::Read, path::PathBuf, sync::Arc};

use clap::{Parser, Subcommand};
use config::{Config, ConfigError};
use lumen_core::audit::AuditIntegrityError;
use lumen_core::{
    action::CanonicalValue,
    audit::{AuditEvent, AuditEventId, AuditEventKind, AuditOutcome},
    secret::SecretRefId,
};
use lumen_db::{Database, RepositoryError, SecretReference, SecretReferenceError};
use lumen_integrations::{
    sandbox::{SandboxBackend, SandboxReport, SystemSandbox},
    secrets::{OsKeyringSecretStore, SecretStore, SecretStoreError},
};
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
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
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
    ServerStopped,
    SandboxReport(SandboxReport),
    SecretCreated(SecretReference),
    SecretReferences(Vec<SecretReference>),
    SecretDeleted(SecretRefId),
}

pub async fn execute(cli: Cli) -> Result<CommandOutput, CliError> {
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
        Command::Secret { command } => {
            execute_secret_command(&config, command, secret_store, secret_input).await
        }
        Command::Serve => serve(config, secret_store).await,
    }
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
) -> Result<CommandOutput, CliError> {
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
    let service = Arc::new(
        runtime::LocalRuntimeService::build_with_secret_store(
            &config,
            database.clone(),
            events.clone(),
            Arc::clone(&sandbox),
            vec![token.clone()],
            secret_store,
        )
        .await?,
    );
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
    SecretReference(#[from] SecretReferenceError),
    #[error(transparent)]
    SecretStore(#[from] SecretStoreError),
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
