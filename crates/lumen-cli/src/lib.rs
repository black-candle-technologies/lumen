pub mod config;
mod runtime;

use std::{collections::BTreeSet, path::PathBuf, sync::Arc};

use clap::{Parser, Subcommand};
use config::{Config, ConfigError};
use lumen_core::audit::AuditIntegrityError;
use lumen_db::{Database, RepositoryError};
use lumen_integrations::sandbox::{SandboxBackend, SystemSandbox};
use lumen_server::{ApiState, EventBroker, router};
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
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum AuditCommand {
    Verify,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandOutput {
    Migrated,
    AuditVerified,
    ServerStopped,
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
        Command::Serve => serve(config).await,
    }
}

async fn serve(config: Config) -> Result<CommandOutput, CliError> {
    let sandbox = Arc::new(SystemSandbox::detect());
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

    let events = EventBroker::new(1024);
    let service = Arc::new(runtime::LocalRuntimeService::build(
        &config,
        database.clone(),
        events.clone(),
        sandbox,
    )?);
    let state = ApiState::new(
        service.clone(),
        events,
        token,
        config.bootstrap_principal(),
        BTreeSet::from([config.workspace_id()]),
    )?;
    let listener = tokio::net::TcpListener::bind(config.server.bind).await?;
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    service.shutdown().await;
    database.close().await;
    Ok(CommandOutput::ServerStopped)
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
