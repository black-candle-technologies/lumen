use std::{net::IpAddr, path::PathBuf};

use clap::Parser;
use lumen_cli::{
    AuditCommand, Cli, Command, SandboxCommand,
    config::{Config, ConfigError, RequiredSandboxStrength},
};
use lumen_integrations::sandbox::{SandboxReport, SandboxStrength};

const MINIMAL_CONFIG: &str = r#"
[database]
path = "runtime/lumen.sqlite3"

[model]
endpoint = "http://127.0.0.1:8080/v1/"
model = "local-model"

[workspace]
id = "26db5a31-94f0-4e92-a9c9-4cdf19d71c31"
name = "Default"
path = "."

[bootstrap_admin]
provider = "local"
subject = "operator"
"#;

#[test]
fn strict_config_rejects_unknown_fields() {
    let config = format!("{MINIMAL_CONFIG}\nunknown = true\n");
    let error = Config::parse(&config).expect_err("unknown field must fail");
    assert!(matches!(error, ConfigError::Parse(_)));
}

#[test]
fn secure_defaults_are_local_and_fail_closed() {
    let config = Config::parse(MINIMAL_CONFIG).expect("config parses");

    assert!(config.server.bind.ip().is_loopback());
    assert_eq!(config.server.bind.port(), 3210);
    assert_eq!(
        config.authentication.token_environment,
        "LUMEN_BEARER_TOKEN"
    );
    assert!(!config.model.allow_remote);
    assert_eq!(
        config.sandbox.required_strength,
        RequiredSandboxStrength::KernelEnforced
    );
    assert!(config.process.allowed_programs.is_empty());
    assert_eq!(config.runtime.file_write_limit_bytes, 1024 * 1024);
}

#[test]
fn non_loopback_bind_is_rejected_for_the_local_runtime() {
    let config = MINIMAL_CONFIG.replace(
        "[database]",
        "[server]\nbind = \"0.0.0.0:3210\"\n\n[database]",
    );
    let error = Config::parse(&config).expect_err("public bind must fail");
    assert_eq!(
        error,
        ConfigError::NonLoopbackBind(IpAddr::from([0, 0, 0, 0]))
    );
}

#[test]
fn remote_model_endpoint_is_rejected_by_default() {
    let config = MINIMAL_CONFIG.replace("127.0.0.1:8080", "models.example.com");
    let error = Config::parse(&config).expect_err("remote endpoint must fail");
    assert_eq!(error, ConfigError::RemoteModelDenied);
}

#[test]
fn required_sandbox_strength_must_be_available() {
    let config = Config::parse(MINIMAL_CONFIG).expect("config parses");
    let report = SandboxReport::new(
        "test",
        SandboxStrength::Unavailable,
        Some("not installed".into()),
    );

    let error = config
        .validate_sandbox(&report)
        .expect_err("missing sandbox must fail");

    assert_eq!(
        error,
        ConfigError::SandboxUnavailable("test: not installed".into())
    );
}

#[test]
fn operator_commands_have_one_unambiguous_grammar() {
    let migrate = Cli::try_parse_from(["lumen", "--config", "custom.toml", "migrate"])
        .expect("migrate command");
    assert_eq!(migrate.config, PathBuf::from("custom.toml"));
    assert_eq!(migrate.command, Command::Migrate);

    let serve = Cli::try_parse_from(["lumen", "serve"]).expect("serve command");
    assert_eq!(serve.command, Command::Serve);

    let verify = Cli::try_parse_from(["lumen", "audit", "verify"]).expect("audit command");
    assert_eq!(
        verify.command,
        Command::Audit {
            command: AuditCommand::Verify
        }
    );

    let report = Cli::try_parse_from(["lumen", "sandbox", "report"]).expect("sandbox command");
    assert_eq!(
        report.command,
        Command::Sandbox {
            command: SandboxCommand::Report
        }
    );
}
