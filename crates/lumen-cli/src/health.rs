//! Health and diagnostics for the local operator.
//!
//! `lumen health` runs a fixed set of checks against the real configured
//! state: the config that was loaded, the database file, the audit chain,
//! the detected sandbox backend, the admission store, and (best-effort) the
//! configured model endpoint. Every check reports pass/fail with a detail
//! string; nothing is simulated.

use std::time::Duration;

use lumen_db::Database;
use lumen_integrations::sandbox::{SandboxBackend, SandboxReport, SystemSandbox};
use serde::Serialize;
use thiserror::Error;

use crate::config::Config;

#[derive(Debug, Error)]
pub enum HealthError {
    #[error(transparent)]
    Database(#[from] lumen_db::RepositoryError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Audit(#[from] lumen_core::audit::AuditIntegrityError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HealthCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HealthReport {
    pub checks: Vec<HealthCheck>,
    pub healthy: bool,
}

impl HealthReport {
    pub fn new(checks: Vec<HealthCheck>) -> Self {
        let healthy = checks.iter().all(|check| check.passed);
        Self { checks, healthy }
    }
}

fn check(name: &str, passed: bool, detail: String) -> HealthCheck {
    HealthCheck {
        name: name.to_owned(),
        passed,
        detail,
    }
}

/// The sandbox health check. The verdict mirrors `serve`'s gate
/// (`Config::validate_sandbox`): a backend name alone is not enough — e.g.
/// on Linux without a usable bubblewrap install the backend reports
/// `linux-bubblewrap` with `SandboxStrength::Unavailable`, which must fail
/// the check when the configuration requires kernel-enforced sandboxing.
fn sandbox_check(config: &Config, report: &SandboxReport) -> HealthCheck {
    let result = config.validate_sandbox(report);
    let passed = result.is_ok();
    check(
        "sandbox",
        passed,
        format!(
            "backend={} strength={:?}{}{}",
            report.backend(),
            report.strength(),
            report
                .detail()
                .map(|detail| format!(" ({detail})"))
                .unwrap_or_default(),
            match &result {
                Ok(()) => String::new(),
                Err(error) => format!(" [fails required sandbox strength: {error}]"),
            },
        ),
    )
}

/// Run all health checks. The database is connected by the caller; this
/// function only reads from it.
pub async fn collect(config: &Config, database: &Database) -> Result<HealthReport, HealthError> {
    let mut checks = Vec::new();

    // Config: the fact that we are running means it parsed and validated.
    checks.push(check(
        "config",
        true,
        format!(
            "configuration loaded and validated (workspace {})",
            config.workspace_id()
        ),
    ));

    // Database: reachable, migrations applied (sqlx applies pending
    // migrations on connect, so the count is the applied set).
    let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(database.pool())
        .await
        .map_err(lumen_db::RepositoryError::Sqlx)?;
    checks.push(check(
        "database",
        applied > 0,
        format!("connected; {applied} migrations applied"),
    ));

    // Workspace bootstrap record.
    let bootstrapped: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workspaces WHERE id = ?")
        .bind(config.workspace_id().to_string())
        .fetch_one(database.pool())
        .await
        .map_err(lumen_db::RepositoryError::Sqlx)?;
    checks.push(check(
        "workspace",
        bootstrapped > 0,
        if bootstrapped > 0 {
            format!("workspace {} is bootstrapped", config.workspace_id())
        } else {
            format!(
                "workspace {} has no bootstrap record",
                config.workspace_id()
            )
        },
    ));

    // Audit chain: real cryptographic verification of the hash chain.
    match database.verify_audit_chain().await {
        Ok(()) => {
            let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
                .fetch_one(database.pool())
                .await
                .map_err(lumen_db::RepositoryError::Sqlx)?;
            checks.push(check(
                "audit-chain",
                true,
                format!("hash chain verified over {events} event(s)"),
            ));
        }
        Err(error) => {
            checks.push(check(
                "audit-chain",
                false,
                format!("chain verification failed: {error}"),
            ));
        }
    }

    // Sandbox backend: the real detected backend, not an assumption.
    checks.push(sandbox_check(config, &SystemSandbox::detect().report()));

    // Admission store: readable and listing works.
    match crate::plugin_admission::list(config) {
        Ok(records) => checks.push(check(
            "plugin-admissions",
            true,
            format!("admission store readable; {} record(s)", records.len()),
        )),
        Err(error) => checks.push(check(
            "plugin-admissions",
            false,
            format!("admission store unreadable: {error}"),
        )),
    }

    // Data directory: writable (probe file, removed afterwards).
    let probe = config
        .runtime
        .data_directory
        .join(format!(".health-probe-{}", uuid::Uuid::new_v4().simple()));
    match std::fs::write(&probe, b"health") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            checks.push(check(
                "data-directory",
                true,
                format!("writable: {}", config.runtime.data_directory.display()),
            ));
        }
        Err(error) => checks.push(check(
            "data-directory",
            false,
            format!(
                "not writable {}: {error}",
                config.runtime.data_directory.display()
            ),
        )),
    }

    // Model endpoint: best-effort TCP reachability with a short timeout.
    // Failure here is a warning, not unhealthiness: the runtime can serve
    // cached/local flows without the model endpoint.
    let endpoint = config.model.endpoint.clone();
    let (host, port) = parse_host_port(&endpoint);
    let reachable = match (host, port) {
        (Some(host), Some(port)) => tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect((host.as_str(), port)),
        )
        .await
        .is_ok_and(|result| result.is_ok()),
        _ => false,
    };
    checks.push(check(
        "model-endpoint",
        true,
        if reachable {
            format!("{endpoint} reachable")
        } else {
            format!("{endpoint} not reachable (warning only)")
        },
    ));

    Ok(HealthReport::new(checks))
}

fn parse_host_port(endpoint: &str) -> (Option<String>, Option<u16>) {
    let parsed = (|| {
        let url = url::Url::parse(endpoint).ok()?;
        let host = url.host_str()?.to_owned();
        let port = url.port_or_known_default()?;
        Some((host, port))
    })();
    match parsed {
        Some((host, port)) => (Some(host), Some(port)),
        None => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_marks_unhealthy_on_any_failure() {
        let report = HealthReport::new(vec![
            check("a", true, "ok".into()),
            check("b", false, "broken".into()),
        ]);
        assert!(!report.healthy);
        assert_eq!(report.checks.len(), 2);
        assert!(report.checks[0].passed);
        assert!(!report.checks[1].passed);
    }

    #[test]
    fn endpoint_parsing_handles_urls() {
        assert_eq!(
            parse_host_port("http://127.0.0.1:8080/v1/"),
            (Some("127.0.0.1".into()), Some(8080))
        );
        assert_eq!(parse_host_port("not a url"), (None, None));
    }

    fn test_config() -> Config {
        Config::parse(
            r#"[database]
path = "ignored.sqlite3"
[model]
endpoint = "http://127.0.0.1:8080/v1/"
model = "local-model"
[runtime]
data_directory = "/tmp/lumen-health-test"
[workspace]
id = "26db5a31-94f0-4e92-a9c9-4cdf19d71c31"
name = "Default"
path = "workspace"
[bootstrap_admin]
provider = "local"
subject = "operator"
"#,
        )
        .expect("test config parses")
    }

    #[test]
    fn sandbox_check_fails_when_strength_unavailable() {
        use lumen_integrations::sandbox::SandboxStrength;

        let config = test_config();
        // The reported scenario: the backend name looks fine
        // (`linux-bubblewrap`) but the detected strength is Unavailable
        // (no usable bubblewrap install). Health must fail here, exactly
        // like `serve` does.
        let report = SandboxReport::new(
            "linux-bubblewrap",
            SandboxStrength::Unavailable,
            Some("bwrap probe failed: setting up uid map: Permission denied".into()),
        );
        let check = sandbox_check(&config, &report);
        assert!(
            !check.passed,
            "health must fail when sandbox strength is unavailable"
        );
        assert!(check.detail.contains("linux-bubblewrap"));
        assert!(check.detail.contains("Unavailable"));
    }

    #[test]
    fn sandbox_check_passes_when_kernel_enforced() {
        use lumen_integrations::sandbox::SandboxStrength;

        let config = test_config();
        let report = SandboxReport::new("linux-bubblewrap", SandboxStrength::KernelEnforced, None);
        let check = sandbox_check(&config, &report);
        assert!(check.passed, "health must pass: {check:?}");
    }
}
