//! sandboxd: the strict-profile sandbox broker daemon.
//!
//! Startup order:
//! 1. Load and validate config (fails closed).
//! 2. Build driver (RunStore + FirecrackerBackend).
//! 3. Run crash reconciliation (reclaim orphans, sweep strays) BEFORE listening.
//! 4. Bind the API socket (0600) and serve.
//! 5. Graceful shutdown on SIGTERM/SIGINT.

use std::{path::PathBuf, sync::Arc};

use lumen_sandboxd::{
    api,
    config::DaemonConfig,
    driver::{Driver, FirecrackerBackend},
    error::SandboxdError,
    state::{HostSystemView, RunStore, reconcile},
};

#[tokio::main]
async fn main() -> Result<(), SandboxdError> {
    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/lumen/sandboxd.toml"));

    // 1. Load and validate config.
    let config = DaemonConfig::load(&config_path)?;
    config.validate()?;
    eprintln!("sandboxd: config loaded from {}", config_path.display());

    // 2. Build the driver.
    let store = RunStore::open(&config.state.dir)?;
    let backend = Arc::new(FirecrackerBackend);
    let driver = Driver::new(config.clone(), store, backend)?;
    eprintln!("sandboxd: driver initialized");

    // 3. Reconciliation BEFORE listening: a previous daemon may have died
    //    holding runs, netns, TAPs, or jailer chroots. Reclaim them now so we
    //    never serve with stale state.
    let mut sys = HostSystemView;
    let report = reconcile(
        driver.store(),
        &mut sys,
        &config.firecracker.chroot_base,
        &config.net.netns_prefix,
        &config.net.tap_prefix,
        |_uid| {
            // UID release is a no-op at startup; the Driver rebuilt its cursor
            // past live UIDs already.
        },
    )?;
    if !report.orphaned_runs.is_empty()
        || !report.killed_pids.is_empty()
        || !report.removed_netns.is_empty()
    {
        eprintln!(
            "sandboxd: reconciled {} orphaned runs, {} pids, {} netns, {} taps, {} dirs",
            report.orphaned_runs.len(),
            report.killed_pids.len(),
            report.removed_netns.len(),
            report.removed_taps.len(),
            report.removed_dirs.len(),
        );
    }

    // 4. Serve the API with graceful shutdown.
    let driver = Arc::new(driver);
    let api_config = config.api.clone();
    let serve_fut = api::serve(&api_config, driver);

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate())
            .map_err(|e| SandboxdError::Host(format!("signal setup: {e}")))?;
        let mut sigint = signal(SignalKind::interrupt())
            .map_err(|e| SandboxdError::Host(format!("signal setup: {e}")))?;

        tokio::select! {
            r = serve_fut => r,
            _ = sigterm.recv() => {
                eprintln!("sandboxd: SIGTERM, shutting down");
                let _ = std::fs::remove_file(&api_config.socket);
                Ok(())
            }
            _ = sigint.recv() => {
                eprintln!("sandboxd: SIGINT, shutting down");
                let _ = std::fs::remove_file(&api_config.socket);
                Ok(())
            }
        }
    }

    #[cfg(not(unix))]
    {
        serve_fut.await
    }
}
