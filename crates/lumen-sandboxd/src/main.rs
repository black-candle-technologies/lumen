//! sandboxd: the strict-profile sandbox broker daemon.
//!
//! Startup order:
//! 1. Load and validate config (fails closed).
//! 2. Build driver (RunStore + FirecrackerBackend).
//! 3. Run crash reconciliation (reclaim orphans, sweep strays) BEFORE listening.
//! 4. Bind the API socket (0600) and serve.
//! 5. Graceful shutdown on SIGTERM/SIGINT.

use std::{path::PathBuf, sync::Arc, time::Duration};

use lumen_sandboxd::{
    api,
    cgroups::CGROUP_PARENT,
    config::DaemonConfig,
    driver::{Driver, FirecrackerBackend},
    error::SandboxdError,
    state::{HostSystemView, ReconcileConfig, RunStore, reconcile, retry_teardown_failed},
};

/// How often the background task retries `TeardownFailed` records while
/// the daemon serves. The per-record backoff (5s doubling to 5min) still
/// gates each attempt; this is just the poll cadence.
const TEARDOWN_RETRY_INTERVAL_SECS: u64 = 30;

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
    let rcfg = ReconcileConfig {
        chroot_base: &config.firecracker.chroot_base,
        firecracker_bin: &config.firecracker.binary,
        cgroup_parent: std::path::Path::new(CGROUP_PARENT),
        netns_prefix: &config.net.netns_prefix,
        tap_prefix: &config.net.tap_prefix,
    };
    let report = reconcile(driver.store(), &mut sys, &rcfg, |_uid| {
        // UID release is a no-op at startup; the Driver rebuilt its cursor
        // past live UIDs already.
    })?;
    if !report.is_clean() {
        eprintln!(
            "sandboxd: reconciled {} orphaned runs, {} pids, {} netns, {} taps, {} dirs, {} uids released; teardown_failed: {:?}",
            report.orphaned_runs.len(),
            report.killed_pids.len(),
            report.removed_netns.len(),
            report.removed_taps.len(),
            report.removed_dirs.len(),
            report.released_uids.len(),
            report.teardown_failed,
        );
    }

    // 3b. Periodic retry of TeardownFailed records WHILE serving. Startup
    //     reconciliation runs exactly once; a teardown that cannot be
    //     confirmed then would otherwise sit in TeardownFailed forever.
    //     This task retries ONLY due TeardownFailed records — never the
    //     full reconcile, which would misread live runs as orphaned.
    //     The blocking work runs in spawn_blocking, off the async runtime.
    {
        let state_dir = config.state.dir.clone();
        let netns_prefix = config.net.netns_prefix.clone();
        let tap_prefix = config.net.tap_prefix.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(TEARDOWN_RETRY_INTERVAL_SECS));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let dir = state_dir.clone();
                let nsp = netns_prefix.clone();
                let tpp = tap_prefix.clone();
                let res = tokio::task::spawn_blocking(move || {
                    let store = RunStore::open(&dir)?;
                    let mut sys = HostSystemView;
                    retry_teardown_failed(&store, &mut sys, &nsp, &tpp, |_uid| {
                        // Same no-op rationale as the startup pass: the
                        // Driver's UID cursor is monotonic within this
                        // daemon, so a "released" UID is never reused.
                    })
                })
                .await;
                match res {
                    Err(join_err) => {
                        eprintln!("sandboxd: teardown-retry task panicked: {join_err}")
                    }
                    Ok(Err(e)) => eprintln!("sandboxd: teardown retry failed: {e}"),
                    Ok(Ok(report)) => {
                        if !report.is_clean() {
                            eprintln!(
                                "sandboxd: teardown retry: {} netns, {} taps, {} dirs removed, {} uids released; still failing: {:?}",
                                report.removed_netns.len(),
                                report.removed_taps.len(),
                                report.removed_dirs.len(),
                                report.released_uids.len(),
                                report.teardown_failed,
                            );
                        }
                    }
                }
            }
        });
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
