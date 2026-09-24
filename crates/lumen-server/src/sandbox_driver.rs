//! [`SandboxRunner`] implemented over the Phase-2 [`Driver`].
//!
//! # The seam
//!
//! Phase 3 defines [`SandboxRunner`] (stage/commit) for the host tool
//! pipeline; Phase 2 provides [`Driver`] (prepare/start/stream). This module
//! is the mechanical adapter between them. It uses
//! [`Driver::stream_collect`] — never the frozen [`SandboxDriver::stream`]
//! — because `stream` takes `&mut dyn OutputSink` (no `Send` bound), so its
//! future is `!Send` and cannot run in the spawned tasks the host pipeline
//! uses. `stream_collect`'s future is `Send`.
//!
//! # Honest semantic gap: no true staging
//!
//! [`Driver`] v1 executes eagerly: `prepare` → `start` runs the command to
//! completion inside the microVM, and there is no overlayfs upper layer or
//! buffered-egress handle held back for a later commit. This adapter
//! therefore implements the [`SandboxRunner`] *shape* —
//! [`DriverSandboxRunner::stage`] runs the action and returns a
//! [`DriverStagedExecution`] whose [`commit`](StagedExecution::commit)
//! marks the execution committed — but it cannot provide the *semantics*
//! the trait documents ("no effects may become visible before commit").
//! Dropping a [`DriverStagedExecution`] without commit records an abort in
//! the adapter's bookkeeping, but the guest already ran: effects cannot be
//! un-executed.
//!
//! True stage/commit needs driver-level support (a prepare mode that holds
//! the run's effects — overlayfs upper, buffered egress — until an explicit
//! commit call). That is a Phase-2 design decision, marked
//! `TODO(INTEGRATION)` at the call site below; it is not invented here.
//!
//! # Envelope → spec mapping is injected
//!
//! Turning a host [`ActionEnvelope`] into a [`SandboxSpec`] (tool → guest
//! command, image digest, quotas, egress allowlist) is a policy decision
//! the coordinator owns. The adapter takes it as an injected
//! [`SpecBuilder`]; the adapter itself never invents a command mapping.

use std::sync::{Arc, Mutex};

use lumen_sandboxd::{SandboxDriver, contracts::SandboxSpec, driver::Driver};
use sha2::{Digest, Sha256};

use crate::{
    kernel_client::{ActionEnvelope, Obligation},
    tool_catalog::{
        ResourceUsage, SandboxError, SandboxFuture, SandboxOutcome, SandboxRunner, StagedExecution,
    },
};

/// Builds the [`SandboxSpec`] for one staged action. Injected by the host:
/// the tool → guest-command mapping is a coordinator-owned policy, not
/// something the adapter invents.
pub type SpecBuilder =
    dyn Fn(&ActionEnvelope, &str, &[Obligation]) -> Result<SandboxSpec, SandboxError> + Send + Sync;

/// [`SandboxRunner`] over the Phase-2 [`Driver`].
pub struct DriverSandboxRunner {
    driver: Arc<Driver>,
    spec_builder: Arc<SpecBuilder>,
}

impl DriverSandboxRunner {
    pub fn new(driver: Arc<Driver>, spec_builder: Arc<SpecBuilder>) -> Self {
        Self {
            driver,
            spec_builder,
        }
    }

    pub fn driver(&self) -> &Arc<Driver> {
        &self.driver
    }
}

/// A [`Driver`] run wrapped as a staged execution.
///
/// [`commit`](StagedExecution::commit) marks the execution committed;
/// dropping without commit records an abort. See the module docs for the
/// honest gap: the guest already ran during `stage`, so abort is
/// bookkeeping-only — true effect staging needs driver support
/// (`TODO(INTEGRATION)`).
pub struct DriverStagedExecution {
    outcome: SandboxOutcome,
    committed: Mutex<bool>,
    on_abort: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl DriverStagedExecution {
    /// Build from a finished driver run. Pure constructor, unit-tested
    /// without KVM.
    pub fn from_completed(
        chunks: &[lumen_sandboxd::contracts::OutputChunk],
        result: &lumen_sandboxd::contracts::SandboxResult,
        on_abort: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Self {
        let mut hasher = Sha256::new();
        let mut tail = Vec::new();
        for chunk in chunks {
            hasher.update(&chunk.bytes);
            tail.extend_from_slice(&chunk.bytes);
        }
        // Bounded tail for the host outcome; the digest covers everything.
        const TAIL_LIMIT: usize = 32 * 1024;
        let output_tail = if tail.len() > TAIL_LIMIT {
            String::from_utf8_lossy(&tail[tail.len() - TAIL_LIMIT..]).into_owned()
        } else {
            String::from_utf8_lossy(&tail).into_owned()
        };
        let export_digest = result.export_manifest.as_ref().map(|m| {
            format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(m).unwrap_or_default())
            )
        });
        Self {
            outcome: SandboxOutcome {
                exit_code: result.exit_code,
                output_tail,
                output_digest: format!("{:x}", hasher.finalize()),
                usage: ResourceUsage {
                    cpu_ms: result.usage.wall_time_ms,
                    memory_bytes_max: result.usage.peak_memory_mib * 1024 * 1024,
                    egress_bytes: result.usage.egress_bytes,
                },
                export_digest,
            },
            committed: Mutex::new(false),
            on_abort,
        }
    }

    pub fn was_committed(&self) -> bool {
        *self.committed.lock().unwrap()
    }
}

impl StagedExecution for DriverStagedExecution {
    fn outcome(&self) -> &SandboxOutcome {
        &self.outcome
    }

    fn commit(self: Box<Self>) -> SandboxFuture<'static, ()> {
        Box::pin(async move {
            *self.committed.lock().unwrap() = true;
            // TODO(INTEGRATION): the Driver executed eagerly during stage;
            // a true commit would merge the run's held-back effects
            // (overlayfs upper layer, buffered egress) here. That needs
            // driver-level staging support — not invented in this adapter.
            Ok(())
        })
    }
}

impl Drop for DriverStagedExecution {
    fn drop(&mut self) {
        if !*self.committed.lock().unwrap()
            && let Some(on_abort) = self.on_abort.take()
        {
            on_abort();
        }
    }
}

impl SandboxRunner for DriverSandboxRunner {
    fn stage<'a>(
        &'a self,
        envelope: &'a ActionEnvelope,
        lease_id: &'a str,
        obligations: &'a [Obligation],
    ) -> SandboxFuture<'a, Box<dyn StagedExecution>> {
        let driver = Arc::clone(&self.driver);
        let spec_builder = Arc::clone(&self.spec_builder);
        Box::pin(async move {
            let spec = spec_builder(envelope, lease_id, obligations)?;
            let map_err =
                |e: lumen_sandboxd::SandboxError| SandboxError::Failed(format!("driver: {e}"));
            let handle = driver.prepare(&spec).await.map_err(map_err)?;
            driver.start(&handle).await.map_err(map_err)?;
            // `stream_collect`, not the frozen `stream`: its future is
            // `Send`, so this stage future can run in spawned tasks.
            let (chunks, _stats) = driver.stream_collect(&handle).await.map_err(map_err)?;
            let result = driver.run_result(&handle).map_err(map_err)?;
            Ok(Box::new(DriverStagedExecution::from_completed(
                &chunks, &result, None,
            )) as Box<dyn StagedExecution>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lumen_sandboxd::contracts::{ExportManifest, OutputChunk, SandboxResult, SandboxUsage};

    fn sample_result() -> SandboxResult {
        SandboxResult {
            exit_code: 3,
            timed_out: false,
            output: "hello".to_string(),
            output_truncated: false,
            usage: SandboxUsage {
                wall_time_ms: 1500,
                peak_memory_mib: 64,
                egress_bytes: 128,
                ingress_bytes: 64,
            },
            export_manifest: Some(ExportManifest { changed: vec![] }),
        }
    }

    #[test]
    fn outcome_conversion_is_lossless_on_digest() {
        let chunks = vec![
            OutputChunk {
                stream: "stdout".to_string(),
                bytes: b"hel".to_vec(),
            },
            OutputChunk {
                stream: "stdout".to_string(),
                bytes: b"lo".to_vec(),
            },
        ];
        let exec = DriverStagedExecution::from_completed(&chunks, &sample_result(), None);
        let outcome = exec.outcome();
        assert_eq!(outcome.exit_code, 3);
        // Digest covers the concatenated chunks, not just the tail.
        let expected = format!("{:x}", Sha256::digest(b"hello"));
        assert_eq!(outcome.output_digest, expected);
        assert_eq!(outcome.output_tail, "hello");
        assert_eq!(outcome.usage.cpu_ms, 1500);
        assert_eq!(outcome.usage.memory_bytes_max, 64 * 1024 * 1024);
        assert_eq!(outcome.usage.egress_bytes, 128);
        assert!(outcome.export_digest.is_some());
    }

    #[test]
    fn commit_marks_committed_and_drop_without_commit_aborts() {
        let aborted = Arc::new(Mutex::new(0u32));
        let on_abort = {
            let aborted = Arc::clone(&aborted);
            Arc::new(move || {
                *aborted.lock().unwrap() += 1;
            })
        };
        let chunks = vec![OutputChunk {
            stream: "stdout".to_string(),
            bytes: b"x".to_vec(),
        }];
        // Drop without commit -> abort recorded.
        drop(DriverStagedExecution::from_completed(
            &chunks,
            &sample_result(),
            Some(on_abort.clone()),
        ));
        assert_eq!(*aborted.lock().unwrap(), 1);

        // Commit -> no abort on drop.
        let exec = DriverStagedExecution::from_completed(&chunks, &sample_result(), Some(on_abort));
        let exec: Box<dyn StagedExecution> = Box::new(exec);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(exec.commit()).unwrap();
        assert_eq!(*aborted.lock().unwrap(), 1);
    }
}
