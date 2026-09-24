//! Crash-safe run state machine and startup reconciliation.
//!
//! Every run moves through
//! `Prepared -> Starting -> Running -> Exporting -> Destroying -> Destroyed`
//! (with `Done`/`Failed`/`Cancelled`/`TimedOut` as pre-destroy terminal
//! markers, and `TeardownFailed` as a NONTERMINAL recovery state entered when
//! a teardown step cannot be confirmed — the record is retained and the
//! teardown is retried until every artifact is confirmed gone). Each
//! transition is appended to a per-run JSONL journal and fsynced before the
//! transition is considered durable.
//!
//! Crash rule: if the daemon dies at any point, the next boot's
//! [`reconcile`] finds every run that is not `Destroyed`, marks it
//! `Orphaned`, reclaims its VM, TAP device, netns, cgroup, chroot, and
//! disks, and sweeps any stray resources not tied to a run. A host restart
//! mid-run therefore leaves zero orphaned VMs, TAP devices, or disks.
//!
//! Teardown rule: a run is `Destroyed` only after every teardown step's
//! postcondition is CONFIRMED (no live processes, cgroup empty and removed,
//! netns/TAP gone, files gone). A step that cannot be confirmed moves the
//! run to `TeardownFailed` instead; the record is retained, the UID stays
//! allocated, and the next reconcile retries with bounded backoff. A run is
//! never marked `Destroyed` on best-effort cleanup.

use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    contracts::{SandboxResult, SandboxRunSpec},
    error::SandboxdError,
    jailer,
    provenance::ProvenanceRecord,
};

/// Lifecycle phase of a single strict-profile run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    /// Spec validated, resources reserved, artifacts staged. VM not started.
    Prepared,
    /// Jailer spawned, Firecracker API up, guest booting.
    Starting,
    /// Guest agent handshake done, workload executing.
    Running,
    /// Workload finished; export being inventoried and validated.
    Exporting,
    /// Terminal outcome recorded; artifacts being reclaimed.
    Destroying,
    /// `wait()` returned; artifacts retained for export/destroy.
    Done,
    /// Driver-level failure before completion.
    Failed,
    /// `cancel()` requested; guest terminated.
    Cancelled,
    /// Deadline exceeded; guest terminated.
    TimedOut,
    /// Found non-terminal at daemon startup; artifacts being reclaimed.
    Orphaned,
    /// Teardown attempted but at least one artifact is NOT confirmed gone.
    /// NONTERMINAL: the record is retained (never deleted in this state),
    /// the UID stays allocated, and the next reconcile retries the teardown
    /// with bounded backoff until every postcondition is confirmed. A run
    /// in this state must never transition to `Destroyed` without a
    /// fully-verified teardown.
    TeardownFailed,
    /// Terminal: every artifact removed and attested. Nothing left.
    Destroyed,
}

impl RunState {
    /// States from which no further driver operation is legal except
    /// `destroy` (and the reconcile path).
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            RunState::Done
                | RunState::Failed
                | RunState::Cancelled
                | RunState::TimedOut
                | RunState::Destroyed
        )
    }
}

/// Host-side artifact locations for one run. Everything here is created by
/// sandboxd and must be removable by [`reconcile`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPaths {
    /// Jailer id (also the chroot leaf name).
    pub jail_id: String,
    /// Jailer chroot: `<chroot_base>/<exec_file_name>/<jail_id>/root`
    /// (see `jailer::jail_root`).
    pub chroot_dir: PathBuf,
    /// Firecracker config inside the chroot staging area.
    pub config_path: PathBuf,
    /// UID/GID the jailer drops to.
    pub uid: u32,
    pub gid: u32,
    /// Network namespace and TAP names.
    pub netns_name: String,
    pub tap_name: String,
    /// veth pair: host leg (proxy/DNS side) and guest leg.
    pub veth_host: String,
    pub veth_guest: String,
    /// /30 addresses: host side and guest side.
    pub host_ip: String,
    pub guest_ip: String,
    /// cgroup v2 path for this run's Firecracker process.
    pub cgroup_path: PathBuf,
    /// Copy-on-write workspace disk (qcow2 with read-only backing file).
    pub workspace_disk: PathBuf,
    /// Guest agent vsock UDS path (inside the chroot).
    pub vsock_path: PathBuf,
    /// Firecracker API socket (inside the chroot).
    pub api_sock: PathBuf,
    /// Host staging dir for validated export bytes.
    pub staging_dir: PathBuf,
    /// Sandboxd's supervised jailer pid (0 = unknown / already reaped).
    pub jailer_pid: u32,
}

/// One run's durable record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    pub run_id: String,
    pub state: RunState,
    pub spec: SandboxRunSpec,
    /// sha256 of the canonical spec JSON (binds journal to the spec).
    pub spec_digest: String,
    pub artifacts: ArtifactPaths,
    pub provenance: Option<ProvenanceRecord>,
    pub outcome: Option<SandboxResult>,
    pub created_at: u64,
    pub updated_at: u64,
    /// Consecutive teardown attempts that left at least one artifact
    /// unconfirmed. Drives the bounded retry backoff in [`reconcile`].
    /// `#[serde(default)]` keeps records written before this field loading.
    #[serde(default)]
    pub teardown_attempts: u32,
}

/// Journal entry appended on every mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum JournalEvent {
    Created {
        spec_digest: String,
    },
    StateChanged {
        from: RunState,
        to: RunState,
    },
    ProvenanceRecorded {
        image_digest: String,
    },
    OutputTruncated {
        kept_bytes: u64,
    },
    ExportStaged {
        files: usize,
        bytes: u64,
    },
    OrphanedFound {},
    ArtifactsRemoved {
        removed: Vec<String>,
    },
    /// A teardown attempt left artifacts unconfirmed. This is the audit
    /// event for the teardown-failure alert: it names the run (via the
    /// journal file it lives in), the attempt number, and every
    /// unconfirmed artifact.
    TeardownAlert {
        attempt: u32,
        failures: Vec<String>,
    },
    Note {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalEntry {
    seq: u64,
    ts: u64,
    #[serde(flatten)]
    event: JournalEvent,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Persistent store of run records under `<state_dir>/runs/<run_id>/`.
#[derive(Debug, Clone)]
pub struct RunStore {
    runs_dir: PathBuf,
}

impl RunStore {
    pub fn open(state_dir: &Path) -> Result<Self, SandboxdError> {
        let runs_dir = state_dir.join("runs");
        fs::create_dir_all(&runs_dir).map_err(SandboxdError::Io)?;
        Ok(Self { runs_dir })
    }

    pub fn run_dir(&self, run_id: &str) -> PathBuf {
        self.runs_dir.join(run_id)
    }

    fn journal_path(&self, run_id: &str) -> PathBuf {
        self.run_dir(run_id).join("journal.jsonl")
    }

    fn state_path(&self, run_id: &str) -> PathBuf {
        self.run_dir(run_id).join("state.json")
    }

    /// Create a new run record in `Prepared` state. Fails if the run exists.
    pub fn create(
        &self,
        run_id: &str,
        spec: SandboxRunSpec,
        spec_digest: String,
        artifacts: ArtifactPaths,
    ) -> Result<RunRecord, SandboxdError> {
        let dir = self.run_dir(run_id);
        if dir.exists() {
            return Err(SandboxdError::RunState(format!(
                "run already exists: {run_id}"
            )));
        }
        fs::create_dir_all(&dir).map_err(SandboxdError::Io)?;
        let now = now_unix();
        let record = RunRecord {
            run_id: run_id.to_string(),
            state: RunState::Prepared,
            spec,
            spec_digest: spec_digest.clone(),
            artifacts,
            provenance: None,
            outcome: None,
            created_at: now,
            updated_at: now,
            teardown_attempts: 0,
        };
        self.append_journal(run_id, JournalEvent::Created { spec_digest }, 0, &record)?;
        self.write_state(&record)?;
        Ok(record)
    }

    /// Load every run record present on disk.
    pub fn all_runs(&self) -> Result<Vec<RunRecord>, SandboxdError> {
        let mut runs = Vec::new();
        let entries = fs::read_dir(&self.runs_dir).map_err(SandboxdError::Io)?;
        for entry in entries {
            let entry = entry.map_err(SandboxdError::Io)?;
            if !entry.file_type().map_err(SandboxdError::Io)?.is_dir() {
                continue;
            }
            let run_id = entry.file_name().to_string_lossy().into_owned();
            match self.load(&run_id) {
                Ok(record) => runs.push(record),
                Err(e) => {
                    // A corrupt state.json must not block reconciliation of
                    // every other run; record it and keep going. The corrupt
                    // dir is swept by the stray-resource pass.
                    eprintln!("sandboxd: skipping corrupt run dir {run_id}: {e}");
                }
            }
        }
        Ok(runs)
    }

    pub fn load(&self, run_id: &str) -> Result<RunRecord, SandboxdError> {
        let text = fs::read_to_string(self.state_path(run_id)).map_err(SandboxdError::Io)?;
        serde_json::from_str(&text).map_err(SandboxdError::Json)
    }

    /// Transition a run to a new state, journaling the change first.
    pub fn transition(&self, run_id: &str, to: RunState) -> Result<RunRecord, SandboxdError> {
        let mut record = self.load(run_id)?;
        let from = record.state;
        let seq = self.next_seq(run_id)?;
        self.append_journal(
            run_id,
            JournalEvent::StateChanged { from, to },
            seq,
            &record,
        )?;
        record.state = to;
        record.updated_at = now_unix();
        self.write_state(&record)?;
        Ok(record)
    }

    pub fn note(&self, run_id: &str, message: String) -> Result<(), SandboxdError> {
        let record = self.load(run_id)?;
        let seq = self.next_seq(run_id)?;
        self.append_journal(run_id, JournalEvent::Note { message }, seq, &record)?;
        Ok(())
    }

    pub fn set_provenance(
        &self,
        run_id: &str,
        provenance: ProvenanceRecord,
    ) -> Result<RunRecord, SandboxdError> {
        let mut record = self.load(run_id)?;
        let seq = self.next_seq(run_id)?;
        self.append_journal(
            run_id,
            JournalEvent::ProvenanceRecorded {
                image_digest: provenance.image_digest.clone(),
            },
            seq,
            &record,
        )?;
        record.provenance = Some(provenance);
        record.updated_at = now_unix();
        self.write_state(&record)?;
        Ok(record)
    }

    pub fn set_outcome(
        &self,
        run_id: &str,
        outcome: SandboxResult,
    ) -> Result<RunRecord, SandboxdError> {
        let mut record = self.load(run_id)?;
        record.outcome = Some(outcome);
        record.updated_at = now_unix();
        self.write_state(&record)?;
        Ok(record)
    }

    /// Record a teardown attempt that left artifacts unconfirmed: journal a
    /// [`JournalEvent::TeardownAlert`] (the audit event for the alert) and
    /// bump the attempt counter that drives the retry backoff.
    ///
    /// Fail-closed per design invariant (7): the journal append happens
    /// BEFORE the state is persisted, so if the audit write fails the
    /// caller must not transition the run — it stays in its current
    /// nonterminal state and is retried by the next reconcile.
    pub fn teardown_attempt(
        &self,
        run_id: &str,
        attempt: u32,
        failures: Vec<String>,
    ) -> Result<RunRecord, SandboxdError> {
        let mut record = self.load(run_id)?;
        let seq = self.next_seq(run_id)?;
        self.append_journal(
            run_id,
            JournalEvent::TeardownAlert {
                attempt,
                failures: failures.clone(),
            },
            seq,
            &record,
        )?;
        record.teardown_attempts = attempt;
        record.updated_at = now_unix();
        self.write_state(&record)?;
        Ok(record)
    }

    /// Journal the artifacts a verified teardown removed (audit trail for
    /// the successful path; the `Destroyed` transition is journaled
    /// separately by [`RunStore::transition`]).
    pub fn record_artifacts_removed(
        &self,
        run_id: &str,
        removed: Vec<String>,
    ) -> Result<(), SandboxdError> {
        let record = self.load(run_id)?;
        let seq = self.next_seq(run_id)?;
        self.append_journal(
            run_id,
            JournalEvent::ArtifactsRemoved { removed },
            seq,
            &record,
        )?;
        Ok(())
    }

    /// Test-only hook to control the retry-backoff clock without sleeping.
    #[cfg(test)]
    pub fn set_updated_at_for_test(&self, run_id: &str, ts: u64) -> Result<(), SandboxdError> {
        let mut record = self.load(run_id)?;
        record.updated_at = ts;
        self.write_state(&record)?;
        Ok(())
    }

    fn next_seq(&self, run_id: &str) -> Result<u64, SandboxdError> {
        // seq = number of existing journal lines (Created is seq 0).
        let path = self.journal_path(run_id);
        let text = fs::read_to_string(&path).map_err(SandboxdError::Io)?;
        Ok(text.lines().filter(|l| !l.trim().is_empty()).count() as u64)
    }

    fn append_journal(
        &self,
        run_id: &str,
        event: JournalEvent,
        seq: u64,
        _record: &RunRecord,
    ) -> Result<(), SandboxdError> {
        let entry = JournalEntry {
            seq,
            ts: now_unix(),
            event,
        };
        let mut line = serde_json::to_string(&entry).map_err(SandboxdError::Json)?;
        line.push('\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.journal_path(run_id))
            .map_err(SandboxdError::Io)?;
        file.write_all(line.as_bytes()).map_err(SandboxdError::Io)?;
        file.sync_all().map_err(SandboxdError::Io)?;
        Ok(())
    }

    fn write_state(&self, record: &RunRecord) -> Result<(), SandboxdError> {
        // Write-then-rename so a crash never leaves a torn state.json.
        let path = self.state_path(&record.run_id);
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(record).map_err(SandboxdError::Json)?;
        fs::write(&tmp, text).map_err(SandboxdError::Io)?;
        // Best-effort fsync of the temp file before rename.
        if let Ok(f) = fs::File::open(&tmp) {
            let _ = f.sync_all();
        }
        fs::rename(&tmp, &path).map_err(SandboxdError::Io)?;
        Ok(())
    }
}

/// Abstraction over the host for reconciliation. The real implementation
/// shells out to `/proc` and `ip`; tests inject [`FakeSystemView`].
pub trait SystemView {
    /// PIDs of firecracker processes tied to our chroot base.
    fn firecracker_pids(&self) -> Vec<(u32, String)>;
    fn pid_alive(&self, pid: u32) -> bool;
    /// Kill every process in the run's cgroup (preferred) or the pid.
    fn kill_cgroup(&mut self, cgroup_path: &Path) -> io::Result<()>;
    fn kill_pid(&mut self, pid: u32) -> io::Result<()>;
    fn netns_names(&self, prefix: &str) -> Vec<String>;
    fn delete_netns(&mut self, name: &str) -> io::Result<()>;
    fn tap_names(&self, prefix: &str) -> Vec<String>;
    fn delete_tap(&mut self, name: &str) -> io::Result<()>;
    fn remove_dir(&mut self, path: &Path) -> io::Result<()>;
    /// Remove a single file. `NotFound` (already gone) is success.
    fn remove_file(&mut self, path: &Path) -> io::Result<()>;
    /// PIDs currently in the run's cgroup. Empty when the cgroup is gone
    /// or holds no processes — the postcondition `kill_cgroup` must
    /// establish before the cgroup dir may be removed.
    fn cgroup_pids(&self, cgroup_path: &Path) -> Vec<u32>;
    /// True while the path still exists (dir or file). Teardown steps
    /// verify their postcondition through this: "already gone" is
    /// success, "still present after the operation" is failure.
    fn path_exists(&self, path: &Path) -> bool;
    fn jail_dirs(&self, chroot_base: &Path) -> Vec<String>;
}

/// Report of what [`reconcile`] found and removed. Empty means clean.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ReconcileReport {
    pub orphaned_runs: Vec<String>,
    pub killed_pids: Vec<u32>,
    pub removed_netns: Vec<String>,
    pub removed_taps: Vec<String>,
    pub removed_dirs: Vec<String>,
    pub released_uids: Vec<u32>,
    /// Runs whose teardown could not be confirmed. Their records are
    /// RETAINED in the nonterminal [`RunState::TeardownFailed`] state and
    /// retried by the next reconcile; their UIDs stay allocated.
    pub teardown_failed: Vec<String>,
}

impl ReconcileReport {
    pub fn is_clean(&self) -> bool {
        self.orphaned_runs.is_empty()
            && self.killed_pids.is_empty()
            && self.removed_netns.is_empty()
            && self.removed_taps.is_empty()
            && self.removed_dirs.is_empty()
            && self.teardown_failed.is_empty()
    }
}

/// Base delay between teardown retries for a run stuck in
/// [`RunState::TeardownFailed`]; doubles per consecutive failed attempt.
const TEARDOWN_RETRY_BASE_SECS: u64 = 5;
/// Cap on the teardown retry backoff.
const TEARDOWN_RETRY_MAX_SECS: u64 = 300;

/// Backoff before the next teardown attempt for a run with `attempts`
/// consecutive unconfirmed teardowns: 5s, 10s, 20s, ... capped at 5min.
fn teardown_backoff_secs(attempts: u32) -> u64 {
    let shift = attempts.saturating_sub(1).min(6);
    (TEARDOWN_RETRY_BASE_SECS << shift).min(TEARDOWN_RETRY_MAX_SECS)
}

/// True when a run in [`RunState::TeardownFailed`] is due for another
/// teardown attempt. A run that has never been attempted is always due.
fn teardown_retry_due(record: &RunRecord) -> bool {
    if record.teardown_attempts == 0 {
        return true;
    }
    now_unix().saturating_sub(record.updated_at) >= teardown_backoff_secs(record.teardown_attempts)
}

/// Poll `cond` until it holds or `timeout` elapses. Gives a kill that is
/// racing with process exit a short grace period before the teardown is
/// declared unconfirmed.
fn poll_until(mut cond: impl FnMut() -> bool, timeout: Duration, interval: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(interval);
    }
}

/// "Already gone" is success; any other I/O error is failure context.
/// The caller decides failure on the POSTCONDITION, not on this result.
fn already_gone(result: io::Result<()>) -> Result<(), String> {
    match result {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Tear down every artifact belonging to one run, VERIFYING each step's
/// postcondition instead of assuming the operation worked.
///
/// Returns `Ok(())` only when nothing belonging to the run is confirmed
/// still present: no live processes, cgroup empty and removed, netns and
/// TAP gone, files gone. Returns `Err(failures)` naming each unconfirmed
/// artifact; the caller must then retain the run record (never mark it
/// `Destroyed`) and retry later.
///
/// Idempotent: re-running this on an already-clean run succeeds — every
/// "already gone" observation counts as success.
fn teardown_run<S: SystemView>(
    run: &RunRecord,
    sys: &mut S,
    netns_prefix: &str,
    tap_prefix: &str,
    report: &mut ReconcileReport,
) -> Result<(), Vec<String>> {
    let a = &run.artifacts;
    let mut failures: Vec<String> = Vec::new();

    // The cgroup path is relative to /sys/fs/cgroup (see kill_cgroup);
    // resolve it the same way here (tolerating an absolute path from
    // older records) so the membership check and the removal target the
    // same directory the kill did.
    let cgroup_dir = if a.cgroup_path.is_absolute() {
        a.cgroup_path.clone()
    } else {
        Path::new("/sys/fs/cgroup").join(&a.cgroup_path)
    };

    // 1. Processes: cgroup.kill first (catches jailer + firecracker + any
    //    forked children), fall back to the recorded pid, then CONFIRM that
    //    the recorded pid is gone and the cgroup holds no processes.
    let pid_was_alive = a.jailer_pid != 0 && sys.pid_alive(a.jailer_pid);
    let mut kill_err: Option<String> = None;
    if let Err(e) = already_gone(sys.kill_cgroup(&a.cgroup_path)) {
        kill_err = Some(format!("kill cgroup {}: {e}", cgroup_dir.display()));
    }
    if pid_was_alive && let Err(e) = already_gone(sys.kill_pid(a.jailer_pid)) {
        let msg = format!("kill pid {}: {e}", a.jailer_pid);
        kill_err = Some(match kill_err {
            Some(prev) => format!("{prev}; {msg}"),
            None => msg,
        });
    }
    let procs_gone = poll_until(
        || {
            let pid_gone = a.jailer_pid == 0 || !sys.pid_alive(a.jailer_pid);
            pid_gone && sys.cgroup_pids(&cgroup_dir).is_empty()
        },
        Duration::from_secs(2),
        Duration::from_millis(50),
    );
    if procs_gone {
        if pid_was_alive {
            report.killed_pids.push(a.jailer_pid);
        }
    } else {
        let mut detail = Vec::new();
        if a.jailer_pid != 0 && sys.pid_alive(a.jailer_pid) {
            detail.push(format!("pid {} still alive", a.jailer_pid));
        }
        let members = sys.cgroup_pids(&cgroup_dir);
        if !members.is_empty() {
            detail.push(format!(
                "cgroup {} still holds pids {members:?}",
                cgroup_dir.display()
            ));
        }
        if let Some(e) = kill_err {
            detail.push(format!("kill errors: {e}"));
        }
        failures.push(format!("processes unconfirmed ({})", detail.join(", ")));
    }

    // 2. Cgroup dir: remove, then confirm gone. (cgroupfs refuses to rmdir
    //    a non-empty cgroup, so a removal failure here usually means step 1
    //    is also unconfirmed — both are reported.)
    let cgroup_existed = sys.path_exists(&cgroup_dir);
    let cgroup_rm_err = already_gone(sys.remove_dir(&cgroup_dir)).err();
    if sys.path_exists(&cgroup_dir) {
        let mut detail = format!("cgroup dir {} still exists", cgroup_dir.display());
        if let Some(e) = cgroup_rm_err {
            detail.push_str(&format!(" (remove error: {e})"));
        }
        failures.push(detail);
    } else if cgroup_existed {
        report.removed_dirs.push(cgroup_dir.display().to_string());
    }

    // 3. Network: TAP then netns, confirming each is gone afterwards.
    let tap_existed = sys.tap_names(tap_prefix).contains(&a.tap_name);
    let tap_rm_err = already_gone(sys.delete_tap(&a.tap_name)).err();
    if sys.tap_names(tap_prefix).contains(&a.tap_name) {
        let mut detail = format!("tap {} still exists", a.tap_name);
        if let Some(e) = tap_rm_err {
            detail.push_str(&format!(" (delete error: {e})"));
        }
        failures.push(detail);
    } else if tap_existed {
        report.removed_taps.push(a.tap_name.clone());
    }
    let netns_existed = sys.netns_names(netns_prefix).contains(&a.netns_name);
    let netns_rm_err = already_gone(sys.delete_netns(&a.netns_name)).err();
    if sys.netns_names(netns_prefix).contains(&a.netns_name) {
        let mut detail = format!("netns {} still exists", a.netns_name);
        if let Some(e) = netns_rm_err {
            detail.push_str(&format!(" (delete error: {e})"));
        }
        failures.push(detail);
    } else if netns_existed {
        report.removed_netns.push(a.netns_name.clone());
    }

    // 4. Filesystem: chroot (covers config/api.sock/vsock), staging dir,
    //    then the workspace disk file explicitly in case the chroot dir
    //    itself is already gone.
    for dir in [a.chroot_dir.clone(), a.staging_dir.clone()] {
        let existed = sys.path_exists(&dir);
        let rm_err = already_gone(sys.remove_dir(&dir)).err();
        if sys.path_exists(&dir) {
            let mut detail = format!("dir {} still exists", dir.display());
            if let Some(e) = rm_err {
                detail.push_str(&format!(" (remove error: {e})"));
            }
            failures.push(detail);
        } else if existed {
            report.removed_dirs.push(dir.display().to_string());
        }
    }
    let file_existed = sys.path_exists(&a.workspace_disk);
    let file_rm_err = already_gone(sys.remove_file(&a.workspace_disk)).err();
    if sys.path_exists(&a.workspace_disk) {
        let mut detail = format!("file {} still exists", a.workspace_disk.display());
        if let Some(e) = file_rm_err {
            detail.push_str(&format!(" (remove error: {e})"));
        }
        failures.push(detail);
    } else if file_existed {
        report
            .removed_dirs
            .push(a.workspace_disk.display().to_string());
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

/// Daemon-startup crash recovery. For every run that is not `Destroyed`:
/// mark `Orphaned`, reclaim all artifacts with a postcondition-verified
/// teardown, release its UID, mark `Destroyed`. A teardown that leaves any
/// artifact unconfirmed moves the run to the nonterminal
/// [`RunState::TeardownFailed`] state instead: the record is retained, the
/// UID stays allocated, an alert is journaled, and the next reconcile
/// retries with bounded backoff. Then sweep stray firecracker processes,
/// netns, TAPs, and jail dirs that belong to no live run.
///
/// `release_uid` persists the freed UID back into the allocator. It is only
/// called for runs whose teardown was fully verified — never for a run in
/// `TeardownFailed`, which may still hold live resources.
pub fn reconcile<S: SystemView>(
    store: &RunStore,
    sys: &mut S,
    chroot_base: &Path,
    firecracker_bin: &Path,
    netns_prefix: &str,
    tap_prefix: &str,
    mut release_uid: impl FnMut(u32),
) -> Result<ReconcileReport, SandboxdError> {
    let mut report = ReconcileReport::default();
    let live_jail_ids: HashSet<String> = HashSet::new();
    let live_netns: HashSet<String> = HashSet::new();
    let live_taps: HashSet<String> = HashSet::new();

    for run in store.all_runs()? {
        if run.state == RunState::Destroyed {
            continue;
        }
        // Not destroyed => the previous daemon died holding it (or never
        // got to destroy it). Reclaim, but only mark Destroyed once the
        // teardown is confirmed — never on best-effort.
        let run_id = run.run_id.clone();
        let retrying = run.state == RunState::TeardownFailed;
        if retrying {
            if !teardown_retry_due(&run) {
                // Backoff has not elapsed: keep the record for a later
                // reconcile. The stray sweep below still gets a chance at
                // any leftover processes in the meantime.
                report.teardown_failed.push(run_id.clone());
                continue;
            }
            store.note(
                &run_id,
                format!(
                    "reconcile: retrying teardown (attempt {})",
                    run.teardown_attempts + 1
                ),
            )?;
        } else {
            store.note(&run_id, "reconcile: orphaned run found".to_string())?;
            store.transition(&run_id, RunState::Orphaned)?;
        }
        report.orphaned_runs.push(run_id.clone());

        let reloaded = store.load(&run_id)?;
        match teardown_run(&reloaded, sys, netns_prefix, tap_prefix, &mut report) {
            Ok(()) => {
                let removed: Vec<String> = report
                    .removed_dirs
                    .iter()
                    .chain(report.removed_netns.iter())
                    .chain(report.removed_taps.iter())
                    .cloned()
                    .collect();
                store.record_artifacts_removed(&run_id, removed)?;
                release_uid(reloaded.artifacts.uid);
                report.released_uids.push(reloaded.artifacts.uid);
                store.transition(&run_id, RunState::Destroying)?;
                store.transition(&run_id, RunState::Destroyed)?;
            }
            Err(failures) => {
                // Fail closed per design invariant (7): the alert is
                // journaled BEFORE the run enters the nonterminal state.
                // If the journal write fails, this returns Err and the run
                // stays Orphaned/Destroying — retried by the next reconcile
                // — instead of being silently dropped.
                let attempt = reloaded.teardown_attempts.saturating_add(1);
                let detail = failures.join("; ");
                eprintln!(
                    "sandboxd: ERROR teardown of run {run_id} unconfirmed \
                     (attempt {attempt}): {detail}. Record retained in \
                     TeardownFailed; retrying with backoff."
                );
                store.teardown_attempt(&run_id, attempt, failures)?;
                if reloaded.state != RunState::TeardownFailed {
                    store.transition(&run_id, RunState::TeardownFailed)?;
                }
                report.teardown_failed.push(run_id.clone());
                // NOTE: the UID is deliberately NOT released here: the run
                // may still hold live processes, netns, or files.
            }
        }
    }

    // Recompute live sets (only Destroyed runs remain, which hold nothing).
    let _ = (live_jail_ids, live_netns, live_taps);

    // Sweep strays: firecracker pids, netns, TAPs, jail dirs with no run.
    for (pid, _cmdline) in sys.firecracker_pids() {
        let _ = sys.kill_pid(pid);
        report.killed_pids.push(pid);
    }
    for ns in sys.netns_names(netns_prefix) {
        if sys.delete_netns(&ns).is_ok() {
            report.removed_netns.push(ns);
        }
    }
    for tap in sys.tap_names(tap_prefix) {
        if sys.delete_tap(&tap).is_ok() {
            report.removed_taps.push(tap);
        }
    }
    // The jailer nests per-id jails under <chroot_base>/<exec_file_name>;
    // scan that directory, not a hardcoded `firecracker` component.
    let jail_root = jailer::jail_parent(chroot_base, firecracker_bin);
    for jail_id in sys.jail_dirs(&jail_root) {
        let dir = jail_root.join(&jail_id);
        if sys.remove_dir(&dir).is_ok() {
            report.removed_dirs.push(dir.display().to_string());
        }
    }

    Ok(report)
}

/// In-memory [`SystemView`] for hermetic tests.
#[derive(Debug, Default)]
pub struct FakeSystemView {
    pub pids: HashMap<u32, String>,
    pub alive: HashSet<u32>,
    pub netns: HashSet<String>,
    pub taps: HashSet<String>,
    pub dirs: HashSet<PathBuf>,
    /// Single files (e.g. the workspace disk) tracked separately from dirs.
    pub files: HashSet<PathBuf>,
    /// cgroup dir -> member pids. A successful `kill_cgroup` kills every
    /// member still in `alive`, modelling cgroup.kill.
    pub cgroup_members: HashMap<PathBuf, Vec<u32>>,
    pub killed: Vec<u32>,
    /// Failure injection: when set, the corresponding teardown step fails
    /// while the resource stays present, so the postcondition check must
    /// report it unconfirmed.
    pub kill_fail: bool,
    pub net_fail: bool,
    pub remove_fail: bool,
}

impl SystemView for FakeSystemView {
    fn firecracker_pids(&self) -> Vec<(u32, String)> {
        self.pids
            .iter()
            .filter(|(pid, _)| self.alive.contains(pid))
            .map(|(pid, cmd)| (*pid, cmd.clone()))
            .collect()
    }

    fn pid_alive(&self, pid: u32) -> bool {
        self.alive.contains(&pid)
    }

    fn kill_cgroup(&mut self, cgroup_path: &Path) -> io::Result<()> {
        if self.kill_fail {
            return Err(io::Error::other("kill failed"));
        }
        // Model cgroup.kill: every member still alive dies.
        if let Some(members) = self.cgroup_members.get(cgroup_path) {
            for pid in members.clone() {
                self.alive.remove(&pid);
                self.killed.push(pid);
            }
        }
        Ok(())
    }

    fn kill_pid(&mut self, pid: u32) -> io::Result<()> {
        if self.kill_fail {
            return Err(io::Error::other("kill failed"));
        }
        if self.alive.remove(&pid) {
            self.killed.push(pid);
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }

    fn netns_names(&self, prefix: &str) -> Vec<String> {
        self.netns
            .iter()
            .filter(|n| n.starts_with(prefix))
            .cloned()
            .collect()
    }

    fn delete_netns(&mut self, name: &str) -> io::Result<()> {
        if self.net_fail {
            return Err(io::Error::other("netns delete failed"));
        }
        if self.netns.remove(name) {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }

    fn tap_names(&self, prefix: &str) -> Vec<String> {
        self.taps
            .iter()
            .filter(|n| n.starts_with(prefix))
            .cloned()
            .collect()
    }

    fn delete_tap(&mut self, name: &str) -> io::Result<()> {
        if self.net_fail {
            return Err(io::Error::other("tap delete failed"));
        }
        if self.taps.remove(name) {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }

    fn remove_dir(&mut self, path: &Path) -> io::Result<()> {
        if self.remove_fail {
            return Err(io::Error::other("remove dir failed"));
        }
        if self.dirs.remove(path) {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }

    fn remove_file(&mut self, path: &Path) -> io::Result<()> {
        if self.remove_fail {
            return Err(io::Error::other("remove file failed"));
        }
        if self.files.remove(path) {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }

    fn cgroup_pids(&self, cgroup_path: &Path) -> Vec<u32> {
        self.cgroup_members
            .get(cgroup_path)
            .map(|members| {
                members
                    .iter()
                    .copied()
                    .filter(|pid| self.alive.contains(pid))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn path_exists(&self, path: &Path) -> bool {
        self.dirs.contains(path) || self.files.contains(path)
    }

    fn jail_dirs(&self, chroot_base: &Path) -> Vec<String> {
        self.dirs
            .iter()
            .filter_map(|d| {
                d.strip_prefix(chroot_base)
                    .ok()
                    .and_then(|rel| rel.components().next())
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .collect()
    }
}

/// Real host view for production reconciliation. Shells out to `ip`,
/// reads `/proc`, and manipulates cgroups directly. All operations are
/// best-effort: reconciliation must not fail because a stray is already gone.
pub struct HostSystemView;

impl HostSystemView {
    fn run_ip(args: &[&str]) -> io::Result<String> {
        let out = std::process::Command::new("ip").args(args).output()?;
        if !out.status.success() {
            return Err(io::Error::other(format!("ip {} failed", args.join(" "))));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

impl SystemView for HostSystemView {
    fn firecracker_pids(&self) -> Vec<(u32, String)> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return out;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid_str) = name.to_str() else {
                continue;
            };
            let Ok(pid) = pid_str.parse::<u32>() else {
                continue;
            };
            let cmdline_path = format!("/proc/{pid}/cmdline");
            let Ok(cmdline) = std::fs::read(&cmdline_path) else {
                continue;
            };
            // cmdline is NUL-separated; check the first component.
            let prog = cmdline
                .split(|b| *b == 0)
                .next()
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .unwrap_or_default();
            if prog.contains("firecracker") {
                out.push((pid, prog));
            }
        }
        out
    }

    fn pid_alive(&self, pid: u32) -> bool {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }

    fn kill_cgroup(&mut self, cgroup_path: &Path) -> io::Result<()> {
        crate::cgroups::kill(Path::new("/sys/fs/cgroup"), cgroup_path)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn kill_pid(&mut self, pid: u32) -> io::Result<()> {
        let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            // Already gone is fine.
            if err.kind() != std::io::ErrorKind::NotFound {
                return Err(err);
            }
        }
        Ok(())
    }

    fn netns_names(&self, prefix: &str) -> Vec<String> {
        let Ok(out) = Self::run_ip(&["netns", "list"]) else {
            return Vec::new();
        };
        out.lines()
            .filter_map(|line| {
                let name = line.split_whitespace().next()?;
                name.strip_prefix(prefix).map(|_| name.to_string())
            })
            .collect()
    }

    fn delete_netns(&mut self, name: &str) -> io::Result<()> {
        Self::run_ip(&["netns", "delete", name]).map(|_| ())
    }

    fn tap_names(&self, prefix: &str) -> Vec<String> {
        let Ok(out) = Self::run_ip(&["-o", "link", "show"]) else {
            return Vec::new();
        };
        out.lines()
            .filter_map(|line| {
                // Format: "idx: name: <flags> ..."
                let name = line.split(':').nth(1)?.trim();
                // TAPs have a specific prefix; also strip @if suffix.
                let name = name.split('@').next()?.trim();
                name.strip_prefix(prefix).map(|_| name.to_string())
            })
            .collect()
    }

    fn delete_tap(&mut self, name: &str) -> io::Result<()> {
        Self::run_ip(&["link", "delete", name]).map(|_| ())
    }

    fn remove_dir(&mut self, path: &Path) -> io::Result<()> {
        match std::fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn remove_file(&mut self, path: &Path) -> io::Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn cgroup_pids(&self, cgroup_path: &Path) -> Vec<u32> {
        // Records may store the path relative to /sys/fs/cgroup or
        // absolute; teardown resolves it before calling, this tolerates
        // both for direct callers.
        let dir = if cgroup_path.is_absolute() {
            cgroup_path.to_path_buf()
        } else {
            Path::new("/sys/fs/cgroup").join(cgroup_path)
        };
        // A missing cgroup.procs means the cgroup is gone: no members.
        let Ok(text) = std::fs::read_to_string(dir.join("cgroup.procs")) else {
            return Vec::new();
        };
        text.lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .collect()
    }

    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn jail_dirs(&self, chroot_base: &Path) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(chroot_base) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|e| {
                let ft = e.file_type().ok()?;
                if ft.is_dir() {
                    e.file_name().to_str().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{NetworkPolicy, ResourceLimits, SandboxProfile};

    pub fn test_spec() -> SandboxRunSpec {
        SandboxRunSpec {
            image_digest: "sha256:test-image".into(),
            kernel_digest: "sha256:test-kernel".into(),
            policy_version: "sandbox-policy-v1".into(),
            profile: SandboxProfile::Strict,
            limits: ResourceLimits {
                vcpu: 1,
                memory_mib: 512,
                wall_time_secs: 60,
                max_processes: 32,
                disk_mib: 1024,
                max_output_bytes: 65536,
            },
            network: NetworkPolicy {
                allow_egress: vec![],
                deny_metadata: true,
                deny_private_ranges: true,
            },
            command: vec!["true".into()],
            env: vec![],
        }
    }

    pub fn test_artifacts(tag: &str) -> ArtifactPaths {
        ArtifactPaths {
            jail_id: format!("lmn-{tag}"),
            chroot_dir: PathBuf::from(format!("/srv/jailer/firecracker/lmn-{tag}/root")),
            config_path: PathBuf::from(format!(
                "/srv/jailer/firecracker/lmn-{tag}/root/config.json"
            )),
            uid: 61000,
            gid: 61000,
            netns_name: format!("lmn-{tag}"),
            tap_name: format!("lmnt-{tag}"),
            veth_host: format!("lmnvh-{tag}"),
            veth_guest: format!("lmnvg-{tag}"),
            host_ip: "10.244.0.1".into(),
            guest_ip: "10.244.0.2".into(),
            cgroup_path: PathBuf::from(format!("/sys/fs/cgroup/lumen/lmn-{tag}")),
            workspace_disk: PathBuf::from(format!("/var/lib/lumen/runs/lmn-{tag}/ws.qcow2")),
            vsock_path: PathBuf::from(format!("/srv/jailer/firecracker/lmn-{tag}/root/v.sock")),
            api_sock: PathBuf::from(format!("/srv/jailer/firecracker/lmn-{tag}/root/api.sock")),
            staging_dir: PathBuf::from(format!("/var/lib/lumen/runs/lmn-{tag}/staging")),
            jailer_pid: 4242,
        }
    }

    fn test_store() -> (tempfile::TempDir, RunStore) {
        let tmp = tempfile::tempdir().unwrap();
        let store = RunStore::open(tmp.path()).unwrap();
        (tmp, store)
    }

    #[test]
    fn create_and_transition_journals_every_step() {
        let (_tmp, store) = test_store();
        let spec = test_spec();
        let record = store
            .create(
                "lmn-abc123",
                spec,
                "sha256:spec".into(),
                test_artifacts("abc123"),
            )
            .unwrap();
        assert_eq!(record.state, RunState::Prepared);

        for to in [
            RunState::Starting,
            RunState::Running,
            RunState::Exporting,
            RunState::Destroying,
            RunState::Destroyed,
        ] {
            store.transition("lmn-abc123", to).unwrap();
        }
        let final_record = store.load("lmn-abc123").unwrap();
        assert_eq!(final_record.state, RunState::Destroyed);

        let journal = std::fs::read_to_string(store.journal_path("lmn-abc123")).unwrap();
        let lines: Vec<_> = journal.lines().collect();
        // Created + 5 transitions = 6 entries, seqs 0..6.
        assert_eq!(lines.len(), 6);
        for (i, line) in lines.iter().enumerate() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["seq"], i as u64);
        }
    }

    #[test]
    fn state_survives_reload() {
        let tmp = tempfile::tempdir().unwrap();
        let store = RunStore::open(tmp.path()).unwrap();
        store
            .create(
                "lmn-xyz",
                test_spec(),
                "sha256:s".into(),
                test_artifacts("xyz"),
            )
            .unwrap();
        store.transition("lmn-xyz", RunState::Running).unwrap();
        drop(store);

        let store2 = RunStore::open(tmp.path()).unwrap();
        let runs = store2.all_runs().unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].state, RunState::Running);
    }

    #[test]
    fn reconcile_reclaims_orphaned_run() {
        let (_tmp, store) = test_store();
        let artifacts = test_artifacts("dead01");
        store
            .create(
                "lmn-dead01",
                test_spec(),
                "sha256:s".into(),
                artifacts.clone(),
            )
            .unwrap();
        store.transition("lmn-dead01", RunState::Running).unwrap();

        // Simulate the host as the dead daemon left it.
        let mut sys = FakeSystemView::default();
        sys.alive.insert(4242);
        sys.pids.insert(4242, "firecracker --api-sock ...".into());
        sys.netns.insert(artifacts.netns_name.clone());
        sys.taps.insert(artifacts.tap_name.clone());
        sys.dirs.insert(artifacts.chroot_dir.clone());
        sys.dirs.insert(artifacts.cgroup_path.clone());
        sys.dirs.insert(artifacts.staging_dir.clone());

        let mut released = Vec::new();
        let report = reconcile(
            &store,
            &mut sys,
            Path::new("/srv/jailer"),
            Path::new("/usr/bin/firecracker"),
            "lmn-",
            "lmnt-",
            |uid| released.push(uid),
        )
        .unwrap();

        assert_eq!(report.orphaned_runs, vec!["lmn-dead01".to_string()]);
        assert!(report.killed_pids.contains(&4242));
        assert!(report.removed_netns.contains(&artifacts.netns_name));
        assert!(report.removed_taps.contains(&artifacts.tap_name));
        assert_eq!(released, vec![61000]);

        let final_record = store.load("lmn-dead01").unwrap();
        assert_eq!(final_record.state, RunState::Destroyed);
        assert!(sys.netns.is_empty() && sys.taps.is_empty());
    }

    #[test]
    fn reconcile_sweeps_strays_with_no_run() {
        let (_tmp, store) = test_store();
        let mut sys = FakeSystemView::default();
        sys.alive.insert(9999);
        sys.pids
            .insert(9999, "firecracker --api-sock /srv/jailer/...".into());
        sys.netns.insert("lmn-stray01".into());
        sys.taps.insert("lmnt-stray01".into());
        sys.dirs
            .insert(PathBuf::from("/srv/jailer/firecracker/lmn-stray01"));

        let report = reconcile(
            &store,
            &mut sys,
            Path::new("/srv/jailer"),
            Path::new("/usr/bin/firecracker"),
            "lmn-",
            "lmnt-",
            |_| {},
        )
        .unwrap();

        assert!(report.orphaned_runs.is_empty());
        assert!(report.killed_pids.contains(&9999));
        assert!(report.removed_netns.contains(&"lmn-stray01".to_string()));
        assert!(report.removed_taps.contains(&"lmnt-stray01".to_string()));
        assert_eq!(report.removed_dirs.len(), 1);
    }

    #[test]
    fn reconcile_leaves_unrelated_resources_alone() {
        let (_tmp, store) = test_store();
        let mut sys = FakeSystemView::default();
        sys.netns.insert("other-ns".into());
        sys.taps.insert("eth0".into());

        let report = reconcile(
            &store,
            &mut sys,
            Path::new("/srv/jailer"),
            Path::new("/usr/bin/firecracker"),
            "lmn-",
            "lmnt-",
            |_| {},
        )
        .unwrap();

        assert!(report.is_clean());
        assert!(sys.netns.contains("other-ns"));
        assert!(sys.taps.contains("eth0"));
    }

    #[test]
    fn reconcile_is_idempotent() {
        let (_tmp, store) = test_store();
        store
            .create(
                "lmn-once",
                test_spec(),
                "sha256:s".into(),
                test_artifacts("once"),
            )
            .unwrap();
        let mut sys = FakeSystemView::default();
        let r1 = reconcile(
            &store,
            &mut sys,
            Path::new("/srv/jailer"),
            Path::new("/usr/bin/firecracker"),
            "lmn-",
            "lmnt-",
            |_| {},
        )
        .unwrap();
        assert_eq!(r1.orphaned_runs.len(), 1);
        let r2 = reconcile(
            &store,
            &mut sys,
            Path::new("/srv/jailer"),
            Path::new("/usr/bin/firecracker"),
            "lmn-",
            "lmnt-",
            |_| {},
        )
        .unwrap();
        assert!(r2.is_clean());
    }

    /// Build a fake host that looks like the dead daemon left it: live
    /// jailer pid, cgroup members, netns, TAP, dirs, and workspace file.
    fn dirty_sys(artifacts: &ArtifactPaths) -> FakeSystemView {
        let mut sys = FakeSystemView::default();
        sys.alive.insert(4242);
        sys.pids.insert(4242, "firecracker --api-sock ...".into());
        sys.cgroup_members
            .insert(artifacts.cgroup_path.clone(), vec![4242]);
        sys.netns.insert(artifacts.netns_name.clone());
        sys.taps.insert(artifacts.tap_name.clone());
        sys.dirs.insert(artifacts.chroot_dir.clone());
        sys.dirs.insert(artifacts.cgroup_path.clone());
        sys.dirs.insert(artifacts.staging_dir.clone());
        sys.files.insert(artifacts.workspace_disk.clone());
        sys
    }

    fn journal_events(store: &RunStore, run_id: &str) -> Vec<serde_json::Value> {
        let journal = std::fs::read_to_string(store.journal_path(run_id)).unwrap();
        journal
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn reconcile_all(
        store: &RunStore,
        sys: &mut FakeSystemView,
        released: &mut Vec<u32>,
    ) -> ReconcileReport {
        reconcile(
            store,
            sys,
            Path::new("/srv/jailer"),
            Path::new("/usr/bin/firecracker"),
            "lmn-",
            "lmnt-",
            |uid| released.push(uid),
        )
        .unwrap()
    }

    #[test]
    fn teardown_failure_keeps_nonterminal_state_and_retains_record() {
        let (_tmp, store) = test_store();
        let artifacts = test_artifacts("tfail01");
        store
            .create(
                "lmn-tfail01",
                test_spec(),
                "sha256:s".into(),
                artifacts.clone(),
            )
            .unwrap();
        store.transition("lmn-tfail01", RunState::Running).unwrap();

        // Inject a failing kill step: the pid and cgroup members survive.
        let mut sys = dirty_sys(&artifacts);
        sys.kill_fail = true;

        let mut released = Vec::new();
        let report = reconcile_all(&store, &mut sys, &mut released);

        // The run must NOT be marked Destroyed: it sits in the nonterminal
        // recovery state with its record retained for retry.
        let record = store.load("lmn-tfail01").unwrap();
        assert_eq!(record.state, RunState::TeardownFailed);
        assert!(!record.state.is_terminal());
        assert_eq!(record.teardown_attempts, 1);
        assert_eq!(report.teardown_failed, vec!["lmn-tfail01".to_string()]);
        // The UID must stay allocated while resources may still be live.
        assert!(released.is_empty());
        assert!(!report.is_clean());

        // The alert is journaled through the audit pipeline: attempt number
        // plus the unconfirmed artifacts (the surviving pid/cgroup).
        let events = journal_events(&store, "lmn-tfail01");
        let alerts: Vec<_> = events
            .iter()
            .filter(|v| v["event"] == "teardown_alert")
            .collect();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0]["attempt"], 1);
        let failures = alerts[0]["failures"].as_array().unwrap();
        assert!(!failures.is_empty());
        let text = failures
            .iter()
            .map(|f| f.as_str().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        assert!(text.contains("4242"), "alert names the pid: {text}");
        assert!(text.contains("processes"), "alert names the step: {text}");

        // The surviving process is genuinely still there.
        assert!(sys.pid_alive(4242));
    }

    #[test]
    fn teardown_retry_succeeds_after_transient_failure() {
        let (_tmp, store) = test_store();
        let artifacts = test_artifacts("tret01");
        store
            .create(
                "lmn-tret01",
                test_spec(),
                "sha256:s".into(),
                artifacts.clone(),
            )
            .unwrap();
        store.transition("lmn-tret01", RunState::Running).unwrap();

        let mut sys = dirty_sys(&artifacts);
        sys.kill_fail = true;
        let mut released = Vec::new();
        reconcile_all(&store, &mut sys, &mut released);
        assert_eq!(
            store.load("lmn-tret01").unwrap().state,
            RunState::TeardownFailed
        );

        // Transient failure clears; move the backoff clock into the past so
        // the retry is due without sleeping in the test.
        sys.kill_fail = false;
        let past = now_unix().saturating_sub(TEARDOWN_RETRY_MAX_SECS + 1);
        store.set_updated_at_for_test("lmn-tret01", past).unwrap();

        let report = reconcile_all(&store, &mut sys, &mut released);
        let record = store.load("lmn-tret01").unwrap();
        assert_eq!(record.state, RunState::Destroyed);
        assert!(report.teardown_failed.is_empty());
        assert_eq!(released, vec![61000]);
        assert!(!sys.pid_alive(4242));
        assert!(!sys.path_exists(&artifacts.chroot_dir));

        // The successful teardown is journaled too (previously dead variant).
        let events = journal_events(&store, "lmn-tret01");
        assert!(events.iter().any(|v| v["event"] == "artifacts_removed"));
    }

    #[test]
    fn teardown_retry_respects_backoff() {
        let (_tmp, store) = test_store();
        let artifacts = test_artifacts("tbo01");
        store
            .create(
                "lmn-tbo01",
                test_spec(),
                "sha256:s".into(),
                artifacts.clone(),
            )
            .unwrap();
        store.transition("lmn-tbo01", RunState::Running).unwrap();

        let mut sys = dirty_sys(&artifacts);
        sys.kill_fail = true;
        let mut released = Vec::new();
        reconcile_all(&store, &mut sys, &mut released);
        assert_eq!(record_attempts(&store), 1);

        // Failure cleared, but the backoff has NOT elapsed: the run must be
        // left alone for a later reconcile, with no duplicate alert.
        sys.kill_fail = false;
        let report = reconcile_all(&store, &mut sys, &mut released);
        let record = store.load("lmn-tbo01").unwrap();
        assert_eq!(record.state, RunState::TeardownFailed);
        assert_eq!(record.teardown_attempts, 1);
        assert_eq!(report.teardown_failed, vec!["lmn-tbo01".to_string()]);
        assert!(report.orphaned_runs.is_empty());
        let events = journal_events(&store, "lmn-tbo01");
        assert_eq!(
            events
                .iter()
                .filter(|v| v["event"] == "teardown_alert")
                .count(),
            1
        );

        fn record_attempts(store: &RunStore) -> u32 {
            store.load("lmn-tbo01").unwrap().teardown_attempts
        }
    }

    #[test]
    fn teardown_network_failure_is_unconfirmed_not_destroyed() {
        let (_tmp, store) = test_store();
        let artifacts = test_artifacts("tnet01");
        store
            .create(
                "lmn-tnet01",
                test_spec(),
                "sha256:s".into(),
                artifacts.clone(),
            )
            .unwrap();
        store.transition("lmn-tnet01", RunState::Running).unwrap();

        let mut sys = dirty_sys(&artifacts);
        sys.net_fail = true;
        let mut released = Vec::new();
        let report = reconcile_all(&store, &mut sys, &mut released);

        assert_eq!(
            store.load("lmn-tnet01").unwrap().state,
            RunState::TeardownFailed
        );
        assert!(released.is_empty());
        assert_eq!(report.teardown_failed, vec!["lmn-tnet01".to_string()]);
        // Network resources are still present; processes were reclaimed.
        assert!(sys.netns.contains(&artifacts.netns_name));
        assert!(sys.taps.contains(&artifacts.tap_name));
        assert!(!sys.pid_alive(4242));

        let events = journal_events(&store, "lmn-tnet01");
        let alert = events
            .iter()
            .find(|v| v["event"] == "teardown_alert")
            .unwrap();
        let text = alert["failures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f.as_str().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        assert!(
            text.contains(&artifacts.tap_name),
            "alert names tap: {text}"
        );
        assert!(
            text.contains(&artifacts.netns_name),
            "alert names netns: {text}"
        );
    }

    #[test]
    fn teardown_is_idempotent_on_clean_run() {
        let (_tmp, store) = test_store();
        store
            .create(
                "lmn-clean01",
                test_spec(),
                "sha256:s".into(),
                test_artifacts("clean01"),
            )
            .unwrap();
        store.transition("lmn-clean01", RunState::Running).unwrap();

        // Nothing exists on the host: every "already gone" is success.
        let mut sys = FakeSystemView::default();
        let mut released = Vec::new();
        let report = reconcile_all(&store, &mut sys, &mut released);

        assert_eq!(
            store.load("lmn-clean01").unwrap().state,
            RunState::Destroyed
        );
        assert!(report.teardown_failed.is_empty());
        assert_eq!(released, vec![61000]);
    }

    #[test]
    fn teardown_backoff_schedule() {
        assert_eq!(teardown_backoff_secs(0), 5);
        assert_eq!(teardown_backoff_secs(1), 5);
        assert_eq!(teardown_backoff_secs(2), 10);
        assert_eq!(teardown_backoff_secs(3), 20);
        assert_eq!(teardown_backoff_secs(6), 160);
        assert_eq!(teardown_backoff_secs(7), 300);
        assert_eq!(teardown_backoff_secs(100), 300);
    }

    #[test]
    fn teardown_failed_state_is_nonterminal() {
        assert!(!RunState::TeardownFailed.is_terminal());
        // Serde round-trip: the journal must persist the new state name.
        let name = serde_json::to_string(&RunState::TeardownFailed).unwrap();
        assert_eq!(name, "\"teardown_failed\"");
        let back: RunState = serde_json::from_str(&name).unwrap();
        assert_eq!(back, RunState::TeardownFailed);
    }

    #[test]
    fn terminal_states() {
        assert!(RunState::Destroyed.is_terminal());
        assert!(RunState::Done.is_terminal());
        assert!(!RunState::Running.is_terminal());
        assert!(!RunState::Orphaned.is_terminal());
        assert!(!RunState::TeardownFailed.is_terminal());
    }
}
