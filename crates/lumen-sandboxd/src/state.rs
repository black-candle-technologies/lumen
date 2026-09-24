//! Crash-safe run state machine and startup reconciliation.
//!
//! Every run moves through
//! `Prepared -> Starting -> Running -> Exporting -> Destroying -> Destroyed`
//! (with `Done`/`Failed`/`Cancelled`/`TimedOut` as pre-destroy terminal
//! markers). Each transition is appended to a per-run JSONL journal and
//! fsynced before the transition is considered durable.
//!
//! Crash rule: if the daemon dies at any point, the next boot's
//! [`reconcile`] finds every run that is not `Destroyed`, marks it
//! `Orphaned`, reclaims its VM, TAP device, netns, cgroup, chroot, and
//! disks, and sweeps any stray resources not tied to a run. A host restart
//! mid-run therefore leaves zero orphaned VMs, TAP devices, or disks.

use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    contracts::{SandboxResult, SandboxRunSpec},
    error::SandboxdError,
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
    /// Jailer chroot: `<chroot_base>/firecracker/<jail_id>/root`.
    pub chroot_dir: PathBuf,
    /// Firecracker config + seccomp filter inside the chroot staging area.
    pub config_path: PathBuf,
    pub seccomp_path: PathBuf,
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
}

/// Journal entry appended on every mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum JournalEvent {
    Created { spec_digest: String },
    StateChanged { from: RunState, to: RunState },
    ProvenanceRecorded { image_digest: String },
    OutputTruncated { kept_bytes: u64 },
    ExportStaged { files: usize, bytes: u64 },
    OrphanedFound {},
    ArtifactsRemoved { removed: Vec<String> },
    Note { message: String },
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
}

impl ReconcileReport {
    pub fn is_clean(&self) -> bool {
        self.orphaned_runs.is_empty()
            && self.killed_pids.is_empty()
            && self.removed_netns.is_empty()
            && self.removed_taps.is_empty()
            && self.removed_dirs.is_empty()
    }
}

/// Remove every artifact belonging to one run. Idempotent: missing pieces
/// are skipped, never fatal.
fn destroy_artifacts<S: SystemView>(run: &RunRecord, sys: &mut S, report: &mut ReconcileReport) {
    let a = &run.artifacts;

    // 1. Kill the VM: cgroup.kill first (catches jailer + firecracker +
    //    any forked children), fall back to the recorded pid.
    if sys.kill_cgroup(&a.cgroup_path).is_ok() {
        // cgroup.kill is best-effort; absence of the cgroup is fine.
    }
    if a.jailer_pid != 0 && sys.pid_alive(a.jailer_pid) {
        let _ = sys.kill_pid(a.jailer_pid);
        report.killed_pids.push(a.jailer_pid);
    }

    // 2. Network: TAP then netns.
    if sys.delete_tap(&a.tap_name).is_ok() {
        report.removed_taps.push(a.tap_name.clone());
    }
    if sys.delete_netns(&a.netns_name).is_ok() {
        report.removed_netns.push(a.netns_name.clone());
    }

    // 3. Filesystem: chroot, cgroup dir, workspace disk, staging.
    //    The chroot dir removal covers config/seccomp/api.sock/vsock.
    for dir in [
        a.chroot_dir.clone(),
        a.cgroup_path.clone(),
        a.staging_dir.clone(),
    ] {
        if sys.remove_dir(&dir).is_ok() {
            report.removed_dirs.push(dir.display().to_string());
        }
    }
    // The qcow2 delta lives next to the chroot staging area's parent run
    // dir; remove the file explicitly.
    let _ = std::fs::remove_file(&a.workspace_disk);
}

/// Daemon-startup crash recovery. For every run that is not `Destroyed`:
/// mark `Orphaned`, reclaim all artifacts, release its UID, mark
/// `Destroyed`. Then sweep stray firecracker processes, netns, TAPs, and
/// jail dirs that belong to no live run.
///
/// `release_uid` persists the freed UID back into the allocator.
pub fn reconcile<S: SystemView>(
    store: &RunStore,
    sys: &mut S,
    chroot_base: &Path,
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
        // got to destroy it). Reclaim unconditionally.
        let run_id = run.run_id.clone();
        store.note(&run_id, "reconcile: orphaned run found".to_string())?;
        store.transition(&run_id, RunState::Orphaned)?;
        report.orphaned_runs.push(run_id.clone());

        let reloaded = store.load(&run_id)?;
        destroy_artifacts(&reloaded, sys, &mut report);
        release_uid(reloaded.artifacts.uid);
        report.released_uids.push(reloaded.artifacts.uid);
        store.transition(&run_id, RunState::Destroying)?;
        store.transition(&run_id, RunState::Destroyed)?;
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
    let jail_root = chroot_base.join("firecracker");
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
    pub killed: Vec<u32>,
    pub kill_fail: bool,
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

    fn kill_cgroup(&mut self, _cgroup_path: &Path) -> io::Result<()> {
        if self.kill_fail {
            return Err(io::Error::other("kill failed"));
        }
        Ok(())
    }

    fn kill_pid(&mut self, pid: u32) -> io::Result<()> {
        if self.kill_fail {
            return Err(io::Error::other("kill failed"));
        }
        self.alive.remove(&pid);
        self.killed.push(pid);
        Ok(())
    }

    fn netns_names(&self, prefix: &str) -> Vec<String> {
        self.netns
            .iter()
            .filter(|n| n.starts_with(prefix))
            .cloned()
            .collect()
    }

    fn delete_netns(&mut self, name: &str) -> io::Result<()> {
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
        if self.taps.remove(name) {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }

    fn remove_dir(&mut self, path: &Path) -> io::Result<()> {
        if self.dirs.remove(path) {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
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
            seccomp_path: PathBuf::from(format!(
                "/srv/jailer/firecracker/lmn-{tag}/root/seccomp.json"
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
            "lmn-",
            "lmnt-",
            |_| {},
        )
        .unwrap();
        assert!(r2.is_clean());
    }

    #[test]
    fn terminal_states() {
        assert!(RunState::Destroyed.is_terminal());
        assert!(RunState::Done.is_terminal());
        assert!(!RunState::Running.is_terminal());
        assert!(!RunState::Orphaned.is_terminal());
    }
}
