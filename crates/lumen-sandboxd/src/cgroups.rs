//! cgroup v2 quota enforcement and metering.
//!
//! The jailer applies the primary limits itself (`--cgroup memory.max=…`
//! etc.), so no extra privileged helper sits between sandboxd and the VMM.
//! This module covers the surrounding duties:
//!
//! - [`apply_limits`]: idempotent limit writer (used when the driver manages
//!   the cgroup directly, e.g. tests and non-jailer fallbacks);
//! - [`read_peak_memory_mib`]: usage metering for [`SandboxUsage`];
//! - [`kill`]: `cgroup.kill` — terminates the VMM *and its threads*, the
//!   preferred termination path;
//! - [`remove`]: cgroup teardown during destroy/reconcile.
//!
//! Semantics note on `pids.max`: this cgroup lives on the HOST and counts
//! Firecracker VMM threads (main, API, vCPUs, virtio workers) — it does
//! NOT count guest processes, because a guest `fork()` never creates a host
//! task. It is therefore set from [`vmm_pids_max`] (a VMM thread bound),
//! never from `contracts::ResourceLimits::max_processes`, which is not
//! currently enforced for guest processes in this phase (see that field's
//! docs). The VM boundary is the guest isolation in this phase.
//!
//! All paths are rooted at a configurable cgroupfs mount so the logic is
//! hermetically testable against a fake tree.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use crate::contracts::ResourceLimits;

/// The cgroup v2 parent every run cgroup lives under. Single source of
/// truth: the driver, the jailer argv, and the reconcile stray sweep must
/// agree on this path, otherwise limits, kill, and metering act on the
/// wrong cgroup.
pub const CGROUP_PARENT: &str = "/sys/fs/cgroup/lumen";

/// Firecracker's minimum guest RAM: `render_config` clamps to this, and the
/// host-side `memory.max` is derived from the clamped value so a request
/// with `memory_mib < 64` cannot fail every run.
pub const GUEST_MEM_MIN_MIB: u64 = 64;

/// Headroom for the Firecracker VMM process itself on top of guest RAM.
/// The VMM's RSS is guest RAM plus its own device/API state; without
/// headroom a guest that uses its full RAM allocation gets the VMM
/// OOM-killed instead of the guest.
pub const VMM_OVERHEAD_MIB: u64 = 128;

/// Guest RAM actually configured in the VM (clamped to Firecracker's minimum).
pub fn guest_mem_mib(limits: &ResourceLimits) -> u64 {
    limits.memory_mib.max(GUEST_MEM_MIN_MIB)
}

/// Host-side `memory.max` for the run's cgroup: guest RAM plus VMM
/// overhead. Both limit writers ([`apply_limits`] and the jailer's
/// `--cgroup` flags) must use this one formula.
pub fn host_memory_max_mib(limits: &ResourceLimits) -> u64 {
    guest_mem_mib(limits) + VMM_OVERHEAD_MIB
}

/// Host-side thread cap for the run's cgroup (`pids.max`). Bounds VMM
/// threads only — never guest processes. Deliberately decoupled from
/// `max_processes`: a small guest process cap must not break VM startup.
/// Generous on purpose; tripping it means the VMM itself is misbehaving.
pub fn vmm_pids_max(vcpu: u32) -> u32 {
    32 + 8 * vcpu.max(1)
}

/// Write one cgroup control file. Missing files are an error — silently
/// skipping a limit would be a fail-open.
fn write_one(cgroup: &Path, file: &str, value: &str) -> io::Result<()> {
    let path = cgroup.join(file);
    let mut f = fs::OpenOptions::new().write(true).open(&path)?;
    f.write_all(value.as_bytes())?;
    Ok(())
}

/// Apply the run's quotas to `fs_root/rel_path`, creating the cgroup if
/// needed. Idempotent.
pub fn apply_limits(
    fs_root: &Path,
    rel_path: &Path,
    limits: &ResourceLimits,
) -> io::Result<PathBuf> {
    let cgroup = fs_root.join(rel_path);
    fs::create_dir_all(&cgroup)?;
    write_one(
        &cgroup,
        "memory.max",
        &format!("{}M", host_memory_max_mib(limits)),
    )?;
    write_one(&cgroup, "memory.swap.max", "0")?;
    let quota = limits.vcpu.max(1) as u64 * 100_000;
    write_one(&cgroup, "cpu.max", &format!("{quota} 100000"))?;
    // Host-side VMM thread cap (see [`vmm_pids_max`]); guest processes are
    // contained in-guest by the agent, never by this file.
    write_one(&cgroup, "pids.max", &vmm_pids_max(limits.vcpu).to_string())?;
    // Weighted fair share; the hard cap is cpu.max.
    write_one(&cgroup, "cpu.weight", "100")?;
    Ok(cgroup)
}

/// Peak memory usage in MiB, from `memory.peak`.
pub fn read_peak_memory_mib(fs_root: &Path, rel_path: &Path) -> io::Result<u64> {
    let text = fs::read_to_string(fs_root.join(rel_path).join("memory.peak"))?;
    let bytes: u64 = text
        .trim()
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad memory.peak"))?;
    Ok(bytes / (1024 * 1024))
}

/// Current thread count, from `pids.current`. Used by the quota monitor.
/// This is the HOST cgroup: it counts VMM threads, not guest processes.
pub fn read_pids_current(fs_root: &Path, rel_path: &Path) -> io::Result<u64> {
    let text = fs::read_to_string(fs_root.join(rel_path).join("pids.current"))?;
    text.trim()
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad pids.current"))
}

/// Terminate every process in the cgroup via `cgroup.kill`.
pub fn kill(fs_root: &Path, rel_path: &Path) -> io::Result<()> {
    write_one(&fs_root.join(rel_path), "cgroup.kill", "1")
}

/// Move a pid into the cgroup.
pub fn add_process(fs_root: &Path, rel_path: &Path, pid: u32) -> io::Result<()> {
    write_one(&fs_root.join(rel_path), "cgroup.procs", &pid.to_string())
}

/// Remove the cgroup directory. Fails if processes remain — callers must
/// [`kill`] first; a non-empty cgroup at destroy time is a bug, not a
/// cleanup detail.
pub fn remove(fs_root: &Path, rel_path: &Path) -> io::Result<()> {
    fs::remove_dir(fs_root.join(rel_path))
}

/// Quota monitor outcome: the driver polls this during `wait()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaCheck {
    Ok,
    /// A quota was exceeded; the run must be terminated.
    Exceeded(&'static str),
}

/// Evaluate quotas from already-read counters. Pure: hermetically tested.
///
/// - `pids_current >= vmm_pids_max` → the VMM itself is spawning threads
///   out of control (this is the HOST cgroup; guest fork bombs never show
///   up here — the guest agent enforces `max_processes` in-guest);
/// - `disk_bytes > disk_cap_bytes` → disk fill (the workspace delta is
///   watched host-side since the guest could otherwise fill its disk);
/// - `elapsed_secs > wall_time_secs` → deadline.
pub fn check_quotas(
    pids_current: u64,
    vmm_pids_max: u32,
    disk_bytes: u64,
    disk_cap_bytes: u64,
    elapsed_secs: u64,
    wall_time_secs: u64,
) -> QuotaCheck {
    if pids_current >= vmm_pids_max as u64 {
        return QuotaCheck::Exceeded("vmm thread limit");
    }
    if disk_bytes > disk_cap_bytes {
        return QuotaCheck::Exceeded("disk limit");
    }
    if elapsed_secs > wall_time_secs {
        return QuotaCheck::Exceeded("wall-clock deadline");
    }
    QuotaCheck::Ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fake_cgroup() -> (tempfile::TempDir, PathBuf, ResourceLimits) {
        let tmp = tempfile::tempdir().unwrap();
        let rel = PathBuf::from("lumen/lmn-test");
        let cgroup = tmp.path().join(&rel);
        fs::create_dir_all(&cgroup).unwrap();
        for f in [
            "memory.max",
            "memory.swap.max",
            "cpu.max",
            "pids.max",
            "cpu.weight",
            "memory.peak",
            "pids.current",
            "cgroup.kill",
            "cgroup.procs",
        ] {
            fs::write(cgroup.join(f), "").unwrap();
        }
        let limits = ResourceLimits {
            vcpu: 2,
            memory_mib: 1024,
            wall_time_secs: 60,
            max_processes: 64,
            disk_mib: 2048,
            max_output_bytes: 65536,
        };
        (tmp, rel, limits)
    }

    #[test]
    fn apply_limits_writes_all_quotas() {
        let (tmp, rel, limits) = fake_cgroup();
        let cg = apply_limits(tmp.path(), &rel, &limits).unwrap();
        // memory.max = guest RAM (1024) + VMM overhead (128).
        assert_eq!(fs::read_to_string(cg.join("memory.max")).unwrap(), "1152M");
        assert_eq!(fs::read_to_string(cg.join("memory.swap.max")).unwrap(), "0");
        assert_eq!(
            fs::read_to_string(cg.join("cpu.max")).unwrap(),
            "200000 100000"
        );
        // pids.max is the host-side VMM thread cap (32 + 8*vcpu), NOT the
        // guest process limit: a small max_processes must never break VM
        // startup.
        assert_eq!(fs::read_to_string(cg.join("pids.max")).unwrap(), "48");
    }

    #[test]
    fn memory_max_has_vmm_headroom_and_floor() {
        let mut limits = ResourceLimits {
            vcpu: 1,
            memory_mib: 32, // below Firecracker's 64 MiB minimum
            wall_time_secs: 60,
            max_processes: 64,
            disk_mib: 2048,
            max_output_bytes: 65536,
        };
        // Guest RAM clamps to 64; host memory.max adds the VMM overhead.
        assert_eq!(guest_mem_mib(&limits), 64);
        assert_eq!(host_memory_max_mib(&limits), 64 + VMM_OVERHEAD_MIB);
        limits.memory_mib = 1024;
        assert_eq!(guest_mem_mib(&limits), 1024);
        assert_eq!(host_memory_max_mib(&limits), 1024 + VMM_OVERHEAD_MIB);
    }

    #[test]
    fn vmm_thread_cap_scales_with_vcpu() {
        assert_eq!(vmm_pids_max(0), 40); // vcpu clamps to >= 1
        assert_eq!(vmm_pids_max(1), 40);
        assert_eq!(vmm_pids_max(2), 48);
        assert_eq!(vmm_pids_max(8), 96);
    }

    #[test]
    fn tiny_max_processes_does_not_lower_host_pids_max() {
        // Guest fork-bomb containment is enforced inside the VM by the
        // max_processes is not enforced in-guest in this phase; the host
        // cgroup's pids.max must stay at the VMM thread cap so the VMM can
        // still start even for a very small guest process budget.
        let (tmp, rel, _limits) = fake_cgroup();
        let limits = ResourceLimits {
            vcpu: 2,
            memory_mib: 1024,
            wall_time_secs: 60,
            max_processes: 4,
            disk_mib: 2048,
            max_output_bytes: 65536,
        };
        let cg = apply_limits(tmp.path(), &rel, &limits).unwrap();
        assert_eq!(fs::read_to_string(cg.join("pids.max")).unwrap(), "48");
    }

    #[test]
    fn peak_memory_reported_in_mib() {
        let (tmp, rel, _) = fake_cgroup();
        fs::write(tmp.path().join(&rel).join("memory.peak"), "134217728\n").unwrap();
        assert_eq!(read_peak_memory_mib(tmp.path(), &rel).unwrap(), 128);
    }

    #[test]
    fn quota_checks() {
        assert_eq!(check_quotas(10, 48, 100, 1000, 10, 60), QuotaCheck::Ok);
        // Host-side VMM thread count vs the VMM thread cap (not the guest
        // process limit).
        assert_eq!(
            check_quotas(48, 48, 100, 1000, 10, 60),
            QuotaCheck::Exceeded("vmm thread limit")
        );
        assert_eq!(
            check_quotas(10, 48, 2000, 1000, 10, 60),
            QuotaCheck::Exceeded("disk limit")
        );
        assert_eq!(
            check_quotas(10, 48, 100, 1000, 61, 60),
            QuotaCheck::Exceeded("wall-clock deadline")
        );
    }

    #[test]
    fn missing_control_file_is_an_error_not_a_skip() {
        let tmp = tempfile::tempdir().unwrap();
        let rel = PathBuf::from("empty");
        let limits = ResourceLimits {
            vcpu: 1,
            memory_mib: 512,
            wall_time_secs: 60,
            max_processes: 32,
            disk_mib: 1024,
            max_output_bytes: 65536,
        };
        // create_dir_all makes the dir but none of the control files exist.
        assert!(apply_limits(tmp.path(), &rel, &limits).is_err());
    }
}
