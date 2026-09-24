//! cgroup v2 quota enforcement and metering.
//!
//! The jailer applies the primary limits itself (`--cgroup memory.max=…`
//! etc.), so no extra privileged helper sits between sandboxd and the VMM.
//! This module covers the surrounding duties:
//!
//! - [`apply_limits`]: idempotent limit writer (used when the driver manages
//!   the cgroup directly, e.g. tests and non-jailer fallbacks);
//! - [`read_peak_memory_mib`]: usage metering for [`SandboxUsage`];
//! - [`kill`]: `cgroup.kill` — terminates the VMM *and* any forked children
//!   (fork-bomb containment), the preferred termination path;
//! - [`remove`]: cgroup teardown during destroy/reconcile.
//!
//! All paths are rooted at a configurable cgroupfs mount so the logic is
//! hermetically testable against a fake tree.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use crate::contracts::ResourceLimits;

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
    write_one(&cgroup, "memory.max", &format!("{}M", limits.memory_mib))?;
    write_one(&cgroup, "memory.swap.max", "0")?;
    let quota = limits.vcpu.max(1) as u64 * 100_000;
    write_one(&cgroup, "cpu.max", &format!("{quota} 100000"))?;
    write_one(&cgroup, "pids.max", &limits.max_processes.to_string())?;
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

/// Current process count, from `pids.current`. Used by the quota monitor.
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
/// - `pids_current >= max_processes` → fork bomb / process exhaustion;
/// - `disk_bytes > disk_cap_bytes` → disk fill (the qcow2 delta is watched
///   host-side since the guest could otherwise fill its workspace disk);
/// - `elapsed_secs > wall_time_secs` → deadline.
pub fn check_quotas(
    pids_current: u64,
    max_processes: u32,
    disk_bytes: u64,
    disk_cap_bytes: u64,
    elapsed_secs: u64,
    wall_time_secs: u64,
) -> QuotaCheck {
    if pids_current >= max_processes as u64 {
        return QuotaCheck::Exceeded("process limit");
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
        assert_eq!(fs::read_to_string(cg.join("memory.max")).unwrap(), "1024M");
        assert_eq!(fs::read_to_string(cg.join("memory.swap.max")).unwrap(), "0");
        assert_eq!(
            fs::read_to_string(cg.join("cpu.max")).unwrap(),
            "200000 100000"
        );
        assert_eq!(fs::read_to_string(cg.join("pids.max")).unwrap(), "64");
    }

    #[test]
    fn peak_memory_reported_in_mib() {
        let (tmp, rel, _) = fake_cgroup();
        fs::write(tmp.path().join(&rel).join("memory.peak"), "134217728\n").unwrap();
        assert_eq!(read_peak_memory_mib(tmp.path(), &rel).unwrap(), 128);
    }

    #[test]
    fn quota_checks() {
        assert_eq!(check_quotas(10, 64, 100, 1000, 10, 60), QuotaCheck::Ok);
        assert_eq!(
            check_quotas(64, 64, 100, 1000, 10, 60),
            QuotaCheck::Exceeded("process limit")
        );
        assert_eq!(
            check_quotas(10, 64, 2000, 1000, 10, 60),
            QuotaCheck::Exceeded("disk limit")
        );
        assert_eq!(
            check_quotas(10, 64, 100, 1000, 61, 60),
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
