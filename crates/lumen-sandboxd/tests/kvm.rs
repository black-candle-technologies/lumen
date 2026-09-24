//! KVM-gated integration tests for the strict sandbox.
//!
//! These tests require:
//! - The `kvm` Cargo feature.
//! - `/dev/kvm` present.
//! - Root (for netns, cgroups, jailer).
//!
//! They are NEVER run on the dev machine. Run via
//! `scripts/sandbox/kvm-runner.sh` on lane-vps.
//!
//! Each test boots a real Firecracker microVM and verifies an isolation
//! property. Tests are single-threaded (`--test-threads=1`) to avoid
//! resource contention.

#![cfg(feature = "kvm")]

use std::path::PathBuf;

/// Skip if /dev/kvm is not present (e.g., accidentally run on dev machine).
fn require_kvm() {
    if !PathBuf::from("/dev/kvm").exists() {
        eprintln!("SKIP: /dev/kvm not present");
        std::process::exit(0);
    }
    // Must be root for netns/cgroup/jailer.
    if unsafe { libc::getuid() } != 0 {
        eprintln!("SKIP: must run as root");
        std::process::exit(0);
    }
}

/// Boot a VM, run the agent handshake, and verify basic liveness.
#[test]
fn kvm_boot_and_handshake() {
    require_kvm();
    // TODO: implement with the real Driver + FirecrackerBackend.
    // 1. Prepare a spec with the test image.
    // 2. Start the run.
    // 3. Wait for the Hello/Welcome handshake (with timeout).
    // 4. Assert the agent version matches.
    // 5. Destroy.
    eprintln!("TODO: kvm_boot_and_handshake");
}

/// Default-deny: the guest cannot reach the internet.
#[test]
fn kvm_default_deny_network() {
    require_kvm();
    // TODO:
    // 1. Boot with an empty allowlist.
    // 2. Run `curl -m 5 http://example.com` in the guest.
    // 3. Assert it fails (timeout or connection refused).
    // 4. Assert DNS for example.com fails.
    eprintln!("TODO: kvm_default_deny_network");
}

/// Proxy: allowlisted CONNECT succeeds, others get 403.
#[test]
fn kvm_proxy_allowlist() {
    require_kvm();
    // TODO:
    // 1. Boot with allowlist ["example.com:443"].
    // 2. CONNECT example.com:443 -> 200.
    // 3. CONNECT evil.com:443 -> 403.
    eprintln!("TODO: kvm_proxy_allowlist");
}

/// Metadata endpoint is unreachable.
#[test]
fn kvm_metadata_denied() {
    require_kvm();
    // TODO:
    // 1. Boot.
    // 2. Try to fetch http://169.254.169.254/latest/meta-data/.
    // 3. Assert failure.
    eprintln!("TODO: kvm_metadata_denied");
}

/// DNS rebinding to private IPs is blocked.
#[test]
fn kvm_dns_rebinding_blocked() {
    require_kvm();
    // TODO:
    // 1. Boot with a test DNS server that returns a public IP first,
    //    then a private IP on re-query.
    // 2. Assert the proxy refuses the private IP.
    eprintln!("TODO: kvm_dns_rebinding_blocked");
}

/// Fork bomb is contained by cgroup pids.max.
#[test]
fn kvm_fork_bomb_contained() {
    require_kvm();
    // TODO:
    // 1. Boot with max_processes=32.
    // 2. Run `:(){ :|:& };:` in the guest.
    // 3. Assert the run is killed (pids.max) and the host is unaffected.
    // 4. Assert host load is normal.
    eprintln!("TODO: kvm_fork_bomb_contained");
}

/// Disk fill is contained by the workspace quota.
#[test]
fn kvm_disk_fill_contained() {
    require_kvm();
    // TODO:
    // 1. Boot with disk_mib=100.
    // 2. Run `dd if=/dev/zero of=/workspace/fill bs=1M` in the guest.
    // 3. Assert it fails at ~100 MiB and the host disk is not filled.
    eprintln!("TODO: kvm_disk_fill_contained");
}

/// Killing sandboxd mid-run: reconciliation reclaims.
#[test]
fn kvm_restart_reclaims() {
    require_kvm();
    // TODO:
    // 1. Start a run (long-running workload).
    // 2. Kill -9 the sandboxd process.
    // 3. Restart sandboxd.
    // 4. Assert reconciliation marks the run Orphaned and destroys it.
    // 5. Assert no netns/TAP/cgroup/jail remains.
    eprintln!("TODO: kvm_restart_reclaims");
}

/// Orphaned netns/TAPs/cgroups are swept on startup.
#[test]
fn kvm_orphan_sweep() {
    require_kvm();
    // TODO:
    // 1. Manually create a stale netns, TAP, cgroup, and jail dir.
    // 2. Start sandboxd.
    // 3. Assert they are removed.
    eprintln!("TODO: kvm_orphan_sweep");
}

/// Guest cannot access the Firecracker API socket.
#[test]
fn kvm_vmm_socket_isolated() {
    require_kvm();
    // TODO:
    // 1. Boot.
    // 2. From the guest, try to connect to the Firecracker API socket
    //    (should not be visible in the guest's filesystem or network).
    // 3. Assert failure.
    eprintln!("TODO: kvm_vmm_socket_isolated");
}

/// Export: files are staged, hashed, and validated.
#[test]
fn kvm_export_validated() {
    require_kvm();
    // TODO:
    // 1. Boot, write files to /workspace (including a symlink attack).
    // 2. Wait for completion.
    // 3. Assert the export manifest contains only valid files.
    // 4. Assert the symlink attack was rejected.
    eprintln!("TODO: kvm_export_validated");
}

/// After destroy, no artifacts remain.
#[test]
fn kvm_cleanup_complete() {
    require_kvm();
    // TODO:
    // 1. Boot and destroy a run.
    // 2. Assert: no netns, no TAP, no cgroup, no jail dir, no run dir.
    // 3. Assert the vsock and API sockets are gone.
    eprintln!("TODO: kvm_cleanup_complete");
}
