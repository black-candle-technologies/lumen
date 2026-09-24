//! Firecracker jailer invocation.
//!
//! Defense in depth, host side:
//! - the jailer chroots into `<chroot_base>/firecracker/<id>/root`,
//!   joins the run's network namespace, optionally starts a new PID
//!   namespace, drops to a dedicated per-run UID/GID, closes inherited
//!   FDs, clears the environment, and only then execs Firecracker;
//! - cgroup v2 limits are applied by the jailer itself (`--cgroup`),
//!   so no extra privileged helper is needed between sandboxd and the VMM;
//! - the guest never sees the API socket path outside the chroot, and the
//!   chroot contains only: the firecracker binary, config, kernel, rootfs,
//!   workspace image, and the sockets firecracker itself creates.
//!
//! Flag reference: Firecracker `docs/jailer.md` (jailer `--id --exec-file
//! --uid --gid [--cgroup-version 2 --cgroup ...] [--netns] [--new-pid-ns]
//! [--daemonize] -- <firecracker args>`).

use std::path::{Path, PathBuf};

use sha2::Digest;

use crate::{
    cgroups::{guest_mem_mib, host_memory_max_mib, vmm_pids_max},
    contracts::ResourceLimits,
    error::SandboxdError,
};

/// Everything the jailer needs to launch one microVM.
#[derive(Debug, Clone)]
pub struct JailSpec {
    /// Jail id: alphanumeric + hyphens, <= 64 chars.
    pub id: String,
    pub uid: u32,
    pub gid: u32,
    pub chroot_base: PathBuf,
    /// Path to the run's network namespace handle (`/var/run/netns/<name>`).
    pub netns_path: PathBuf,
    pub firecracker_bin: PathBuf,
    pub firecracker_version: String,
    pub limits: ResourceLimits,
    /// cgroup v2 parent for this host, e.g. `/sys/fs/cgroup/lumen`.
    pub cgroup_parent: PathBuf,
    /// Whether to request a fresh snapshot restore instead of a cold boot.
    pub snapshot: Option<SnapshotLoad>,
}

#[derive(Debug, Clone)]
pub struct SnapshotLoad {
    pub mem_path: PathBuf,
    pub vmstate_path: PathBuf,
}

/// File-name component of the `--exec-file` path. The jailer builds its
/// chroot as `<chroot_base>/<exec_file_name>/<id>/root` (jailer v1.10.1
/// `env.rs`: it pushes the exec file *name*, not a fixed component), so
/// every host-side path into the jail must use the same element.
///
/// Mirrors `validate_exec_file`: the jailer `canonicalize`s `--exec-file`
/// first, so a symlinked binary contributes its *target's* file name. We
/// do the same; if canonicalization fails (e.g. in unit tests with fake
/// paths) we fall back to the literal file name.
pub fn exec_file_name(exec_file: &Path) -> String {
    let canonical = std::fs::canonicalize(exec_file).unwrap_or_else(|_| exec_file.to_path_buf());
    canonical
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("firecracker")
        .to_string()
}

/// Chroot layout produced by the jailer for `<id>`:
/// `<chroot_base>/<exec_file_name>/<id>/root/`.
pub fn jail_root(chroot_base: &Path, exec_file: &Path, id: &str) -> PathBuf {
    chroot_base
        .join(exec_file_name(exec_file))
        .join(id)
        .join("root")
}

/// The `<chroot_base>/<exec_file_name>` directory that holds the per-id
/// jails; the unit the reconcile sweep scans for strays.
pub fn jail_parent(chroot_base: &Path, exec_file: &Path) -> PathBuf {
    chroot_base.join(exec_file_name(exec_file))
}

/// Validate a jail id against the jailer's rules.
pub fn validate_jail_id(id: &str) -> Result<(), SandboxdError> {
    if id.is_empty() || id.len() > 64 {
        return Err(SandboxdError::InvalidSpec(
            "jail id must be 1..=64 chars".into(),
        ));
    }
    if !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(SandboxdError::InvalidSpec(
            "jail id allows alphanumeric and hyphen only".into(),
        ));
    }
    Ok(())
}

/// cgroup v2 settings applied by the jailer `--cgroup` flag, derived from
/// the run's [`ResourceLimits`].
///
/// - `memory.max`: guest RAM plus VMM overhead (OOM kills the VMM, not the
///   host) — see [`host_memory_max_mib`];
/// - `cpu.max`: `<quota> <period>`; quota = vcpu * 100_000 (1 vcpu = 1 core).
/// - `pids.max`: host-side VMM thread cap (see [`vmm_pids_max`]) — this does
///   NOT count guest processes, so it is never set from
///   `ResourceLimits::max_processes` (which is not currently enforced for
///   guest processes in this phase; see that field's docs).
/// - `memory.swap.max = 0`: no swap escape hatch.
pub fn cgroup_settings(limits: &ResourceLimits) -> Vec<(String, String)> {
    let memory_max = format!("{}M", host_memory_max_mib(limits));
    let cpu_quota = limits.vcpu.max(1) as u64 * 100_000;
    vec![
        ("memory.max".into(), memory_max),
        ("memory.swap.max".into(), "0".into()),
        ("cpu.max".into(), format!("{cpu_quota} 100000")),
        ("pids.max".into(), vmm_pids_max(limits.vcpu).to_string()),
    ]
}

/// Resource limits applied by the jailer `--resource-limit` flag
/// (RLIMIT_* on the VMM process itself).
pub fn resource_limits() -> Vec<(String, String)> {
    vec![
        // Bound open FDs. (jailer v1.10.1 only supports fsize and no-file;
        // core dumps are disabled via the guest kernel cmdline instead.)
        ("no-file".into(), "1024".into()),
    ]
}

/// Build the full jailer argv (excluding argv[0]).
///
/// We intentionally do NOT pass `--daemonize`: sandboxd supervises the
/// jailer as a child process so crashes are observed and the pid is known.
/// Reconciliation covers the SIGKILL case via `/proc` scanning.
pub fn jailer_argv(spec: &JailSpec, fc_args: &[String]) -> Result<Vec<String>, SandboxdError> {
    validate_jail_id(&spec.id)?;
    // The jailer requires --parent-cgroup to be a relative path (relative
    // to the cgroup v2 mount). The JailSpec stores the absolute host path;
    // strip the /sys/fs/cgroup prefix here. A parent OUTSIDE /sys/fs/cgroup
    // is rejected: silently reinterpreting it (e.g. `/custom/lumen` ->
    // `custom/lumen`, which the jailer resolves under /sys/fs/cgroup) would
    // put the VMM and our limit files in different cgroups, so kill and
    // metering would act on the wrong cgroup.
    let parent_cgroup_rel = spec
        .cgroup_parent
        .strip_prefix("/sys/fs/cgroup")
        .map_err(|_| {
            SandboxdError::InvalidSpec(format!(
                "cgroup_parent must be under /sys/fs/cgroup, got {}",
                spec.cgroup_parent.display()
            ))
        })?;
    let parent_cgroup_rel = parent_cgroup_rel.display().to_string();
    let parent_cgroup_rel = parent_cgroup_rel.trim_start_matches('/').to_string();
    let mut argv = vec![
        "--id".into(),
        spec.id.clone(),
        "--exec-file".into(),
        spec.firecracker_bin.display().to_string(),
        "--uid".into(),
        spec.uid.to_string(),
        "--gid".into(),
        spec.gid.to_string(),
        "--chroot-base-dir".into(),
        spec.chroot_base.display().to_string(),
        "--cgroup-version".into(),
        "2".into(),
        "--parent-cgroup".into(),
        parent_cgroup_rel,
        "--netns".into(),
        spec.netns_path.display().to_string(),
        "--new-pid-ns".into(),
    ];
    for (file, value) in cgroup_settings(&spec.limits) {
        argv.push("--cgroup".into());
        argv.push(format!("{file}={value}"));
    }
    for (resource, value) in resource_limits() {
        argv.push("--resource-limit".into());
        argv.push(format!("{resource}={value}"));
    }
    argv.push("--".into());
    argv.extend(fc_args.iter().cloned());
    Ok(argv)
}

/// Firecracker argv (passed after jailer's `--`).
///
/// No `--seccomp-filter`: Firecracker's flag accepts only bincode-serialized
/// binary filters, not JSON, so a custom JSON filter can never load. With
/// neither `--seccomp-filter` nor `--no-seccomp`, Firecracker installs its
/// default compiled-in filters for the pinned release (default action trap,
/// fail-closed), which is exactly the posture a hand-rolled filter would
/// try to replicate -- vetted by the Firecracker team instead of us.
pub fn firecracker_argv(api_sock_in_jail: &Path, config_in_jail: &Path) -> Vec<String> {
    vec![
        "--api-sock".into(),
        api_sock_in_jail.display().to_string(),
        "--config-file".into(),
        config_in_jail.display().to_string(),
    ]
}

/// Minimal Firecracker config.json: machine, boot source, drives,
/// network interface, vsock. Sockets live inside the jail; the guest agent
/// channel is the vsock device.
///
/// Top-level keys are kebab-case (`machine-config`, `boot-source`,
/// `network-interfaces`) as Firecracker expects; the inner structs keep
/// snake_case fields (`vcpu_count`, `kernel_image_path`, ...), matching the
/// Firecracker API.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct FirecrackerConfig {
    pub machine_config: MachineConfig,
    pub boot_source: BootSource,
    pub drives: Vec<Drive>,
    pub network_interfaces: Vec<NetworkInterface>,
    pub vsock: Vsock,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MachineConfig {
    pub vcpu_count: u32,
    pub mem_size_mib: u64,
    /// Hide SMT / pin to a static CPU template for determinism.
    pub cpu_template: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BootSource {
    pub kernel_image_path: String,
    pub boot_args: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Drive {
    pub drive_id: String,
    pub path_on_host: String,
    pub is_root_device: bool,
    pub is_read_only: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkInterface {
    pub iface_id: String,
    pub host_dev_name: String,
    pub guest_mac: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Vsock {
    pub guest_cid: u32,
    pub uds_path: String,
}

/// Guest boot parameters baked into the kernel command line.
///
/// The guest's `/init` and the guest agent read these from `/proc/cmdline`
/// (`lumen.run_id=`, `lumen.guest_ip=`, ...). They are the only channel
/// that carries per-run addressing into the VM before the vsock handshake.
#[derive(Debug, Clone)]
pub struct GuestBootParams {
    pub run_id: String,
    pub guest_ip: String,
    pub host_ip: String,
    pub proxy_port: u16,
    pub vsock_port: u32,
}

/// Render the Firecracker config.json for one run.
///
/// Paths are jail-relative: the jailer hard-links the kernel/rootfs into
/// the chroot, so the config references `/vmlinux`, `/rootfs.ext4`, etc.
///
/// The workspace drive is a raw image: Firecracker's virtio-blk does not
/// understand qcow2, so the backend copies the (raw ext4) template to
/// `/workspace.raw` per run.
pub fn render_config(
    limits: &ResourceLimits,
    tap_name: &str,
    guest_mac: &str,
    boot: &GuestBootParams,
    snapshot: Option<&SnapshotLoad>,
) -> FirecrackerConfig {
    let _ = snapshot; // Snapshot restore uses the API load path, not config.
    let boot_args = format!(
        "console=ttyS0 reboot=k panic=1 pci=off ro init=/init \
         lumen.run_id={run_id} lumen.vsock_port={vsock_port} \
         lumen.guest_ip={guest_ip} lumen.host_ip={host_ip} \
         lumen.proxy_port={proxy_port}",
        run_id = boot.run_id,
        vsock_port = boot.vsock_port,
        guest_ip = boot.guest_ip,
        host_ip = boot.host_ip,
        proxy_port = boot.proxy_port,
    );
    FirecrackerConfig {
        machine_config: MachineConfig {
            vcpu_count: limits.vcpu.max(1),
            mem_size_mib: guest_mem_mib(limits),
            cpu_template: "None".into(),
        },
        boot_source: BootSource {
            kernel_image_path: "/vmlinux".into(),
            boot_args,
        },
        drives: vec![
            Drive {
                drive_id: "rootfs".into(),
                path_on_host: "/rootfs.ext4".into(),
                is_root_device: true,
                is_read_only: true,
            },
            Drive {
                drive_id: "workspace".into(),
                path_on_host: "/workspace.raw".into(),
                is_root_device: false,
                is_read_only: false,
            },
        ],
        network_interfaces: vec![NetworkInterface {
            iface_id: "eth0".into(),
            host_dev_name: tap_name.into(),
            guest_mac: guest_mac.into(),
        }],
        vsock: Vsock {
            guest_cid: 3,
            uds_path: "/v.sock".into(),
        },
    }
}

/// Deterministic guest MAC from the run tag (locally administered).
pub fn guest_mac(tag: &str) -> String {
    let mut bytes = [0u8; 6];
    bytes[0] = 0x02; // locally administered, unicast
    let digest = sha2::Sha256::digest(tag.as_bytes());
    bytes[1..].copy_from_slice(&digest[..5]);
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

/// Host-visible path of the pid file the jailer writes with `--new-pid-ns`:
/// `<chroot>/firecracker.pid`.
///
/// With `--new-pid-ns` the jailer clones into a new PID namespace, writes
/// the Firecracker child's (host-namespace) pid to this file, and then
/// EXITS (`exec_into_new_pid_ns` in the jailer source). The supervised
/// jailer child pid is therefore dead by the time anyone would signal it —
/// terminate the VMM via this file, never via the jailer pid.
pub fn firecracker_pid_file(chroot_base: &Path, exec_file: &Path, id: &str) -> PathBuf {
    jail_root(chroot_base, exec_file, id).join("firecracker.pid")
}

/// Files the jailer is expected to place in the chroot. Used by the
/// adversarial test "guest probes VMM socket": the API socket exists, but
/// only inside the jail, unreachable from the guest's network namespace
/// and invisible to the workload (no guest path leads to it).
pub fn expected_chroot_entries() -> Vec<&'static str> {
    vec![
        "firecracker",      // exec-file copy
        "firecracker.json", // written by the backend (matches --config-file)
        "vmlinux",          // hard-linked
        "rootfs.ext4",      // hard-linked
        "workspace-template.raw",
        "workspace.raw", // per-run sparse copy of the template
        "fc-api.sock",   // created by firecracker at runtime (--api-sock)
        "v.sock",        // created by firecracker at runtime
        // Written by the jailer with --new-pid-ns (host-namespace pid of
        // the Firecracker child); the VMM termination path reads it.
        "firecracker.pid",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> JailSpec {
        JailSpec {
            id: "lmn-abc12345".into(),
            uid: 61001,
            gid: 61001,
            chroot_base: PathBuf::from("/srv/jailer"),
            netns_path: PathBuf::from("/var/run/netns/lmn-abc12345"),
            firecracker_bin: PathBuf::from("/usr/local/bin/firecracker"),
            firecracker_version: "v1.10.1".into(),
            limits: crate::contracts::ResourceLimits {
                vcpu: 2,
                memory_mib: 1024,
                wall_time_secs: 120,
                max_processes: 64,
                disk_mib: 2048,
                max_output_bytes: 65536,
            },
            cgroup_parent: PathBuf::from("/sys/fs/cgroup/lumen"),
            snapshot: None,
        }
    }

    #[test]
    fn jailer_argv_has_defense_in_depth_flags() {
        let s = spec();
        let fc = firecracker_argv(Path::new("/api.sock"), Path::new("/config.json"));
        let argv = jailer_argv(&s, &fc).unwrap();
        let joined = argv.join(" ");
        for flag in [
            "--id",
            "--exec-file",
            "--uid",
            "--gid",
            "--chroot-base-dir",
            "--cgroup-version",
            "--netns",
            "--new-pid-ns",
        ] {
            assert!(argv.contains(&flag.to_string()), "missing {flag}");
        }
        // No --daemonize: sandboxd supervises the child.
        assert!(!argv.contains(&"--daemonize".to_string()));
        // cgroup v2, not v1.
        let pos = argv.iter().position(|a| a == "--cgroup-version").unwrap();
        assert_eq!(argv[pos + 1], "2");
        // Quotas present: memory.max = guest RAM (1024) + VMM overhead (128).
        assert!(joined.contains("memory.max=1152M"));
        // pids.max is the host-side VMM thread cap (32 + 8*vcpu), not the
        // guest process limit.
        assert!(joined.contains("pids.max=48"));
        assert!(joined.contains("cpu.max=200000 100000"));
        assert!(joined.contains("memory.swap.max=0"));
        // No `core` resource limit: jailer v1.10.1 only accepts fsize and
        // no-file (`jailer --help`); passing core=0 makes the jailer exit
        // with an argument error.
        assert!(!joined.contains("core="));
        // Firecracker args after `--`: no --seccomp-filter (Firecracker
        // only accepts binary filters; it uses its default trap-by-default
        // filters when the flag is absent).
        let dash = argv.iter().position(|a| a == "--").unwrap();
        assert!(!argv[dash + 1..].contains(&"--seccomp-filter".to_string()));
        assert!(argv[dash + 1..].contains(&"--api-sock".to_string()));
        assert!(argv[dash + 1..].contains(&"--config-file".to_string()));
    }

    #[test]
    fn rejects_bad_jail_ids() {
        assert!(validate_jail_id("lmn-abc123").is_ok());
        assert!(validate_jail_id("").is_err());
        assert!(validate_jail_id(&"x".repeat(65)).is_err());
        assert!(validate_jail_id("lmn_abc").is_err());
        assert!(validate_jail_id("../../etc").is_err());
    }

    #[test]
    fn rejects_cgroup_parent_outside_sys_fs_cgroup() {
        let s = spec();
        let fc = firecracker_argv(Path::new("/api.sock"), Path::new("/config.json"));
        // /sys/fs/cgroup/lumen -> "lumen".
        let argv = jailer_argv(&s, &fc).unwrap();
        let pos = argv.iter().position(|a| a == "--parent-cgroup").unwrap();
        assert_eq!(argv[pos + 1], "lumen");

        // Outside /sys/fs/cgroup: reject instead of silently reinterpreting
        // (the old fallback passed `custom/lumen` to the jailer, which
        // resolves it under /sys/fs/cgroup while we applied limits to
        // /custom/lumen/<id> — VMM and limits in different cgroups).
        let mut bad = s.clone();
        bad.cgroup_parent = PathBuf::from("/custom/lumen");
        assert!(jailer_argv(&bad, &fc).is_err());
        bad.cgroup_parent = PathBuf::from("lumen");
        assert!(jailer_argv(&bad, &fc).is_err());
    }

    #[test]
    fn firecracker_pid_file_lives_in_the_jail_root() {
        let p = firecracker_pid_file(
            Path::new("/srv/jailer"),
            Path::new("/usr/local/bin/firecracker"),
            "lmn-abc12345",
        );
        // exec_file_name falls back to the literal file name when the path
        // does not exist on this machine.
        assert_eq!(
            p,
            PathBuf::from("/srv/jailer/firecracker/lmn-abc12345/root/firecracker.pid")
        );
        assert!(expected_chroot_entries().contains(&"firecracker.pid"));
    }

    #[test]
    fn guest_mac_is_locally_administered_and_deterministic() {
        let a = guest_mac("abc12345");
        let b = guest_mac("abc12345");
        let c = guest_mac("zzz99999");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("02:"));
        assert_eq!(a.len(), 17);
    }

    #[test]
    fn render_config_is_read_only_root() {
        let boot = GuestBootParams {
            run_id: "lmn-abc12345".into(),
            guest_ip: "10.244.0.2".into(),
            host_ip: "10.244.0.1".into(),
            proxy_port: 18080,
            vsock_port: 1234,
        };
        let cfg = render_config(
            &spec().limits,
            "lmnt-abc1234",
            "02:aa:bb:cc:dd:ee",
            &boot,
            None,
        );
        let root = cfg.drives.iter().find(|d| d.is_root_device).unwrap();
        assert!(root.is_read_only);
        let ws = cfg
            .drives
            .iter()
            .find(|d| d.drive_id == "workspace")
            .unwrap();
        assert!(!ws.is_read_only && !ws.is_root_device);
        // Raw image: Firecracker's virtio-blk cannot read qcow2.
        assert_eq!(ws.path_on_host, "/workspace.raw");
        assert_eq!(cfg.network_interfaces.len(), 1);
        // The guest boots into /init (mounts, network setup), which execs
        // the agent; the run identity travels on the kernel command line.
        let args = &cfg.boot_source.boot_args;
        assert!(args.contains("init=/init"), "boot_args: {args}");
        assert!(
            args.contains("lumen.run_id=lmn-abc12345"),
            "boot_args: {args}"
        );
        assert!(
            args.contains("lumen.guest_ip=10.244.0.2"),
            "boot_args: {args}"
        );
        assert!(
            args.contains("lumen.host_ip=10.244.0.1"),
            "boot_args: {args}"
        );
        assert!(args.contains("lumen.proxy_port=18080"), "boot_args: {args}");
        assert!(args.contains("lumen.vsock_port=1234"), "boot_args: {args}");
        // Guest RAM is clamped to Firecracker's 64 MiB minimum.
        assert_eq!(cfg.machine_config.mem_size_mib, 1024);
    }

    #[test]
    fn chroot_contains_no_host_secrets_or_control_paths() {
        // The adversarial test "guest probes VMM socket" relies on this:
        // the chroot allowlist has no host paths, no kernel API socket
        // outside the jail, and nothing the guest can reach.
        let entries = expected_chroot_entries();
        for e in &entries {
            assert!(!e.contains(".."), "path traversal in {e}");
            assert!(!e.starts_with('/'), "absolute path in {e}");
        }
        assert!(!entries.contains(&"token"));
        assert!(!entries.contains(&"sandboxd.sock"));
    }
}
