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

use ed25519_dalek::SigningKey;
use lumen_core::pi_boundary::{
    NetworkResource, OutputChunk, OutputSink, SandboxDriver, SandboxProfile, SandboxQuotas,
    SandboxSpec, StreamStats,
};
use lumen_sandboxd::config::{
    ApiConfig, DaemonConfig, FirecrackerConfig, HostLimits, ImageConfig, NetConfig, ProxyConfig,
    SecretsConfig, StateConfig, UidPoolConfig,
};
use lumen_sandboxd::driver::{Driver, FirecrackerBackend, VmBackend};
use lumen_sandboxd::provenance::ImageManifest;
use lumen_sandboxd::state::RunStore;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

/// Fail the gate on a host that cannot run these tests. A silent
/// `std::process::exit(0)` would report "all tests passed" on a
/// misconfigured runner and hide the missing coverage.
fn require_kvm() {
    if !PathBuf::from("/dev/kvm").exists() {
        panic!("SKIP-REFUSED: /dev/kvm not present; failing the gate instead of reporting green");
    }
    if unsafe { libc::getuid() } != 0 {
        panic!("SKIP-REFUSED: must run as root; failing the gate instead of reporting green");
    }
}

// ---------------------------------------------------------------------------
// Fixture: ephemeral signed test image + Driver config.
// ---------------------------------------------------------------------------

struct Fixture {
    dir: PathBuf,
    config: DaemonConfig,
    image_digest: String,
}

static FIXTURE: OnceLock<Fixture> = OnceLock::new();

fn fixture() -> &'static Fixture {
    FIXTURE.get_or_init(|| build_fixture().expect("fixture setup failed"))
}

fn build_fixture() -> Result<Fixture, String> {
    // Short temp dir under /var/tmp (NOT /tmp): Unix socket paths (API
    // socket, vsock) must fit in SUN_LEN (108 chars), and /tmp is mounted
    // `nodev` -- the jailer's /dev/kvm and /dev/net/tun device nodes
    // cannot be opened on a nodev filesystem (EACCES on open).
    let dir = PathBuf::from(format!("/var/tmp/lkt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir:?}: {e}"))?;

    // Ephemeral Ed25519 keypair. The verifying key is stored as 32 raw
    // bytes, which `provenance::load_verifying_key` accepts.
    let seed: [u8; 32] = {
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom").map_err(|e| format!("urandom: {e}"))?;
        let mut buf = [0u8; 32];
        f.read_exact(&mut buf)
            .map_err(|e| format!("urandom read: {e}"))?;
        buf
    };
    let signing_key = SigningKey::from_bytes(&seed);
    let verify_key_path = dir.join("test-verify.key");
    // Write as 64-char hex (load_verifying_key accepts hex or raw bytes;
    // raw bytes may not be valid UTF-8 for its read_to_string probe).
    std::fs::write(
        &verify_key_path,
        hex::encode(signing_key.verifying_key().to_bytes()),
    )
    .map_err(|e| format!("write verify key: {e}"))?;

    // Test image: reuse the prebuilt artifacts from the fixture build.
    // Set LUMEN_KVM_GUEST_OUT to the directory containing manifest.json,
    // vmlinux, rootfs.ext4, and workspace-template.raw.
    let img_src = PathBuf::from(std::env::var("LUMEN_KVM_GUEST_OUT").map_err(|_| {
        "LUMEN_KVM_GUEST_OUT not set; build the guest image with scripts/sandbox/build-guest.sh"
            .to_string()
    })?);
    if !img_src.join("manifest.json").exists() {
        return Err(format!(
            "test image not found at {img_src:?}; build it with scripts/sandbox/build-guest.sh"
        ));
    }
    let manifest_text = std::fs::read_to_string(img_src.join("manifest.json"))
        .map_err(|e| format!("read manifest: {e}"))?;
    let mut manifest: ImageManifest =
        serde_json::from_str(&manifest_text).map_err(|e| format!("parse manifest: {e}"))?;
    manifest
        .sign(&signing_key)
        .map_err(|e| format!("sign manifest: {e}"))?;
    let image_digest = manifest
        .image_digest()
        .map_err(|e| format!("image digest: {e}"))?;

    // Sanity: the signature must verify against our key.
    let vk = lumen_sandboxd::provenance::load_verifying_key(&verify_key_path)
        .map_err(|e| format!("load verify key: {e}"))?;
    manifest
        .verify(&[vk])
        .map_err(|e| format!("self-verify: {e}"))?;

    // Store layout: <store>/<digest>/{manifest.json,vmlinux,rootfs.ext4,workspace-template.raw}
    let store = dir.join("images");
    let store_img = store.join(&image_digest);
    std::fs::create_dir_all(&store_img).map_err(|e| format!("mkdir store: {e}"))?;
    let manifest_out =
        serde_json::to_string_pretty(&manifest).map_err(|e| format!("ser manifest: {e}"))?;
    std::fs::write(store_img.join("manifest.json"), manifest_out)
        .map_err(|e| format!("write manifest: {e}"))?;
    for name in ["vmlinux", "rootfs.ext4", "workspace-template.raw"] {
        std::fs::copy(img_src.join(name), store_img.join(name))
            .map_err(|e| format!("copy {name}: {e}"))?;
    }

    // Daemon config wired to the fixture.
    let state_dir = dir.join("state");
    std::fs::create_dir_all(&state_dir).map_err(|e| format!("mkdir state: {e}"))?;
    // Short binary names: the jailer uses the --exec-file *file name*
    // (after canonicalization) as the chroot path element, and Unix socket
    // paths must fit in SUN_LEN (108). Copy the versioned binaries to
    // short names under the fixture dir.
    let bin_dir = dir.join("bin");
    std::fs::create_dir_all(&bin_dir).map_err(|e| format!("mkdir bin: {e}"))?;
    // Set LUMEN_KVM_DL_DIR to the directory containing the Firecracker/jailer
    // binaries (firecracker-v1.10.1-x86_64, jailer-v1.10.1-x86_64).
    let dl = PathBuf::from(std::env::var("LUMEN_KVM_DL_DIR").map_err(|_| {
        "LUMEN_KVM_DL_DIR not set; download Firecracker v1.10.1 binaries".to_string()
    })?);
    let fc_bin = bin_dir.join("firecracker");
    std::fs::copy(dl.join("firecracker-v1.10.1-x86_64"), &fc_bin)
        .map_err(|e| format!("copy firecracker: {e}"))?;
    let jailer_bin = bin_dir.join("jailer");
    std::fs::copy(dl.join("jailer-v1.10.1-x86_64"), &jailer_bin)
        .map_err(|e| format!("copy jailer: {e}"))?;
    let config = DaemonConfig {
        state: StateConfig { dir: state_dir },
        api: ApiConfig {
            socket: dir.join("api.sock"),
            token_file: dir.join("api.token"),
            allowed_uids: vec![0],
        },
        firecracker: FirecrackerConfig {
            binary: fc_bin,
            jailer: jailer_bin,
            chroot_base: dir.join("chroot"),
            version: "1.10.1".to_string(),
        },
        images: ImageConfig {
            store,
            trusted_keys: vec![verify_key_path],
            policy_version: "v1".to_string(),
        },
        net: NetConfig {
            pod_cidr: "10.244.0.0/16".to_string(),
            upstream_dns: "8.8.8.8".to_string(),
            ..Default::default()
        },
        uid_pool: UidPoolConfig {
            start: 200000,
            end: 200099,
        },
        limits: HostLimits::default(),
        proxy: ProxyConfig::default(),
        secrets: SecretsConfig::default(),
    };

    Ok(Fixture {
        dir,
        config,
        image_digest,
    })
}

/// Fresh Driver per test (isolated RunStore).
fn test_driver(fx: &Fixture, test_name: &str) -> Driver {
    let store_dir = fx.dir.join(format!("store-{test_name}"));
    std::fs::create_dir_all(&store_dir).expect("mkdir store");
    let mut config = fx.config.clone();
    config.state.dir = store_dir.join("state");
    std::fs::create_dir_all(&config.state.dir).expect("mkdir state");
    let store = RunStore::open(&store_dir).expect("open RunStore");
    let backend: Arc<dyn VmBackend> = Arc::new(FirecrackerBackend);
    Driver::new(config, store, backend).expect("Driver::new")
}

struct VecSink {
    chunks: Vec<OutputChunk>,
}

impl OutputSink for VecSink {
    fn push(&mut self, chunk: OutputChunk) {
        self.chunks.push(chunk);
    }
}

impl VecSink {
    fn stdout_text(&self) -> String {
        let mut s = String::new();
        for c in &self.chunks {
            if c.stream == "stdout" {
                s.push_str(&String::from_utf8_lossy(&c.bytes));
            }
        }
        s
    }
}

/// Prepare, start, stream to completion, destroy. Returns stdout.
async fn run_guest(
    driver: &Driver,
    image_digest: &str,
    command: Vec<String>,
    egress_allowlist: Vec<NetworkResource>,
) -> Result<String, String> {
    let spec = SandboxSpec {
        version: 1,
        profile: SandboxProfile::Strict,
        image_digest: image_digest.to_string(),
        command,
        quotas: SandboxQuotas {
            memory_mb: 256,
            vcpus: 1,
            wall_time_ms: 60000,
            output_bytes: 1024 * 1024,
        },
        egress_allowlist,
    };
    let handle = driver
        .prepare(&spec)
        .await
        .map_err(|e| format!("prepare: {e:?}"))?;
    driver
        .start(&handle)
        .await
        .map_err(|e| format!("start: {e:?}"))?;
    let mut sink = VecSink { chunks: vec![] };
    let _stats: StreamStats = driver
        .stream(&handle, &mut sink)
        .await
        .map_err(|e| format!("stream: {e:?}"))?;
    let stdout = sink.stdout_text();
    driver
        .destroy(&handle)
        .await
        .map_err(|e| format!("destroy: {e:?}"))?;
    Ok(stdout)
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Runtime::new().unwrap().block_on(f)
}

fn sh_cmd(script: &str) -> Vec<String> {
    vec![
        "/bin/busybox".into(),
        "sh".into(),
        "-c".into(),
        script.into(),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Boot a VM, run the agent handshake, and verify basic liveness.
#[test]
fn kvm_boot_and_handshake() {
    require_kvm();
    let fx = fixture();
    let driver = test_driver(fx, "boot_handshake");
    let stdout = block_on(run_guest(
        &driver,
        &fx.image_digest,
        sh_cmd("echo handshake-ok"),
        vec![],
    ))
    .expect("run_guest");
    assert!(
        stdout.contains("handshake-ok"),
        "expected handshake-ok in stdout, got: {stdout:?}"
    );
}

/// Default-deny: the guest cannot reach the internet.
#[test]
fn kvm_default_deny_network() {
    require_kvm();
    let fx = fixture();
    let driver = test_driver(fx, "default_deny");
    let stdout = block_on(run_guest(
        &driver,
        &fx.image_digest,
        sh_cmd("/bin/busybox wget -T 5 -O - http://example.com 2>&1 | head -5; echo wget-done"),
        vec![],
    ))
    .expect("run_guest");
    assert!(
        stdout.contains("wget-done"),
        "run did not complete: {stdout:?}"
    );
    assert!(
        !stdout.contains("Example Domain"),
        "default-deny violated: fetched example.com: {stdout:?}"
    );
}

/// Proxy: allowlisted CONNECT succeeds, others get 403.
#[test]
#[ignore = "host egress proxy is not functional (DNS/proxy binding broken); cannot verify allowlist enforcement"]
fn kvm_proxy_allowlist() {
    require_kvm();
}

/// Metadata endpoint is unreachable.
#[test]
fn kvm_metadata_denied() {
    require_kvm();
    let fx = fixture();
    let driver = test_driver(fx, "metadata_denied");
    let stdout = block_on(run_guest(
        &driver,
        &fx.image_digest,
        sh_cmd("/bin/busybox wget -T 5 -O - http://169.254.169.254/latest/meta-data/ 2>&1 | head -5; echo done"),
        vec![],
    ))
    .expect("run_guest");
    assert!(
        !stdout.contains("ami-id") && !stdout.contains("instance-id"),
        "metadata endpoint reachable: {stdout:?}"
    );
}

/// DNS rebinding to private IPs is blocked.
#[test]
#[ignore = "host DNS forwarder/proxy not functional; cannot verify rebinding protection"]
fn kvm_dns_rebinding_blocked() {
    require_kvm();
}

/// Fork bomb is contained by cgroup pids.max.
#[test]
fn kvm_fork_bomb_contained() {
    require_kvm();
    let fx = fixture();
    let driver = test_driver(fx, "fork_bomb");
    let host_load_before: f64 = std::fs::read_to_string("/proc/loadavg")
        .unwrap_or_default()
        .split_whitespace()
        .next()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0.0);
    let stdout = block_on(run_guest(
        &driver,
        &fx.image_digest,
        sh_cmd("timeout 10 /bin/busybox sh -c ':(){ :|:& };:' 2>&1 | head -3; echo bomb-done"),
        vec![],
    ))
    .expect("run_guest");
    assert!(
        stdout.contains("bomb-done"),
        "run did not complete after fork bomb: {stdout:?}"
    );
    let host_load_after: f64 = std::fs::read_to_string("/proc/loadavg")
        .unwrap_or_default()
        .split_whitespace()
        .next()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0.0);
    assert!(
        host_load_after < host_load_before + 10.0,
        "host load spiked: before={host_load_before}, after={host_load_after}"
    );
}

/// Disk fill is contained by the workspace quota.
#[test]
fn kvm_disk_fill_contained() {
    require_kvm();
    let fx = fixture();
    let driver = test_driver(fx, "disk_fill");
    // Try to write 600M into the 512M workspace disk. The disk itself is the
    // containment boundary: dd must hit ENOSPC and the file must not exceed
    // the 512M disk.
    let stdout = block_on(run_guest(
        &driver,
        &fx.image_digest,
        sh_cmd("echo start; /bin/busybox dd if=/dev/zero of=/workspace/fill bs=1M count=600 oflag=direct 2>&1; echo dd-done; /bin/busybox du -m /workspace/fill 2>&1 | head -1; echo fill-done"),
        vec![],
    ))
    .expect("run_guest");
    assert!(
        stdout.contains("fill-done"),
        "run did not complete: {stdout:?}"
    );
    assert!(
        stdout.contains("No space left") || stdout.contains("no space"),
        "expected ENOSPC when overfilling the 512M workspace disk, got: {stdout:?}"
    );
    for line in stdout.lines() {
        if line.contains("/workspace/fill")
            && let Some(mb_str) = line.split_whitespace().next()
            && let Ok(mb) = mb_str.parse::<u64>()
        {
            assert!(mb <= 512, "disk not contained: fill grew to {mb}M");
        }
    }
}

/// Killing sandboxd mid-run: reconciliation reclaims.
#[test]
#[ignore = "daemon reconciliation path not implemented/verified; requires exercising the daemon, not just Driver"]
fn kvm_restart_reclaims() {
    require_kvm();
}

/// Orphaned netns/TAPs/cgroups are swept on startup.
#[test]
#[ignore = "daemon startup sweep not implemented/verified; requires exercising the daemon, not just Driver"]
fn kvm_orphan_sweep() {
    require_kvm();
}

/// Guest cannot access the Firecracker API socket.
#[test]
fn kvm_vmm_socket_isolated() {
    require_kvm();
    let fx = fixture();
    let driver = test_driver(fx, "vmm_isolated");
    let stdout = block_on(run_guest(
        &driver,
        &fx.image_digest,
        sh_cmd("ls -la /run/ /tmp/ 2>&1 | head -30; echo scan-done"),
        vec![],
    ))
    .expect("run_guest");
    assert!(
        stdout.contains("scan-done"),
        "run did not complete: {stdout:?}"
    );
    // The API socket is `fc-api.sock` and the vsock socket is `v.sock`
    // (see jailer::expected_chroot_entries); asserting on the names the
    // implementation actually uses so the check cannot pass vacuously.
    assert!(
        !stdout.contains("fc-api.sock"),
        "VMM API socket visible in guest: {stdout:?}"
    );
    assert!(
        !stdout.contains("v.sock"),
        "VMM vsock socket visible in guest: {stdout:?}"
    );
}

/// Export: files are staged, hashed, and validated.
#[test]
fn kvm_export_validated() {
    require_kvm();
    let fx = fixture();
    let driver = test_driver(fx, "export_validated");
    block_on(async {
        let spec = SandboxSpec {
            version: 1,
            profile: SandboxProfile::Strict,
            image_digest: fx.image_digest.clone(),
            command: sh_cmd(
                "echo hello > /workspace/ok.txt; ln -s /etc/passwd /workspace/evil-link; echo done",
            ),
            quotas: SandboxQuotas {
                memory_mb: 256,
                vcpus: 1,
                wall_time_ms: 60000,
                output_bytes: 1024 * 1024,
            },
            egress_allowlist: vec![],
        };
        let handle = driver.prepare(&spec).await.expect("prepare");
        driver.start(&handle).await.expect("start");
        let mut sink = VecSink { chunks: vec![] };
        driver.stream(&handle, &mut sink).await.expect("stream");
        let exported = driver.export(&handle).await.expect("export");
        driver.destroy(&handle).await.expect("destroy");

        let paths: Vec<&str> = exported.iter().map(|f| f.path.as_str()).collect();
        assert!(
            paths.iter().any(|p| p.ends_with("ok.txt")),
            "ok.txt not exported: {paths:?}"
        );
        assert!(
            !paths.iter().any(|p| p.contains("evil-link")),
            "symlink attack was exported: {paths:?}"
        );
    });
}

/// After destroy, no artifacts remain.
#[test]
fn kvm_cleanup_complete() {
    require_kvm();
    let fx = fixture();
    let driver = test_driver(fx, "cleanup_complete");
    block_on(async {
        let spec = SandboxSpec {
            version: 1,
            profile: SandboxProfile::Strict,
            image_digest: fx.image_digest.clone(),
            command: sh_cmd("echo cleanup-test"),
            quotas: SandboxQuotas {
                memory_mb: 256,
                vcpus: 1,
                wall_time_ms: 60000,
                output_bytes: 1024 * 1024,
            },
            egress_allowlist: vec![],
        };
        let handle = driver.prepare(&spec).await.expect("prepare");
        let run_id = handle.run_id.to_string();
        driver.start(&handle).await.expect("start");
        let mut sink = VecSink { chunks: vec![] };
        driver.stream(&handle, &mut sink).await.expect("stream");
        driver.destroy(&handle).await.expect("destroy");

        let out = std::process::Command::new("ip")
            .args(["netns", "list"])
            .output()
            .expect("ip netns");
        let netns = String::from_utf8_lossy(&out.stdout);
        assert!(!netns.contains(&run_id[..8]), "netns leaked: {netns:?}");

        let out = std::process::Command::new("ip")
            .args(["link", "show"])
            .output()
            .expect("ip link");
        let links = String::from_utf8_lossy(&out.stdout);
        assert!(!links.contains(&run_id[..8]), "TAP leaked");

        let chroot_base = &fx.config.firecracker.chroot_base;
        // Leaked per-run jail dirs live under
        // <chroot_base>/<exec_file_name>/ (jailer::jail_parent), not at the
        // top level of chroot_base, so scan the right directory.
        let jail_parent =
            lumen_sandboxd::jailer::jail_parent(chroot_base, &fx.config.firecracker.binary);
        if jail_parent.exists() {
            for entry in std::fs::read_dir(&jail_parent).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name().to_string_lossy().to_string();
                assert!(!name.contains(&run_id), "jail dir leaked: {name:?}");
            }
        }
        // The jailer diagnostic logs (jailer-<id>.log, jailer-cmd-<id>.log)
        // live directly in the chroot base.
        if chroot_base.exists() {
            for entry in std::fs::read_dir(chroot_base).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name().to_string_lossy().to_string();
                assert!(!name.contains(&run_id), "jailer log leaked: {name:?}");
            }
        }
    });
}
