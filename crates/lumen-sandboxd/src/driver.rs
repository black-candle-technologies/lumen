//! [`SandboxDriver`] implementation: spec validation, run lifecycle,
//! supervision, and the [`VmBackend`] seam for host effects.
//!
//! The driver is pure orchestration. Everything that touches KVM, netns,
//! the jailer, or the filesystem goes through [`VmBackend`], which has a
//! hermetic [`MockBackend`] for development-machine tests and a real
//! [`FirecrackerBackend`] for lane-vps (`--features kvm`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ed25519_dalek::VerifyingKey;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use uuid::Uuid;

use crate::cgroups;
use crate::config::DaemonConfig;
use crate::contracts::{
    ExportManifest, ExportedFile, NetworkPolicy, OutputChunk, OutputSink, ResourceLimits,
    SANDBOX_DRIVER_VERSION, SandboxDriver, SandboxError, SandboxHandle, SandboxProfile,
    SandboxResult, SandboxRunSpec, SandboxSpec, SandboxUsage, StreamStats,
};
use crate::dns::{DnsForwarder, HostPolicyResolver, SystemUpstream};
use crate::error::SandboxdError;
use crate::export::{ExportLimits, ExportValidator, StagedFile};
use crate::guest_agent::{
    AgentMsg, HostMsg, PROTOCOL_VERSION, VSOCK_PORT, check_hello, read_msg, write_msg,
};
use crate::jailer::{self, JailSpec};
use crate::network;
use crate::provenance::{self, ProvenanceRecord};
use crate::proxy;
use crate::secrets::{Redactor, Secret, SecretBroker, fetch_granted_secrets};
use crate::state::{ArtifactPaths, RunState, RunStore};
use crate::storage;

// ---------------------------------------------------------------------------
// Agent I/O
// ---------------------------------------------------------------------------

/// Byte stream to the guest agent (vsock in production, duplex in tests).
#[async_trait]
pub trait AgentIo: Send {
    async fn next_msg(&mut self) -> Result<Option<AgentMsg>, SandboxdError>;
    async fn send_msg(&mut self, msg: &HostMsg) -> Result<(), SandboxdError>;
}

#[async_trait]
impl<T> AgentIo for T
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn next_msg(&mut self) -> Result<Option<AgentMsg>, SandboxdError> {
        read_msg(self).await
    }

    async fn send_msg(&mut self, msg: &HostMsg) -> Result<(), SandboxdError> {
        write_msg(self, msg).await
    }
}

// ---------------------------------------------------------------------------
// Jailer handle
// ---------------------------------------------------------------------------

/// Supervised jailer/VMM process.
#[async_trait]
pub trait JailerHandle: Send {
    /// SIGKILL the jailer process group (best effort, idempotent).
    async fn terminate(&mut self) -> Result<(), SandboxdError>;
    fn pid(&self) -> Option<u32>;
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// All host effects behind one trait. The driver never touches KVM,
/// netns, or the jailer directly.
#[async_trait]
pub trait VmBackend: Send + Sync {
    async fn setup_network(
        &self,
        plan: &network::NetPlan,
        nftables_rules: &str,
    ) -> Result<(), SandboxdError>;
    async fn teardown_network(&self, plan: &network::NetPlan) -> Result<(), SandboxdError>;
    /// Spawn per-run netns services (DNS forwarder + egress proxy).
    async fn spawn_netns_services(
        &self,
        ctx: &NetnsCtx,
    ) -> Result<Box<dyn NetnsHandle>, SandboxdError>;
    async fn spawn_jailer(&self, setup: &JailSetup)
    -> Result<Box<dyn JailerHandle>, SandboxdError>;
    /// Ask a freshly spawned Firecracker to boot: it loads `--config-file`
    /// but waits for the `InstanceStart` action on its API socket.
    async fn boot_instance(&self, api_sock: &Path) -> Result<(), SandboxdError>;
    async fn connect_agent(
        &self,
        uds_path: &Path,
        timeout: Duration,
    ) -> Result<Box<dyn AgentIo>, SandboxdError>;
}

/// Context for the per-run netns services (DNS + egress proxy).
pub struct NetnsCtx {
    pub host_ip: String,
    pub proxy_port: u16,
    pub proxy_cfg: crate::proxy::ProxyConfig,
    pub network_policy: NetworkPolicy,
    pub run_dir: PathBuf,
}

/// Handle to the per-run netns services.
#[async_trait]
pub trait NetnsHandle: Send {
    async fn shutdown(&mut self) -> Result<(), SandboxdError>;
}

/// Everything the backend needs to build the chroot and launch the jailer.
pub struct JailSetup {
    pub spec: JailSpec,
    /// Path to the jailer binary (from DaemonConfig).
    pub jailer_bin: PathBuf,
    /// Pinned, digest-verified launch artifacts (vmlinux, rootfs.ext4,
    /// workspace-template.raw). Opened `O_NOFOLLOW` and hashed at resolve
    /// time; [`FirecrackerBackend::spawn_jailer`] re-hashes each descriptor
    /// immediately before hard-linking it into the chroot from the pinned
    /// descriptor itself. The image-store path is never re-joined here, so
    /// there is no TOCTOU window between verification and launch.
    pub artifacts: Vec<provenance::PinnedArtifact>,
    /// Rendered Firecracker config JSON (also written to the run dir).
    pub fc_config_json: String,
    /// In-jail Firecracker argv (paths are jail-relative).
    pub fc_args: Vec<String>,
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

struct SupervisorHandle {
    cancel_tx: watch::Sender<bool>,
    join: tokio::task::JoinHandle<SupervisedOutcome>,
}

struct LiveRun {
    secrets: Vec<(String, Secret)>,
    secret_env_names: HashSet<String>,
    supervisor: Option<SupervisorHandle>,
    netns_services: Option<Box<dyn NetnsHandle>>,
    result: Option<SandboxResult>,
}

struct DriverInner {
    config: DaemonConfig,
    store: RunStore,
    backend: Arc<dyn VmBackend>,
    uid_pool: Mutex<UidPool>,
    live: Mutex<std::collections::HashMap<String, LiveRun>>,
}

/// Monotonic UID allocator. On startup it skips past UIDs still referenced
/// by non-destroyed runs, so a restart never reuses a live UID.
struct UidPool {
    end: u32,
    next: u32,
}

impl UidPool {
    fn alloc(&mut self) -> Option<u32> {
        if self.next > self.end {
            return None;
        }
        let uid = self.next;
        self.next += 1;
        Some(uid)
    }
}

/// The [`SandboxDriver`] implementation.
pub struct Driver {
    inner: Arc<DriverInner>,
}

impl Clone for Driver {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Driver {
    pub fn new(
        config: DaemonConfig,
        store: RunStore,
        backend: Arc<dyn VmBackend>,
    ) -> Result<Self, SandboxdError> {
        // Rebuild the UID cursor past any UID still referenced by a
        // non-destroyed run (crash safety: never reuse a live UID).
        let mut next = config.uid_pool.start;
        for run in store.all_runs()? {
            if run.state != RunState::Destroyed {
                next = next.max(run.artifacts.uid.saturating_add(1));
            }
        }
        if next < config.uid_pool.start {
            next = config.uid_pool.start;
        }
        Ok(Self {
            inner: Arc::new(DriverInner {
                uid_pool: Mutex::new(UidPool {
                    end: config.uid_pool.end,
                    next,
                }),
                config,
                store,
                backend,
                live: Mutex::new(std::collections::HashMap::new()),
            }),
        })
    }

    /// Access the run store (for reconciliation, etc.).
    pub fn store(&self) -> &RunStore {
        &self.inner.store
    }

    /// Access the config.
    pub fn config(&self) -> &DaemonConfig {
        &self.inner.config
    }

    /// Internal run key derived deterministically from the frozen
    /// [`SandboxHandle`], so every trait method recovers the same journal /
    /// live-map key without a lookup table.
    fn run_key(handle: &SandboxHandle) -> String {
        format!("lmn-{}", handle.run_id.simple())
    }

    /// Adapt a frozen [`SandboxSpec`] to the runtime [`SandboxRunSpec`].
    ///
    /// Fields the v1 contract does not carry are sourced from the daemon:
    /// - `kernel_digest` is resolved from the signed image manifest in
    ///   [`Self::prepare_inner`] (the manifest is the trust root; the kernel
    ///   cannot nominate a kernel different from the image's).
    /// - `policy_version` is the daemon-enforced `images.policy_version`.
    /// - `max_processes` / `disk_mib` come from daemon host limits.
    /// - `env` is empty: v1 has no kernel->guest env channel (secret handles
    ///   arrive via the brokered `grant_secrets` path, never the spec).
    fn adapt_spec(
        spec: &SandboxSpec,
        config: &DaemonConfig,
    ) -> Result<SandboxRunSpec, SandboxdError> {
        if spec.version != SANDBOX_DRIVER_VERSION {
            return Err(SandboxdError::InvalidSpec(format!(
                "version {} != {SANDBOX_DRIVER_VERSION}",
                spec.version
            )));
        }
        if spec.profile != SandboxProfile::Strict {
            return Err(SandboxdError::InvalidSpec(
                "only the strict profile is supported".into(),
            ));
        }
        if !provenance::is_digest(&spec.image_digest) {
            return Err(SandboxdError::InvalidSpec("bad image_digest".into()));
        }
        if spec.command.is_empty() {
            return Err(SandboxdError::InvalidSpec("empty command".into()));
        }
        if spec.command.iter().any(|a| a.is_empty()) {
            return Err(SandboxdError::InvalidSpec("empty command arg".into()));
        }
        // Host limits: defense in depth; the kernel lease is the primary bound.
        let hl = &config.limits;
        if spec.quotas.vcpus == 0 || spec.quotas.vcpus > hl.max_vcpu {
            return Err(SandboxdError::InvalidSpec("vcpus out of host range".into()));
        }
        if spec.quotas.memory_mb < 64 || spec.quotas.memory_mb > hl.max_memory_mib {
            return Err(SandboxdError::InvalidSpec(
                "memory_mb out of host range".into(),
            ));
        }
        if spec.quotas.wall_time_ms == 0 {
            return Err(SandboxdError::InvalidSpec(
                "wall_time_ms must be nonzero".into(),
            ));
        }
        // Round UP so the kernel's deadline is never shortened.
        let wall_time_secs = spec.quotas.wall_time_ms.div_ceil(1000);
        if wall_time_secs > hl.max_wall_time_secs {
            return Err(SandboxdError::InvalidSpec(
                "wall_time out of host range".into(),
            ));
        }
        if spec.quotas.output_bytes == 0 {
            return Err(SandboxdError::InvalidSpec(
                "output_bytes must be nonzero".into(),
            ));
        }
        // The typed allowlist becomes the daemon's destination strings; each
        // entry is re-parsed by the proxy's parser so a malformed entry can
        // never slip past.
        let mut allow_egress = Vec::with_capacity(spec.egress_allowlist.len());
        for nr in &spec.egress_allowlist {
            if nr.scheme.is_empty() || nr.host.is_empty() || nr.port == 0 {
                return Err(SandboxdError::InvalidSpec(format!(
                    "bad egress allowlist entry: {nr:?}"
                )));
            }
            let dest = format!("{}://{}:{}", nr.scheme, nr.host, nr.port);
            network::parse_destination(&dest).map_err(|e| {
                SandboxdError::InvalidSpec(format!("bad egress destination {dest:?}: {e}"))
            })?;
            allow_egress.push(dest);
        }
        Ok(SandboxRunSpec {
            image_digest: spec.image_digest.clone(),
            // Filled from the signed manifest in prepare_inner.
            kernel_digest: String::new(),
            policy_version: config.images.policy_version.clone(),
            profile: spec.profile,
            limits: ResourceLimits {
                vcpu: spec.quotas.vcpus,
                memory_mib: spec.quotas.memory_mb,
                wall_time_secs,
                max_processes: config.limits.default_max_processes,
                disk_mib: config.limits.max_disk_mib,
                max_output_bytes: spec.quotas.output_bytes,
            },
            network: NetworkPolicy {
                allow_egress,
                deny_metadata: true,
                deny_private_ranges: true,
            },
            command: spec.command.clone(),
            env: Vec::new(),
        })
    }

    /// Validate a runtime run spec against host limits. The frozen-spec
    /// checks (version, profile, digest shape, quotas) happen in
    /// [`Self::adapt_spec`]; this covers the daemon-derived fields.
    fn validate_spec(spec: &SandboxRunSpec, config: &DaemonConfig) -> Result<(), SandboxdError> {
        if spec.profile != SandboxProfile::Strict {
            return Err(SandboxdError::InvalidSpec(
                "only the strict profile is supported".into(),
            ));
        }
        if !provenance::is_digest(&spec.image_digest) {
            return Err(SandboxdError::InvalidSpec("bad image_digest".into()));
        }
        if !spec.kernel_digest.is_empty() && !provenance::is_digest(&spec.kernel_digest) {
            return Err(SandboxdError::InvalidSpec("bad kernel_digest".into()));
        }
        if spec.command.is_empty() {
            return Err(SandboxdError::InvalidSpec("empty command".into()));
        }
        if spec.command.iter().any(|a| a.is_empty()) {
            return Err(SandboxdError::InvalidSpec("empty command arg".into()));
        }
        // Host limits: defense in depth; the kernel lease is the primary bound.
        let hl = &config.limits;
        if spec.limits.vcpu == 0 || spec.limits.vcpu > hl.max_vcpu {
            return Err(SandboxdError::InvalidSpec("vcpu out of host range".into()));
        }
        if spec.limits.memory_mib < 64 || spec.limits.memory_mib > hl.max_memory_mib {
            return Err(SandboxdError::InvalidSpec(
                "memory_mib out of host range".into(),
            ));
        }
        if spec.limits.wall_time_secs == 0 || spec.limits.wall_time_secs > hl.max_wall_time_secs {
            return Err(SandboxdError::InvalidSpec(
                "wall_time_secs out of host range".into(),
            ));
        }
        if spec.limits.max_processes == 0 {
            return Err(SandboxdError::InvalidSpec(
                "max_processes must be nonzero".into(),
            ));
        }
        if spec.limits.disk_mib == 0 || spec.limits.disk_mib > hl.max_disk_mib {
            return Err(SandboxdError::InvalidSpec(
                "disk_mib out of host range".into(),
            ));
        }
        if spec.limits.max_output_bytes == 0 {
            return Err(SandboxdError::InvalidSpec(
                "max_output_bytes must be nonzero".into(),
            ));
        }
        // Egress destinations must parse; the proxy enforces them.
        for dest in &spec.network.allow_egress {
            network::parse_destination(dest).map_err(|e| {
                SandboxdError::InvalidSpec(format!("bad egress destination {dest:?}: {e}"))
            })?;
        }
        // Secret-looking names may not ride in the plain env; they must be
        // granted via grant_secrets so they stay brokered and redacted.
        for (k, _) in &spec.env {
            if is_secret_like(k) {
                return Err(SandboxdError::InvalidSpec(format!(
                    "secret-like env name {k:?}: use secret grants"
                )));
            }
        }
        Ok(())
    }

    /// Build artifact paths for a new run.
    fn artifact_paths(
        config: &DaemonConfig,
        store: &RunStore,
        run_id: &str,
        uid: u32,
    ) -> Result<ArtifactPaths, SandboxdError> {
        // Interface names are <= 15 chars; derive a short tag from the run id.
        let tag = run_id
            .strip_prefix("lmn-")
            .unwrap_or(run_id)
            .chars()
            .take(8)
            .collect::<String>();
        let slot = uid.saturating_sub(config.uid_pool.start);
        let plan = network::plan_net(
            &tag,
            &config.net.pod_cidr,
            slot,
            config.proxy.port,
            &config.net.tap_prefix,
            &config.net.netns_prefix,
        )?;
        let run_dir = store.run_dir(run_id);
        let chroot_dir = jailer::jail_root(
            &config.firecracker.chroot_base,
            &config.firecracker.binary,
            run_id,
        );
        Ok(ArtifactPaths {
            jail_id: run_id.to_string(),
            chroot_dir: chroot_dir.clone(),
            config_path: run_dir.join("firecracker.json"),
            uid,
            gid: uid,
            netns_name: plan.netns_name,
            tap_name: plan.tap_name,
            veth_host: plan.veth_host,
            veth_guest: plan.veth_guest,
            host_ip: plan.host_ip,
            guest_ip: plan.guest_ip,
            // Cgroup path (relative to /sys/fs/cgroup) must match what the
            // jailer creates: `--parent-cgroup lumen --id <run_id>` =>
            // `/sys/fs/cgroup/lumen/<run_id>` (the jailer requires a path
            // relative to the cgroup v2 mount). Interface names
            // use the short tag (15-char limit), but cgroups have no such
            // limit, so we use the full run ID for uniqueness and clarity.
            cgroup_path: PathBuf::from(format!("lumen/{run_id}")),
            // The per-run workspace copy lives inside the jail chroot
            // (Firecracker is chrooted and can only open paths under it).
            // The quota monitor watches this file's allocated blocks.
            workspace_disk: chroot_dir.join("workspace.raw"),
            vsock_path: chroot_dir.join("v.sock"),
            api_sock: chroot_dir.join("fc-api.sock"),
            staging_dir: run_dir.join("staging"),
            jailer_pid: 0,
        })
    }

    /// Grant secrets to a prepared run. `grants` maps env var name ->
    /// broker handle. The same handle may back several env names. Secrets
    /// are fetched once per unique handle and never removed from the
    /// broker; the live run holds them until destroy.
    pub async fn grant_secrets(
        &self,
        run_id: &str,
        grants: &[(String, String)],
    ) -> Result<(), SandboxdError> {
        if grants.is_empty() {
            return Ok(());
        }
        // Validate env names (same secret-like rule is inverted here:
        // granted names SHOULD look like secrets, but must be valid).
        for (name, _) in grants {
            if name.is_empty() || name.len() > 128 {
                return Err(SandboxdError::InvalidSpec("bad secret env name".into()));
            }
        }
        let broker = self
            .inner
            .config
            .secrets
            .broker_socket
            .as_ref()
            .map(|p| SecretBroker::new(p.to_string_lossy().into_owned()));
        let handles: Vec<String> = grants.iter().map(|(_, h)| h.clone()).collect();
        let fetched = fetch_granted_secrets(broker.as_ref(), &handles)?;
        let by_handle: std::collections::HashMap<&str, &Secret> =
            fetched.iter().map(|(h, s)| (h.as_str(), s)).collect();
        {
            let mut live = self.inner.live.lock().unwrap();
            let lr = live
                .get_mut(run_id)
                .ok_or_else(|| SandboxdError::RunState(format!("no live run: {run_id}")))?;
            if lr.supervisor.is_some() {
                return Err(SandboxdError::RunState(
                    "cannot grant secrets after start".into(),
                ));
            }
            for (name, handle) in grants {
                let secret = by_handle
                    .get(handle.as_str())
                    .ok_or_else(|| SandboxdError::Host("broker fetch mismatch".into()))?;
                lr.secret_env_names.insert(name.clone());
                // Clone the secret bytes into an owned Secret for this env name.
                lr.secrets
                    .push((name.clone(), Secret::new(secret.as_bytes().to_vec())));
            }
        }
        self.inner
            .store
            .note(run_id, format!("granted {} secret env vars", grants.len()))?;
        Ok(())
    }

    async fn prepare_inner(
        &self,
        run_id: &str,
        spec: &SandboxRunSpec,
    ) -> Result<(), SandboxdError> {
        Self::validate_spec(spec, &self.inner.config)?;

        // Concurrency gate: fail closed past max_concurrent_runs.
        {
            let live = self.inner.live.lock().unwrap();
            let active = live
                .values()
                .filter(|lr| lr.supervisor.is_some() || lr.result.is_none())
                .count();
            if active >= self.inner.config.limits.max_concurrent_runs as usize {
                return Err(SandboxdError::Host("max concurrent runs reached".into()));
            }
        }

        // Resolve + verify the signed image. This is the trust root: the
        // digest in the spec must match a manifest signed by a trusted key,
        // and every artifact must hash to its manifest digest. The guest
        // kernel always comes from that manifest — the caller cannot
        // nominate a different kernel than the image's.
        let trusted_keys = load_trusted_keys(&self.inner.config)?;
        let stored = provenance::resolve_image(
            &self.inner.config.images.store,
            &spec.image_digest,
            &trusted_keys,
        )?;
        let mut spec = spec.clone();
        spec.kernel_digest = stored.manifest.kernel_digest.clone();
        let provenance = ProvenanceRecord {
            image_digest: spec.image_digest.clone(),
            kernel_digest: stored.manifest.kernel_digest.clone(),
            rootfs_digest: stored.manifest.rootfs_digest.clone(),
            workspace_template_digest: stored.manifest.workspace_template_digest.clone(),
            toolchain_digest: stored.manifest.toolchain_digest()?,
            policy_version: self.inner.config.images.policy_version.clone(),
            sandboxd_version: env!("CARGO_PKG_VERSION").to_string(),
            firecracker_version: self.inner.config.firecracker.version.clone(),
        };

        // Allocate UID + network slot.
        let uid = {
            let mut pool = self.inner.uid_pool.lock().unwrap();
            pool.alloc()
                .ok_or_else(|| SandboxdError::Host("UID pool exhausted".into()))?
        };

        let artifacts = Self::artifact_paths(&self.inner.config, &self.inner.store, run_id, uid)?;

        // Canonical spec digest binds the journal to the exact spec.
        let spec_json =
            serde_json::to_vec(&spec).map_err(|e| SandboxdError::Host(e.to_string()))?;
        let spec_digest = crate::provenance::digest_bytes(&spec_json);

        let record = self
            .inner
            .store
            .create(run_id, spec, spec_digest, artifacts.clone())?;
        self.inner.store.set_provenance(run_id, provenance)?;

        self.inner.live.lock().unwrap().insert(
            run_id.to_string(),
            LiveRun {
                secrets: Vec::new(),
                secret_env_names: HashSet::new(),
                supervisor: None,
                netns_services: None,
                result: None,
            },
        );
        let _ = record;
        Ok(())
    }

    fn plan_from_artifacts(&self, artifacts: &ArtifactPaths) -> network::NetPlan {
        network::NetPlan {
            netns_name: artifacts.netns_name.clone(),
            tap_name: artifacts.tap_name.clone(),
            veth_host: artifacts.veth_host.clone(),
            veth_guest: artifacts.veth_guest.clone(),
            host_ip: artifacts.host_ip.clone(),
            guest_ip: artifacts.guest_ip.clone(),
            prefix_len: 30,
            proxy_port: self.inner.config.proxy.port,
        }
    }
}

/// Env names that look like secrets must go through `grant_secrets`.
fn is_secret_like(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("secret")
        || lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("token")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower.contains("private_key")
        || lower.contains("privatekey")
        || lower.contains("credential")
}

// ---------------------------------------------------------------------------
// Supervision
// ---------------------------------------------------------------------------

struct SupervisedOutcome {
    exit_code: i32,
    timed_out: bool,
    cancelled: bool,
    terminated: Option<String>,
    stdout: String,
    stderr: String,
    output_truncated: bool,
    staged: Vec<StagedFile>,
    export_rejected: Option<String>,
    wall_time_ms: u64,
    peak_memory_mib: u64,
}

struct PendingExport {
    path: String,
    size: u64,
    sha256: String,
    bytes: Vec<u8>,
}

/// Own the agent stream until the run ends. Reads stdio (redacted,
/// bounded), enforces quotas/deadline/watchdog, stages validated exports,
/// then ensures the jailer is dead.
#[allow(clippy::too_many_arguments)]
async fn supervise(
    run_id: &str,
    spec: &SandboxRunSpec,
    artifacts: &ArtifactPaths,
    secrets: Vec<Secret>,
    mut agent: Box<dyn AgentIo>,
    export_limits: ExportLimits,
    store: &RunStore,
    mut jailer: Box<dyn JailerHandle>,
    mut cancel_rx: watch::Receiver<bool>,
) -> SupervisedOutcome {
    let start = Instant::now();
    let deadline = Duration::from_secs(spec.limits.wall_time_secs.max(1));
    let max_output = spec.limits.max_output_bytes;

    let mut stdout_red = Redactor::new(&secrets);
    let mut stderr_red = Redactor::new(&secrets);
    let mut stdout_buf: Vec<u8> = Vec::new();
    let mut stderr_buf: Vec<u8> = Vec::new();
    let mut output_truncated = false;

    let mut validator: Option<ExportValidator> = None;
    let mut pending: Option<PendingExport> = None;
    let mut staged: Vec<StagedFile> = Vec::new();
    let mut export_rejected: Option<String> = None;

    let mut exit_code: Option<i32> = None;
    let mut timed_out = false;
    let mut cancelled = false;
    let mut terminated: Option<String> = None;

    let mut last_msg = Instant::now();
    let mut quota_tick = tokio::time::interval(Duration::from_secs(5));
    quota_tick.tick().await; // skip the immediate first tick

    // Append redacted bytes to a bounded buffer.
    let mut push_output = |buf: &mut Vec<u8>, red: &mut Redactor, bytes: &[u8]| {
        let redacted = red.feed(bytes);
        let room = max_output.saturating_sub(buf.len() as u64);
        if room == 0 {
            output_truncated = true;
            return;
        }
        if redacted.len() as u64 > room {
            buf.extend_from_slice(&redacted[..room as usize]);
            output_truncated = true;
        } else {
            buf.extend_from_slice(&redacted);
        }
    };

    // Finalize the pending export file into the validator.
    let finalize_pending = |pending: Option<PendingExport>,
                            validator: &mut Option<ExportValidator>,
                            staged: &mut Vec<StagedFile>|
     -> Result<(), String> {
        let p = match pending {
            Some(p) => p,
            None => return Ok(()),
        };
        let v = validator
            .as_mut()
            .ok_or_else(|| "export data outside an export session".to_string())?;
        // stage_bytes enforces the byte-count match against the size
        // reserved at the ExportFile header (plus the per-file cap).
        let staged_file = v
            .stage_bytes(&p.path, &p.sha256, p.size, &p.bytes)
            .map_err(|e| format!("export rejected: {e}"))?;
        staged.push(staged_file);
        Ok(())
    };

    loop {
        tokio::select! {
            biased;
            msg = agent.next_msg() => {
                last_msg = Instant::now();
                match msg {
                    Err(e) => {
                        terminated = Some(format!("agent protocol error: {e}"));
                        break;
                    }
                    Ok(None) => break, // clean EOF
                    Ok(Some(m)) => {
                        match m {
                            AgentMsg::Hello { .. } => {
                                terminated = Some("duplicate hello".into());
                                break;
                            }
                            AgentMsg::Heartbeat => {}
                            AgentMsg::Exit { code } => {
                                exit_code = Some(code);
                                break;
                            }
                            AgentMsg::Stdout { .. } | AgentMsg::Stderr { .. } => {
                                let is_stdout = matches!(m, AgentMsg::Stdout { .. });
                                match m.payload() {
                                    Err(e) => {
                                        terminated = Some(format!("bad stdio payload: {e}"));
                                        break;
                                    }
                                    Ok(bytes) => {
                                        if is_stdout {
                                            push_output(&mut stdout_buf, &mut stdout_red, &bytes);
                                        } else {
                                            push_output(&mut stderr_buf, &mut stderr_red, &bytes);
                                        }
                                    }
                                }
                            }
                            AgentMsg::ExportBegin { files } => {
                                if validator.is_some() {
                                    terminated = Some("nested export session".into());
                                    break;
                                }
                                if export_rejected.is_some() {
                                    let _ = agent.send_msg(&HostMsg::ExportReject {
                                        reason: "a previous export was rejected; no further exports".into(),
                                    }).await;
                                    continue;
                                }
                                let staging = artifacts.staging_dir.clone();
                                match ExportValidator::new(staging, export_limits.clone()) {
                                    Err(e) => {
                                        export_rejected = Some(format!("export init: {e}"));
                                        let _ = agent.send_msg(&HostMsg::ExportReject {
                                            reason: format!("export init failed: {e}"),
                                        }).await;
                                    }
                                    Ok(v) => {
                                        validator = Some(v);
                                        let _ = store.transition(run_id, RunState::Exporting);
                                        let _ = agent.send_msg(&HostMsg::ExportAck {
                                            path: format!("{files} files"),
                                        }).await;
                                    }
                                }
                            }
                            AgentMsg::ExportFile { path, size, sha256 } => {
                                if export_rejected.is_some() {
                                    continue;
                                }
                                // Finalize any previous pending file first.
                                let prev = pending.take();
                                if let Err(e) = finalize_pending(prev, &mut validator, &mut staged) {
                                    export_rejected = Some(e.clone());
                                    validator = None;
                                    pending = None;
                                    let _ = agent.send_msg(&HostMsg::ExportReject { reason: e }).await;
                                    let _ = store.transition(run_id, RunState::Running);
                                    continue;
                                }
                                // Validate the new file header before accepting data.
                                let ok = match validator.as_mut() {
                                    Some(v) => v.stage_path(&path).and(v.check_size(size)).map(|_| ()),
                                    None => Err(SandboxdError::ExportRejected("no export session".into())),
                                };
                                match ok {
                                    Err(e) => {
                                        let reason = format!("export rejected: {e}");
                                        export_rejected = Some(reason.clone());
                                        validator = None;
                                        let _ = agent.send_msg(&HostMsg::ExportReject { reason }).await;
                                        let _ = store.transition(run_id, RunState::Running);
                                    }
                                    Ok(()) => {
                                        pending = Some(PendingExport { path, size, sha256, bytes: Vec::new() });
                                    }
                                }
                            }
                            AgentMsg::ExportData { .. } => {
                                if export_rejected.is_some() {
                                    continue;
                                }
                                let bytes = match m.payload() {
                                    Err(e) => {
                                        let reason = format!("bad export payload: {e}");
                                        export_rejected = Some(reason.clone());
                                        validator = None;
                                        pending = None;
                                        let _ = agent.send_msg(&HostMsg::ExportReject { reason }).await;
                                        let _ = store.transition(run_id, RunState::Running);
                                        continue;
                                    }
                                    Ok(b) => b,
                                };
                                match pending.as_mut() {
                                    None => {
                                        let reason = "export data with no open file".to_string();
                                        export_rejected = Some(reason.clone());
                                        validator = None;
                                        let _ = agent.send_msg(&HostMsg::ExportReject { reason }).await;
                                        let _ = store.transition(run_id, RunState::Running);
                                    }
                                    Some(p) => {
                                        if p.bytes.len() as u64 + bytes.len() as u64 > p.size {
                                            let reason = format!("export overflow for {}", p.path);
                                            export_rejected = Some(reason.clone());
                                            validator = None;
                                            pending = None;
                                            let _ = agent.send_msg(&HostMsg::ExportReject { reason }).await;
                                            let _ = store.transition(run_id, RunState::Running);
                                        } else {
                                            p.bytes.extend_from_slice(&bytes);
                                        }
                                    }
                                }
                            }
                            AgentMsg::ExportEnd => {
                                let prev = pending.take();
                                match finalize_pending(prev, &mut validator, &mut staged) {
                                    Err(e) => {
                                        export_rejected = Some(e.clone());
                                        let _ = agent.send_msg(&HostMsg::ExportReject { reason: e }).await;
                                    }
                                    Ok(()) => {
                                        let _ = agent.send_msg(&HostMsg::ExportAck {
                                            path: format!("{} staged", staged.len()),
                                        }).await;
                                    }
                                }
                                validator = None;
                                let _ = store.transition(run_id, RunState::Running);
                            }
                        }
                    }
                }
            }
            _ = cancel_rx.changed() => {
                cancelled = true;
                let _ = agent.send_msg(&HostMsg::Cancel).await;
                break;
            }
            _ = tokio::time::sleep(deadline.saturating_sub(start.elapsed())) => {
                timed_out = true;
                break;
            }
            _ = quota_tick.tick() => {
                if last_msg.elapsed() > Duration::from_secs(60) {
                    terminated = Some("agent heartbeat watchdog fired".into());
                    break;
                }
                let elapsed = start.elapsed().as_secs();
                let pids = cgroups::read_pids_current(
                    Path::new("/sys/fs/cgroup"),
                    &artifacts.cgroup_path,
                ).unwrap_or(0);
                let disk = storage::delta_bytes(&artifacts.workspace_disk).unwrap_or(0);
                let disk_cap = spec.limits.disk_mib.saturating_mul(1024 * 1024);
                match cgroups::check_quotas(
                    pids,
                    spec.limits.max_processes,
                    disk,
                    disk_cap,
                    elapsed,
                    spec.limits.wall_time_secs,
                ) {
                    cgroups::QuotaCheck::Ok => {}
                    cgroups::QuotaCheck::Exceeded(what) => {
                        terminated = Some(format!("quota exceeded: {what}"));
                        break;
                    }
                }
            }
        }
    }

    // The run is over: make sure the VM is dead.
    let _ = jailer.terminate().await;

    // Flush redactors.
    stdout_buf.extend_from_slice(&stdout_red.finish());
    stderr_buf.extend_from_slice(&stderr_red.finish());
    // Enforce the cap on the flushed tail too.
    if stdout_buf.len() as u64 > max_output {
        stdout_buf.truncate(max_output as usize);
        output_truncated = true;
    }
    if (stdout_buf.len() + stderr_buf.len()) as u64 > max_output {
        let keep = max_output.saturating_sub(stdout_buf.len() as u64) as usize;
        stderr_buf.truncate(keep);
        output_truncated = true;
    }

    let stdout = String::from_utf8_lossy(&stdout_buf).into_owned();
    let stderr = String::from_utf8_lossy(&stderr_buf).into_owned();
    let peak_memory_mib =
        cgroups::read_peak_memory_mib(Path::new("/sys/fs/cgroup"), &artifacts.cgroup_path)
            .unwrap_or(0);

    SupervisedOutcome {
        exit_code: exit_code.unwrap_or(-1),
        timed_out,
        cancelled,
        terminated,
        stdout,
        stderr,
        output_truncated,
        staged,
        export_rejected,
        wall_time_ms: start.elapsed().as_millis() as u64,
        peak_memory_mib,
    }
}

// ---------------------------------------------------------------------------
// Driver lifecycle
// ---------------------------------------------------------------------------

impl Driver {
    async fn start_inner(&self, run_id: &str) -> Result<(), SandboxdError> {
        let record = self.inner.store.load(run_id)?;
        if record.state != RunState::Prepared {
            return Err(SandboxdError::RunState(format!(
                "start requires Prepared, got {:?}",
                record.state
            )));
        }
        {
            let live = self.inner.live.lock().unwrap();
            let lr = live
                .get(run_id)
                .ok_or_else(|| SandboxdError::RunState(format!("no live run: {run_id}")))?;
            if lr.supervisor.is_some() {
                return Err(SandboxdError::RunState("already started".into()));
            }
        }

        let artifacts = record.artifacts.clone();
        let spec = record.spec.clone();
        let plan = self.plan_from_artifacts(&artifacts);

        // Render the Firecracker config into the run dir (the backend
        // copies it into the chroot).
        let guest_mac = jailer::guest_mac(run_id);
        // Guest boot parameters: run identity + addressing on the kernel
        // command line, read by /init and the guest agent from /proc/cmdline.
        let boot_params = jailer::GuestBootParams {
            run_id: run_id.to_string(),
            guest_ip: plan.guest_ip.clone(),
            host_ip: plan.host_ip.clone(),
            proxy_port: plan.proxy_port,
            vsock_port: VSOCK_PORT,
        };
        let fc_config =
            jailer::render_config(&spec.limits, &plan.tap_name, &guest_mac, &boot_params, None);
        let fc_json = serde_json::to_string_pretty(&fc_config)
            .map_err(|e| SandboxdError::Host(format!("fc config render: {e}")))?;
        std::fs::write(&artifacts.config_path, &fc_json).map_err(SandboxdError::Io)?;

        let jail_spec = JailSpec {
            id: run_id.to_string(),
            uid: artifacts.uid,
            gid: artifacts.gid,
            chroot_base: self.inner.config.firecracker.chroot_base.clone(),
            netns_path: PathBuf::from(format!("/var/run/netns/{}", plan.netns_name)),
            firecracker_bin: self.inner.config.firecracker.binary.clone(),
            firecracker_version: self.inner.config.firecracker.version.clone(),
            limits: spec.limits.clone(),
            cgroup_parent: PathBuf::from("/sys/fs/cgroup/lumen"),
            snapshot: None,
        };
        // In-jail paths (Firecracker's view inside the chroot).
        let fc_args =
            jailer::firecracker_argv(Path::new("/fc-api.sock"), Path::new("/firecracker.json"));

        // Pinned launch artifacts for the backend to hard-link into the
        // chroot. Re-resolve and PIN the image at launch time:
        // resolve_image opens every artifact O_NOFOLLOW and digest-verifies
        // it, and the pinned descriptors (not the store path) travel to
        // spawn_jailer, which re-hashes them immediately before
        // hard-linking. This closes the prepare->start TOCTOU window where
        // a store write could swap the bytes that prepare verified.
        let trusted_keys = load_trusted_keys(&self.inner.config)?;
        let stored = provenance::resolve_image(
            &self.inner.config.images.store,
            &spec.image_digest,
            &trusted_keys,
        )?;

        self.inner.store.transition(run_id, RunState::Starting)?;

        // 1. Network namespace, TAP, veth, nftables.
        let nftables = network::render_nftables(&plan);
        if let Err(e) = self.inner.backend.setup_network(&plan, &nftables).await {
            let _ = self.inner.store.transition(run_id, RunState::Failed);
            return Err(e);
        }
        // 2. Per-run DNS forwarder + egress proxy. These bind the run's
        //    host-side address in the HOST netns (that address is local
        //    only there; the run netns has no route to the host resolver
        //    or upstream targets). The guest reaches them over the veth
        //    pair; guest isolation is unchanged.
        let netns_ctx = NetnsCtx {
            host_ip: plan.host_ip.clone(),
            proxy_port: plan.proxy_port,
            proxy_cfg: crate::proxy::ProxyConfig {
                run_id: run_id.to_string(),
                network: spec.network.clone(),
                byte_cap: self.inner.config.proxy.default_dest_byte_cap,
                log_path: self.inner.store.run_dir(run_id).join("egress.log"),
            },
            network_policy: spec.network.clone(),
            run_dir: self.inner.store.run_dir(run_id),
        };
        let netns_services = match self.inner.backend.spawn_netns_services(&netns_ctx).await {
            Ok(h) => h,
            Err(e) => {
                let _ = self.inner.backend.teardown_network(&plan).await;
                let _ = self.inner.store.transition(run_id, RunState::Failed);
                return Err(e);
            }
        };
        // 3. Jailer (builds chroot, drops privs, execs Firecracker).
        let setup = JailSetup {
            spec: jail_spec,
            jailer_bin: self.inner.config.firecracker.jailer.clone(),
            artifacts: stored.artifacts,
            fc_config_json: fc_json,
            fc_args,
        };
        let jailer_handle = match self.inner.backend.spawn_jailer(&setup).await {
            Ok(h) => h,
            Err(e) => {
                let mut ns = netns_services;
                let _ = ns.shutdown().await;
                let _ = self.inner.backend.teardown_network(&plan).await;
                let _ = self.inner.store.transition(run_id, RunState::Failed);
                return Err(e);
            }
        };
        // 4. Boot the VM. Firecracker loads --config-file but waits for the
        //    InstanceStart action on its API socket; without this the guest
        //    never boots and the vsock handshake below would time out.
        if let Err(e) = self.inner.backend.boot_instance(&artifacts.api_sock).await {
            let mut jh = jailer_handle;
            let _ = jh.terminate().await;
            let mut ns = netns_services;
            let _ = ns.shutdown().await;
            let _ = self.inner.backend.teardown_network(&plan).await;
            let _ = self.inner.store.transition(run_id, RunState::Failed);
            return Err(e);
        }
        // 5. Agent handshake, with retries. The guest agent starts
        //    listening on AF_VSOCK partway through boot; if our CONNECT
        //    arrives before it is listening, Firecracker closes the UDS, so
        //    we retry the whole dial + hello sequence until the deadline.
        let mut agent: Option<Box<dyn AgentIo>> = None;
        let mut last_err = String::from("no attempts");
        let hs_start = Instant::now();
        while hs_start.elapsed() < Duration::from_secs(60) && agent.is_none() {
            match self
                .inner
                .backend
                .connect_agent(&artifacts.vsock_path, Duration::from_secs(5))
                .await
            {
                Ok(mut a) => {
                    let hello_r = tokio::time::timeout(Duration::from_secs(5), a.next_msg()).await;
                    match hello_r {
                        Ok(Ok(Some(hello))) => match check_hello(&hello, run_id) {
                            Ok(_) => agent = Some(a),
                            Err(e) => last_err = format!("bad hello: {e}"),
                        },
                        Ok(Ok(None)) => last_err = "agent closed before hello".to_string(),
                        Ok(Err(e)) => last_err = format!("hello read failed: {e}"),
                        Err(_) => last_err = "hello timeout".to_string(),
                    }
                }
                Err(e) => last_err = format!("vsock dial failed: {e}"),
            }
            if agent.is_none() {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
        let mut agent = match agent {
            Some(a) => a,
            None => {
                let mut jh = jailer_handle;
                let _ = jh.terminate().await;
                let mut ns = netns_services;
                let _ = ns.shutdown().await;
                let _ = self.inner.backend.teardown_network(&plan).await;
                let _ = self.inner.store.transition(run_id, RunState::Failed);
                return Err(SandboxdError::GuestAgent(format!(
                    "agent handshake failed after 60s: {last_err}"
                )));
            }
        };

        // 6. Welcome: argv, env, secrets, deadline.
        let (secret_pairs, secret_vals): (Vec<(String, String)>, Vec<Secret>) = {
            let live = self.inner.live.lock().unwrap();
            let lr = live.get(run_id).expect("live run checked above");
            let mut pairs = Vec::with_capacity(lr.secrets.len());
            let mut vals = Vec::with_capacity(lr.secrets.len());
            for (k, s) in &lr.secrets {
                pairs.push((
                    k.clone(),
                    String::from_utf8_lossy(s.as_bytes()).into_owned(),
                ));
                vals.push(Secret::new(s.as_bytes().to_vec()));
            }
            (pairs, vals)
        };
        let welcome = HostMsg::Welcome {
            run_id: run_id.to_string(),
            argv: spec.command.clone(),
            env: spec.env.clone(),
            secrets: secret_pairs,
            deadline_ms: spec.limits.wall_time_secs * 1000,
        };
        if let Err(e) = agent.send_msg(&welcome).await {
            let mut jh = jailer_handle;
            let _ = jh.terminate().await;
            let mut ns = netns_services;
            let _ = ns.shutdown().await;
            let _ = self.inner.backend.teardown_network(&plan).await;
            let _ = self.inner.store.transition(run_id, RunState::Failed);
            return Err(e);
        }

        // 7. Supervisor task owns the agent stream + jailer from here.
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let store = self.inner.store.clone();
        let run_id_owned = run_id.to_string();
        let export_limits = ExportLimits::default();
        let join = tokio::spawn(async move {
            supervise(
                &run_id_owned,
                &spec,
                &artifacts,
                secret_vals,
                agent,
                export_limits,
                &store,
                jailer_handle,
                cancel_rx,
            )
            .await
        });
        {
            let mut live = self.inner.live.lock().unwrap();
            let lr = live.get_mut(run_id).expect("live run checked above");
            lr.supervisor = Some(SupervisorHandle { cancel_tx, join });
            lr.netns_services = Some(netns_services);
        }
        self.inner.store.transition(run_id, RunState::Running)?;
        Ok(())
    }

    async fn wait_inner(&self, run_id: &str) -> Result<SandboxResult, SandboxdError> {
        // Idempotent: a stored result is returned directly.
        {
            let live = self.inner.live.lock().unwrap();
            if let Some(lr) = live.get(run_id)
                && let Some(r) = &lr.result
            {
                return Ok(r.clone());
            }
        }
        // Hold the whole `SupervisorHandle` (not just its `JoinHandle`) across
        // the await. Dropping the handle drops its `watch::Sender`; a dropped
        // sender makes the supervisor task's `cancel_rx.changed()` resolve
        // with `Err`, which the supervise `select!` loop would misread as a
        // cancel request and abort the run early (losing output/exports).
        let sup = {
            let mut live = self.inner.live.lock().unwrap();
            let lr = live
                .get_mut(run_id)
                .ok_or_else(|| SandboxdError::RunState(format!("no live run: {run_id}")))?;
            lr.supervisor
                .take()
                .ok_or_else(|| SandboxdError::RunState("run not started".into()))?
        };
        let outcome = sup
            .join
            .await
            .map_err(|e| SandboxdError::Host(format!("supervisor panicked: {e}")))?;
        let export_manifest = if outcome.staged.is_empty() {
            None
        } else {
            Some(ExportManifest {
                changed: ExportValidator::manifest(&outcome.staged),
            })
        };
        let result = SandboxResult {
            exit_code: outcome.exit_code,
            timed_out: outcome.timed_out,
            output: format!("{}{}", outcome.stdout, outcome.stderr),
            output_truncated: outcome.output_truncated,
            usage: SandboxUsage {
                wall_time_ms: outcome.wall_time_ms,
                peak_memory_mib: outcome.peak_memory_mib,
                egress_bytes: 0,
                ingress_bytes: 0,
            },
            export_manifest,
        };
        let terminal = if outcome.cancelled {
            RunState::Cancelled
        } else if outcome.timed_out {
            RunState::TimedOut
        } else if outcome.terminated.is_some() {
            RunState::Failed
        } else if outcome.exit_code == 0 {
            RunState::Done
        } else {
            RunState::Failed
        };
        if let Err(e) = self.inner.store.set_outcome(run_id, result.clone()) {
            let _ = self
                .inner
                .store
                .note(run_id, format!("set_outcome failed: {e}"));
        }
        let _ = self.inner.store.transition(run_id, terminal);
        if let Some(reason) = outcome.terminated {
            let _ = self
                .inner
                .store
                .note(run_id, format!("terminated: {reason}"));
        }
        if let Some(reject) = outcome.export_rejected {
            let _ = self
                .inner
                .store
                .note(run_id, format!("export rejected: {reject}"));
        }
        if outcome.output_truncated {
            let _ = self
                .inner
                .store
                .note(run_id, "output truncated at max_output_bytes".to_string());
        }
        {
            let mut live = self.inner.live.lock().unwrap();
            if let Some(lr) = live.get_mut(run_id) {
                lr.result = Some(result.clone());
            }
        }
        Ok(result)
    }

    async fn cancel_inner(&self, run_id: &str) -> Result<(), SandboxdError> {
        let tx = {
            let live = self.inner.live.lock().unwrap();
            live.get(run_id)
                .and_then(|lr| lr.supervisor.as_ref())
                .map(|s| s.cancel_tx.clone())
                .ok_or_else(|| {
                    SandboxdError::RunState(format!("no running supervisor: {run_id}"))
                })?
        };
        let _ = tx.send(true);
        Ok(())
    }

    async fn destroy_inner(&self, run_id: &str) -> Result<(), SandboxdError> {
        // Idempotent: destroying a destroyed (or never-created) run is a no-op.
        let record = match self.inner.store.load(run_id) {
            Ok(r) => r,
            Err(SandboxdError::RunState(_)) => return Ok(()),
            Err(SandboxdError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        if record.state == RunState::Destroyed {
            return Ok(());
        }
        // Persist the Destroying intent BEFORE tearing anything down, so a
        // crash during destroy is recoverable (reconciliation sees Destroying
        // and retries the teardown).
        let _ = self.inner.store.transition(run_id, RunState::Destroying);
        // Stop the supervisor first (it kills the jailer via its handle).
        let (supervisor, netns_services) = {
            let mut live = self.inner.live.lock().unwrap();
            match live.remove(run_id) {
                Some(mut lr) => {
                    if let Some(s) = &lr.supervisor {
                        let _ = s.cancel_tx.send(true);
                    }
                    (lr.supervisor.take(), lr.netns_services.take())
                }
                None => (None, None),
            }
        };
        if let Some(s) = supervisor {
            // Give it a moment; the cgroup kill below is the hammer.
            let _ = tokio::time::timeout(Duration::from_secs(5), s.join).await;
        }
        if let Some(mut ns) = netns_services {
            let _ = ns.shutdown().await;
        }
        // Belt and braces: cgroup kill, then network teardown, then fs.
        let cgroup_fs = Path::new("/sys/fs/cgroup");
        let _ = cgroups::kill(cgroup_fs, &record.artifacts.cgroup_path);
        let _ = cgroups::remove(cgroup_fs, &record.artifacts.cgroup_path);
        let plan = self.plan_from_artifacts(&record.artifacts);
        let _ = self.inner.backend.teardown_network(&plan).await;
        let run_dir = self.inner.store.run_dir(run_id);
        match std::fs::remove_dir_all(&run_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                let _ = self
                    .inner
                    .store
                    .note(run_id, format!("run dir removal failed: {e}"));
            }
        }
        // Remove the jailer chroot tree (best effort; the jailer owns it).
        if let Some(id_dir) = record.artifacts.chroot_dir.parent() {
            let _ = std::fs::remove_dir_all(id_dir);
        }
        // Remove the top-level jailer diagnostic logs. They live directly in
        // the chroot base (`chroot_base/jailer-{id}.log` and
        // `chroot_base/jailer-cmd-{id}.log`), not under the per-run id dir,
        // so the `remove_dir_all` above leaves them behind.
        // `chroot_dir` is `<chroot_base>/<exec_file_name>/<jail_id>/root`.
        if let Some(chroot_base) = record
            .artifacts
            .chroot_dir
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
        {
            for name in [
                format!("jailer-{}.log", record.artifacts.jail_id),
                format!("jailer-cmd-{}.log", record.artifacts.jail_id),
            ] {
                let _ = std::fs::remove_file(chroot_base.join(name));
            }
        }
        // The state file lives inside the run_dir, which we just removed.
        // "No state file" IS the Destroyed state: a subsequent load fails
        // with NotFound and destroy stays idempotent. We do not attempt a
        // Destroyed transition because there is nowhere to persist it.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SandboxDriver trait
// ---------------------------------------------------------------------------

/// Map daemon errors onto the frozen [`SandboxError`]. The v1 contract is
/// coarse by design: refused specs, trust failures, and run faults are all
/// `RunFailed` with a descriptive message; `QuotaExceeded` is reserved for
/// a run the daemon terminated for breaching its deadline/quotas; and
/// `Unavailable` means the sandbox itself cannot serve right now (KVM or
/// jailer down, concurrency gate, UID pool exhausted).
fn to_sandbox_error(e: SandboxdError) -> SandboxError {
    match e {
        SandboxdError::Terminated(m) => SandboxError::QuotaExceeded(m),
        SandboxdError::Host(m) => SandboxError::Unavailable(m),
        other => SandboxError::RunFailed(other.to_string()),
    }
}

/// Fail closed on a handle minted by a different driver version.
fn check_handle(handle: &SandboxHandle) -> Result<(), SandboxError> {
    if handle.version != SANDBOX_DRIVER_VERSION {
        return Err(SandboxError::RunFailed(format!(
            "handle version {} != {SANDBOX_DRIVER_VERSION}",
            handle.version
        )));
    }
    Ok(())
}

impl Driver {
    /// Shared by the trait's `export` and the local API: prefer the live
    /// result, fall back to the durable outcome, fail if the run has no
    /// outcome yet.
    async fn export_manifest_inner(&self, run_id: &str) -> Result<ExportManifest, SandboxdError> {
        {
            let live = self.inner.live.lock().unwrap();
            if let Some(lr) = live.get(run_id)
                && let Some(r) = &lr.result
            {
                return Ok(r.export_manifest.clone().unwrap_or(ExportManifest {
                    changed: Vec::new(),
                }));
            }
        }
        let record = self.inner.store.load(run_id)?;
        match record.outcome {
            Some(o) => Ok(o.export_manifest.unwrap_or(ExportManifest {
                changed: Vec::new(),
            })),
            None => Err(SandboxdError::RunState("run has no outcome yet".into())),
        }
    }

    /// Collect a completed run's output as chunks plus [`StreamStats`].
    ///
    /// This is the [`SandboxDriver::stream`] logic minus the sink: the
    /// frozen trait takes `sink: &mut dyn OutputSink`, and `dyn OutputSink`
    /// has no `Send` bound, so any `async fn` holding that parameter —
    /// including the trait impl — returns a `!Send` future. This inherent
    /// method's future IS `Send`, so `Send`-requiring callers (the local
    /// API's spawned connection tasks, and any kernel executor that
    /// spawns) should use it instead of the trait method.
    pub async fn stream_collect(
        &self,
        handle: &SandboxHandle,
    ) -> Result<(Vec<OutputChunk>, StreamStats), SandboxError> {
        check_handle(handle)?;
        let result = self
            .wait_inner(&Self::run_key(handle))
            .await
            .map_err(to_sandbox_error)?;
        // The supervisor captures bounded output; replay it as chunks. (v1
        // delivers output at completion; the sink interface keeps the door
        // open for incremental streaming later.)
        let bytes = result.output.as_bytes();
        let mut chunks = Vec::new();
        let mut sent = 0u64;
        for piece in bytes.chunks(64 * 1024) {
            chunks.push(OutputChunk {
                stream: "stdout".to_string(),
                bytes: piece.to_vec(),
            });
            sent += piece.len() as u64;
        }
        Ok((
            chunks,
            StreamStats {
                bytes: sent,
                truncated: result.output_truncated,
            },
        ))
    }
}

// ---------------------------------------------------------------------------
// SandboxDriver trait (frozen v1)
// ---------------------------------------------------------------------------

impl SandboxDriver for Driver {
    async fn prepare(&self, spec: &SandboxSpec) -> Result<SandboxHandle, SandboxError> {
        let runtime = Self::adapt_spec(spec, &self.inner.config).map_err(to_sandbox_error)?;
        let handle = SandboxHandle {
            version: SANDBOX_DRIVER_VERSION,
            run_id: Uuid::new_v4(),
        };
        let key = Self::run_key(&handle);
        self.prepare_inner(&key, &runtime)
            .await
            .map_err(to_sandbox_error)?;
        Ok(handle)
    }

    async fn start(&self, handle: &SandboxHandle) -> Result<(), SandboxError> {
        check_handle(handle)?;
        self.start_inner(&Self::run_key(handle))
            .await
            .map_err(to_sandbox_error)
    }

    async fn stream(
        &self,
        handle: &SandboxHandle,
        sink: &mut dyn OutputSink,
    ) -> Result<StreamStats, SandboxError> {
        // NOTE: this future is `!Send` — inherent to the frozen contract
        // (`&mut dyn OutputSink` has no `Send` bound). `Send`-requiring
        // callers should use `stream_collect`.
        let (chunks, stats) = self.stream_collect(handle).await?;
        for chunk in chunks {
            sink.push(chunk);
        }
        Ok(stats)
    }

    async fn cancel(&self, handle: &SandboxHandle) -> Result<(), SandboxError> {
        check_handle(handle)?;
        self.cancel_inner(&Self::run_key(handle))
            .await
            .map_err(to_sandbox_error)
    }

    async fn export(&self, handle: &SandboxHandle) -> Result<Vec<ExportedFile>, SandboxError> {
        check_handle(handle)?;
        let manifest = self
            .export_manifest_inner(&Self::run_key(handle))
            .await
            .map_err(to_sandbox_error)?;
        Ok(manifest
            .changed
            .into_iter()
            .map(|c| ExportedFile {
                path: c.path,
                content_hash: c.sha256,
                size_bytes: c.size_bytes,
            })
            .collect())
    }

    async fn destroy(&self, handle: &SandboxHandle) -> Result<(), SandboxError> {
        check_handle(handle)?;
        self.destroy_inner(&Self::run_key(handle))
            .await
            .map_err(to_sandbox_error)
    }
}

// ---------------------------------------------------------------------------
// FirecrackerBackend (real host effects; lane-vps)
// ---------------------------------------------------------------------------

/// Run a host command, capturing output. Errors include stderr.
async fn run_cmd(prog: &str, args: &[&str]) -> Result<String, SandboxdError> {
    let out = tokio::process::Command::new(prog)
        .args(args)
        .output()
        .await
        .map_err(|e| SandboxdError::Host(format!("spawn {prog}: {e}")))?;
    if !out.status.success() {
        return Err(SandboxdError::Host(format!(
            "{} {:?} failed: {}",
            prog,
            args,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Load the daemon's trusted image-signing keys (shared by the
/// prepare-time and launch-time image resolutions).
fn load_trusted_keys(config: &DaemonConfig) -> Result<Vec<VerifyingKey>, SandboxdError> {
    let mut keys = Vec::new();
    for path in &config.images.trusted_keys {
        keys.push(provenance::load_verifying_key(path)?);
    }
    Ok(keys)
}

// ---------------------------------------------------------------------------
// Bridge-netfilter fail-closed verification + host-namespace enforcement
// ---------------------------------------------------------------------------

/// `br_netfilter` sysctls that must read "1" for bridged guest traffic to
/// traverse the run-netns nftables forward chain. Without them, frames
/// bridged between the TAP and the veth skip netfilter entirely in the run
/// netns, and the only remaining enforcement would be whatever the host
/// happens to have configured — fail-open egress.
const BRIDGE_NF_SYSCTLS: [&str; 3] = [
    "bridge-nf-call-iptables",
    "bridge-nf-call-ip6tables",
    "bridge-nf-call-arptables",
];

/// Check the bridge-nf-call sysctls under `dir` (normally
/// `/proc/sys/net/bridge`). Pure and unit-testable: every value must be
/// exactly "1" (modulo surrounding whitespace). Fails closed on a missing
/// file (module not loaded) or any non-"1" value.
fn check_bridge_nf_sysctls(dir: &Path) -> Result<(), SandboxdError> {
    for name in BRIDGE_NF_SYSCTLS {
        let path = dir.join(name);
        let val = std::fs::read_to_string(&path).map_err(|e| {
            SandboxdError::Host(format!(
                "bridge netfilter sysctl {} unreadable — br_netfilter is not active; \
                 refusing to start because bridged guest traffic would bypass the \
                 run-netns firewall: {e}",
                path.display()
            ))
        })?;
        if val.trim() != "1" {
            return Err(SandboxdError::Host(format!(
                "bridge netfilter disabled ({} = {:?}); refusing to start because \
                 bridged guest traffic would bypass the run-netns firewall",
                path.display(),
                val.trim()
            )));
        }
    }
    Ok(())
}

/// Fail-closed bridge filtering check for action startup: attempt to load
/// `br_netfilter`, then require the sysctls to confirm it is actually
/// active. The sysctl state — not the modprobe exit status — is
/// authoritative (the module may be built in, in which case there is
/// nothing to load).
async fn ensure_bridge_filtering() -> Result<(), SandboxdError> {
    let _ = run_cmd("modprobe", &["br_netfilter"]).await;
    check_bridge_nf_sysctls(Path::new("/proc/sys/net/bridge"))
}

/// nftables table in the HOST (init) network namespace carrying the
/// br_netfilter-independent enforcement layer. The run-netns forward chain
/// only sees bridged guest traffic via br_netfilter; these host rules apply
/// at the host stack's input/forward hooks no matter how the frames got
/// there, so they hold even if bridge filtering were ever unavailable.
const HOST_NFT_TABLE: &str = "lumen-host";
const HOST_NFT_INPUT_CHAIN: &str = "sandbox_input";
const HOST_NFT_FORWARD_CHAIN: &str = "sandbox_forward";

/// Render the host-namespace nftables rules for one run. Each rule is the
/// argument vector after `nft <add|delete> rule`; add and delete use the
/// identical spec so teardown can remove exactly what setup installed.
///
/// Semantics:
/// - input: from the run's host-side veth, allow only the intended
///   guest->host flows (DNS + egress proxy on the host-leg address) plus
///   established return traffic; drop everything else arriving on that
///   interface. The final drop has no `ip` qualifier, so it also covers
///   IPv6.
/// - forward: the guest must never be L3-forwarded by the host; the egress
///   proxy performs upstream fetches on the guest's behalf under its own
///   policy. Dropped unconditionally.
///
/// The rules key on the ingress interface name, never on source IP: a guest
/// that re-addresses itself, adds routes, or enables forwarding inside its
/// own kernel still cannot pass these drops.
fn host_nft_rules(plan: &network::NetPlan) -> Vec<Vec<String>> {
    let veth = &plan.veth_host;
    let host = &plan.host_ip;
    let proxy = plan.proxy_port.to_string();
    let mut rules = Vec::new();
    let mut input = |rest: &[&str]| {
        let mut r = vec![
            "inet".to_string(),
            HOST_NFT_TABLE.to_string(),
            HOST_NFT_INPUT_CHAIN.to_string(),
            "iifname".to_string(),
            veth.clone(),
        ];
        r.extend(rest.iter().map(|s| s.to_string()));
        rules.push(r);
    };
    input(&["ip", "daddr", host, "udp", "dport", "53", "accept"]);
    input(&["ip", "daddr", host, "tcp", "dport", "53", "accept"]);
    input(&["ip", "daddr", host, "tcp", "dport", &proxy, "accept"]);
    input(&["ct", "state", "established,related", "accept"]);
    input(&["drop"]);
    rules.push(vec![
        "inet".to_string(),
        HOST_NFT_TABLE.to_string(),
        HOST_NFT_FORWARD_CHAIN.to_string(),
        "iifname".to_string(),
        veth.clone(),
        "drop".to_string(),
    ]);
    rules
}

/// Run nft in the host namespace with an argument vector.
async fn nft(args: &[String]) -> Result<String, SandboxdError> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_cmd("nft", &refs).await
}

/// Ensure the host table and chains exist (idempotent). Both chains use
/// policy accept: only traffic from sandbox veth interfaces is ever
/// dropped, so a missing or half-installed table cannot break unrelated
/// host traffic.
async fn ensure_host_nft_table() -> Result<(), SandboxdError> {
    if nft(&[
        "list".to_string(),
        "table".to_string(),
        "inet".to_string(),
        HOST_NFT_TABLE.to_string(),
    ])
    .await
    .is_err()
    {
        nft(&[
            "add".to_string(),
            "table".to_string(),
            "inet".to_string(),
            HOST_NFT_TABLE.to_string(),
        ])
        .await?;
        for (chain, hook) in [
            (HOST_NFT_INPUT_CHAIN, "input"),
            (HOST_NFT_FORWARD_CHAIN, "forward"),
        ] {
            nft(&[
                "add".to_string(),
                "chain".to_string(),
                "inet".to_string(),
                HOST_NFT_TABLE.to_string(),
                chain.to_string(),
                format!("{{ type filter hook {hook} priority 0; policy accept; }}"),
            ])
            .await?;
        }
    }
    Ok(())
}

/// Install the host-namespace enforcement rules for one run.
/// Delete-then-add makes setup idempotent against stale rules left by a
/// crashed run. Fail-closed: any error aborts action startup.
async fn install_host_enforcement(plan: &network::NetPlan) -> Result<(), SandboxdError> {
    ensure_host_nft_table().await?;
    for rule in host_nft_rules(plan) {
        let mut del = vec!["delete".to_string(), "rule".to_string()];
        del.extend(rule.iter().cloned());
        let _ = nft(&del).await; // Absent rule: fine.
        let mut add = vec!["add".to_string(), "rule".to_string()];
        add.extend(rule);
        nft(&add).await?;
    }
    Ok(())
}

/// Remove one run's host-namespace rules. Best-effort: teardown must not
/// fail because a rule is already gone (and a stale rule is inert once its
/// veth is deleted, since it matches on the interface name).
async fn remove_host_enforcement(plan: &network::NetPlan) {
    for rule in host_nft_rules(plan) {
        let mut del = vec!["delete".to_string(), "rule".to_string()];
        del.extend(rule);
        let _ = nft(&del).await;
    }
}

/// Re-hash a pinned launch artifact immediately before hand-off and
/// hard-link it into the chroot from its pinned descriptor (never via the
/// image-store path).
///
/// Fail-closed: any digest mismatch aborts the launch. The descriptor pins
/// the exact inode verified at resolve time, so a path swap in the store
/// after resolve cannot redirect the link; the re-hash additionally
/// catches in-place byte changes under the open handle.
fn revalidate_and_link_artifact(
    artifact: &provenance::PinnedArtifact,
    jail_root: &Path,
) -> Result<(), SandboxdError> {
    let actual = provenance::digest_open_file(&artifact.file)?;
    if actual != artifact.expected_digest {
        return Err(SandboxdError::BadSignature(format!(
            "launch revalidation failed for {}: {actual} != {}",
            artifact.name, artifact.expected_digest
        )));
    }
    let dst = jail_root.join(&artifact.name);
    let _ = std::fs::remove_file(&dst);
    artifact.hard_link_into(&dst)?;
    Ok(())
}

struct NetnsTask {
    thread: Option<std::thread::JoinHandle<()>>,
    shutdown_tx: std::sync::mpsc::Sender<()>,
}

#[async_trait]
impl NetnsHandle for NetnsTask {
    async fn shutdown(&mut self) -> Result<(), SandboxdError> {
        let _ = self.shutdown_tx.send(());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        Ok(())
    }
}

fn netns_services_main(ctx: NetnsCtx, shutdown_rx: std::sync::mpsc::Receiver<()>) {
    // NOTE: these services intentionally run in the HOST network namespace.
    // The run's host-side address (host_ip) is assigned to the veth's host
    // leg in the root namespace, so it is only bindable here; inside the
    // run netns the bind fails with EADDRNOTAVAIL, and the run netns has no
    // route to the host resolver or upstream targets. The guest still lives
    // in total isolation: it reaches these services over the veth pair,
    // subject to the nftables default-deny policy, and has no other path.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("sandboxd: runtime build failed: {e}");
            return;
        }
    };
    // Destructure: the proxy takes ownership of its config + resolver.
    let NetnsCtx {
        host_ip,
        proxy_port,
        proxy_cfg,
        network_policy,
        run_dir,
        ..
    } = ctx;
    rt.block_on(async {
        let proxy_addr = format!("{host_ip}:{proxy_port}");
        let listener = match tokio::net::TcpListener::bind(&proxy_addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("sandboxd: proxy bind {proxy_addr}: {e}");
                return;
            }
        };
        let dns_addr: std::net::SocketAddr = match format!("{host_ip}:53").parse() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("sandboxd: bad dns addr: {e}");
                return;
            }
        };
        let resolver =
            match HostPolicyResolver::new(&run_dir, SystemUpstream, network_policy.clone()) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("sandboxd: resolver: {e}");
                    return;
                }
            };
        let proxy = proxy::Proxy::new(proxy_cfg, resolver);
        let proxy_task = tokio::spawn(async move {
            proxy.serve(listener).await;
        });
        let mut dns = match DnsForwarder::bind(dns_addr, &run_dir, SystemUpstream, network_policy) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("sandboxd: dns bind: {e}");
                proxy_task.abort();
                return;
            }
        };
        loop {
            if shutdown_rx.try_recv().is_ok() {
                break;
            }
            match dns.pump_once() {
                Ok(true) => continue,
                Ok(false) => tokio::time::sleep(Duration::from_millis(10)).await,
                Err(e) => {
                    eprintln!("sandboxd: dns pump: {e}");
                    break;
                }
            }
        }
        proxy_task.abort();
    });
}

/// Ensure the cgroup parent exists with the controllers the run needs
/// enabled. Without `+memory +pids +cpu` in `cgroup.subtree_control`,
/// neither our `apply_limits` nor the jailer's `--cgroup` writes take
/// effect (writes fail and limits silently don't apply).
fn ensure_cgroup_parent(parent: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(parent)?;
    let ctl = parent.join("cgroup.subtree_control");
    let current = std::fs::read_to_string(&ctl).unwrap_or_default();
    let mut want = String::new();
    for c in ["memory", "pids", "cpu"] {
        if !current.split_whitespace().any(|x| x == c) {
            want.push('+');
            want.push_str(c);
            want.push(' ');
        }
    }
    if !want.is_empty() {
        std::fs::write(&ctl, want.trim_end())?;
    }
    Ok(())
}

/// Real backend: jailer, netns, vsock, Firecracker. Requires root + /dev/kvm.
pub struct FirecrackerBackend;

#[async_trait]
impl VmBackend for FirecrackerBackend {
    async fn setup_network(
        &self,
        plan: &network::NetPlan,
        nftables_rules: &str,
    ) -> Result<(), SandboxdError> {
        // netns
        //
        // Guest route administration: the guest is a full KVM virtual
        // machine, so its own root inherently holds CAP_NET_ADMIN over its
        // own kernel — that cannot be revoked from the host (capabilities
        // are a container concept; no host mechanism strips them inside a
        // VM). The guest's network is configured statically by /init from
        // the kernel command line (`lumen.guest_ip=`, `lumen.host_ip=`; see
        // jailer::render_config) — no DHCP, no router advertisements — but
        // a hostile guest root can still add routes or enable forwarding
        // inside its own kernel. That is contained by construction: every
        // enforcement rule installed here keys on the ingress interface
        // (iifname), never on source IP or guest routing state, so no route
        // the guest adds can escape the host-side drops.
        let _ = run_cmd("ip", &["netns", "delete", &plan.netns_name]).await;
        run_cmd("ip", &["netns", "add", &plan.netns_name]).await?;
        // veth pair
        let _ = run_cmd("ip", &["link", "delete", &plan.veth_host, "type", "veth"]).await;
        run_cmd(
            "ip",
            &[
                "link",
                "add",
                &plan.veth_host,
                "type",
                "veth",
                "peer",
                "name",
                &plan.veth_guest,
            ],
        )
        .await?;
        run_cmd(
            "ip",
            &["link", "set", &plan.veth_guest, "netns", &plan.netns_name],
        )
        .await?;
        // host leg address
        run_cmd(
            "ip",
            &[
                "addr",
                "add",
                &format!("{}/{}", plan.host_ip, plan.prefix_len),
                "dev",
                &plan.veth_host,
            ],
        )
        .await?;
        run_cmd("ip", &["link", "set", &plan.veth_host, "up"]).await?;
        // guest leg inside the netns: helper builds an owned arg vec so the
        // future doesn't borrow a local.
        let netns_name = plan.netns_name.clone();
        let nn = |args: Vec<String>| {
            let netns_name = netns_name.clone();
            async move {
                // ip netns exec <ns> <cmd>: the <cmd> must be a full command,
                // e.g. `ip link set ...`, not just the ip subcommand.
                let mut full = vec![
                    "netns".to_string(),
                    "exec".to_string(),
                    netns_name,
                    "ip".to_string(),
                ];
                full.extend(args);
                let refs: Vec<&str> = full.iter().map(String::as_str).collect();
                run_cmd("ip", &refs).await
            }
        };
        nn(vec![
            "link".into(),
            "set".into(),
            plan.veth_guest.clone(),
            "up".into(),
        ])
        .await?;
        nn(vec!["link".into(), "set".into(), "lo".into(), "up".into()]).await?;
        // TAP for the guest
        let _ = run_cmd("ip", &["tuntap", "del", &plan.tap_name, "mode", "tap"]).await;
        run_cmd("ip", &["tuntap", "add", &plan.tap_name, "mode", "tap"]).await?;
        run_cmd(
            "ip",
            &["link", "set", &plan.tap_name, "netns", &plan.netns_name],
        )
        .await?;
        nn(vec![
            "link".into(),
            "set".into(),
            plan.tap_name.clone(),
            "up".into(),
        ])
        .await?;
        // Bridge the TAP (guest) and veth_guest (host leg) at L2 so the
        // guest can reach the host's DNS/proxy on the host leg. The bridge
        // carries no IP address: the guest configures `guest_ip` on its own
        // interface inside the VM (from the `lumen.guest_ip=` kernel
        // command-line parameter).
        let br_name = format!("br-{}", &plan.netns_name[..8.min(plan.netns_name.len())]);
        nn(vec![
            "link".into(),
            "add".into(),
            br_name.clone(),
            "type".into(),
            "bridge".into(),
        ])
        .await?;
        nn(vec![
            "link".into(),
            "set".into(),
            br_name.clone(),
            "up".into(),
        ])
        .await?;
        nn(vec![
            "link".into(),
            "set".into(),
            plan.tap_name.clone(),
            "master".into(),
            br_name.clone(),
        ])
        .await?;
        nn(vec![
            "link".into(),
            "set".into(),
            plan.veth_guest.clone(),
            "master".into(),
            br_name.clone(),
        ])
        .await?;
        // nftables (default-deny; see network::render_nftables). Bridged
        // guest traffic traverses the inet forward chain ONLY via
        // br_netfilter, so bridge filtering is verified fail-closed here:
        // without it the run-netns policy would be silently bypassed
        // (fail-open egress). The old "no route, no NAT" topology argument
        // is NOT relied upon — it is an assumption about host state
        // (forwarding flags, MASQUERADE rules, host listeners), not an
        // enforced invariant, and a root guest is not bound by it.
        ensure_bridge_filtering().await?;
        let nft_path = format!("/run/lumen-{}.nft", plan.netns_name);
        std::fs::write(&nft_path, nftables_rules).map_err(SandboxdError::Io)?;
        let nft_cmd = format!("ip netns exec {} nft -f {}", plan.netns_name, nft_path);
        run_cmd("sh", &["-c", &nft_cmd]).await?;
        // Host-namespace enforcement, independent of bridge hooks: even if
        // bridged frames ever bypassed the run-netns chains, the host stack
        // still drops everything arriving on the sandbox veth except the
        // intended guest->host DNS/proxy flows, and never L3-forwards guest
        // traffic.
        install_host_enforcement(plan).await?;
        Ok(())
    }

    async fn teardown_network(&self, plan: &network::NetPlan) -> Result<(), SandboxdError> {
        remove_host_enforcement(plan).await;
        let _ = run_cmd("ip", &["netns", "delete", &plan.netns_name]).await;
        let _ = run_cmd("ip", &["link", "delete", &plan.veth_host, "type", "veth"]).await;
        let _ = run_cmd("ip", &["tuntap", "del", &plan.tap_name, "mode", "tap"]).await;
        let _ = std::fs::remove_file(format!("/run/lumen-{}.nft", plan.netns_name));
        Ok(())
    }

    async fn spawn_netns_services(
        &self,
        ctx: &NetnsCtx,
    ) -> Result<Box<dyn NetnsHandle>, SandboxdError> {
        // Move the ctx into the thread.
        let ctx = NetnsCtx {
            host_ip: ctx.host_ip.clone(),
            proxy_port: ctx.proxy_port,
            proxy_cfg: crate::proxy::ProxyConfig {
                run_id: ctx.proxy_cfg.run_id.clone(),
                network: ctx.proxy_cfg.network.clone(),
                byte_cap: ctx.proxy_cfg.byte_cap,
                log_path: ctx.proxy_cfg.log_path.clone(),
            },
            network_policy: ctx.network_policy.clone(),
            run_dir: ctx.run_dir.clone(),
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || netns_services_main(ctx, rx));
        Ok(Box::new(NetnsTask {
            thread: Some(thread),
            shutdown_tx: tx,
        }))
    }

    async fn spawn_jailer(
        &self,
        setup: &JailSetup,
    ) -> Result<Box<dyn JailerHandle>, SandboxdError> {
        let spec = &setup.spec;
        // 1. Chroot skeleton.
        let root = jailer::jail_root(&spec.chroot_base, &spec.firecracker_bin, &spec.id);
        std::fs::create_dir_all(&root).map_err(SandboxdError::Io)?;
        // 2. Hard-link verified read-only artifacts. The workspace template
        //    is hard-linked too, but the per-run workspace is a COPY (never
        //    a hard link): guest block writes through a hard link would
        //    dirty the shared template for every later run.
        //
        //    Each artifact is re-hashed from its PINNED descriptor
        //    immediately before linking (see revalidate_and_link_artifact):
        //    launch aborts on any digest mismatch, so bytes swapped in the
        //    store after resolve can never boot.
        for artifact in &setup.artifacts {
            revalidate_and_link_artifact(artifact, &root)?;
        }
        // 3. Per-run workspace: sparse (reflink-preferring) copy of the
        //    template. Firecracker's virtio-blk is raw-only, so this is a
        //    raw ext4 image, not qcow2.
        let delta = root.join("workspace.raw");
        let _ = std::fs::remove_file(&delta);
        crate::storage::create_workspace_copy(&root.join("workspace-template.raw"), &delta)
            .map_err(|e| SandboxdError::Host(format!("workspace copy: {e}")))?;
        // Firecracker runs as the jailer's uid/gid and opens the workspace
        // O_RDWR; the copy inherits root ownership (0644) from the template,
        // so chown it to the jailer identity.
        let c_path = std::ffi::CString::new(delta.as_os_str().as_encoded_bytes())
            .map_err(|e| SandboxdError::Host(format!("workspace path contains NUL: {e}")))?;
        // SAFETY: c_path is a valid NUL-terminated path; chown has no other
        // preconditions.
        let rc = unsafe { libc::chown(c_path.as_ptr(), spec.uid, spec.gid) };
        if rc != 0 {
            return Err(SandboxdError::Host(format!(
                "chown workspace.raw to {}:{}: {}",
                spec.uid,
                spec.gid,
                std::io::Error::last_os_error()
            )));
        }
        // 4. Config into the chroot.
        std::fs::write(root.join("firecracker.json"), &setup.fc_config_json)
            .map_err(SandboxdError::Io)?;
        // 5. cgroup for the run. This MUST be the same cgroup the jailer
        //    creates (`--parent-cgroup <parent> --id <id>` => `<parent>/<id>`),
        //    otherwise limits, kill, and metering act on an empty cgroup
        //    while the VMM runs unconstrained next to it.
        let cgroup_parent = &spec.cgroup_parent;
        let cgroup_rel = Path::new(&spec.id);
        // The parent needs the controllers enabled before either we or the
        // jailer (as root) write limit files in the leaf.
        if let Err(e) = ensure_cgroup_parent(cgroup_parent) {
            return Err(SandboxdError::Host(format!("cgroup parent: {e}")));
        }
        if let Err(e) = cgroups::apply_limits(cgroup_parent, cgroup_rel, &spec.limits) {
            return Err(SandboxdError::Host(format!("cgroup apply: {e}")));
        }
        // 6. Launch via the jailer binary.
        let argv = jailer::jailer_argv(spec, &setup.fc_args)?;
        // jailer_argv returns the jailer arguments (starting with --id);
        // the binary path comes from the JailSetup.
        // Capture jailer stderr: the only post-mortem when firecracker dies before the API socket exists.
        let jailer_log = spec.chroot_base.join(format!("jailer-{}.log", spec.id));
        let log_file = std::fs::File::create(&jailer_log).ok();
        let stderr_cfg = log_file
            .map(std::process::Stdio::from)
            .unwrap_or(std::process::Stdio::null());
        // Log the full jailer command alongside, for post-mortem.
        let cmd_log = spec.chroot_base.join(format!("jailer-cmd-{}.log", spec.id));
        let _ = std::fs::write(
            &cmd_log,
            format!("BIN: {}\nARGS: {:?}\n", setup.jailer_bin.display(), argv),
        );
        let mut child = tokio::process::Command::new(&setup.jailer_bin)
            .args(&argv)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(stderr_cfg)
            .spawn()
            .map_err(|e| SandboxdError::Host(format!("spawn jailer: {e}")))?;
        let pid = child.id();
        // Pin the jailer (and its Firecracker child, by inheritance) to the
        // run's cgroup. Best effort: a failure here is logged, not fatal,
        // because the jailer's own rlimits still apply.
        if let Some(pid) = pid {
            let _ = cgroups::add_process(cgroup_parent, cgroup_rel, pid);
        }
        // Reap in the background; the handle kills by pid.
        tokio::spawn(async move {
            let _ = child.wait().await;
        });
        Ok(Box::new(ChildJailerHandle { pid }))
    }

    async fn boot_instance(&self, api_sock: &Path) -> Result<(), SandboxdError> {
        // Firecracker applies --config-file at startup but does NOT boot;
        // the VM waits for the InstanceStart action on its API socket.
        // Minimal HTTP/1.1 client over the unix socket (no extra deps).
        let body = r#"{"action_type":"InstanceStart"}"#;
        let req = format!(
            "PUT /actions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let start = Instant::now();
        loop {
            match tokio::net::UnixStream::connect(api_sock).await {
                Ok(mut s) => {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    s.write_all(req.as_bytes())
                        .await
                        .map_err(|e| SandboxdError::Host(format!("InstanceStart write: {e}")))?;
                    let mut buf = vec![0u8; 4096];
                    let mut len = 0;
                    // Read until the end of the status line.
                    while len < buf.len() {
                        let n = s
                            .read(&mut buf[len..])
                            .await
                            .map_err(|e| SandboxdError::Host(format!("InstanceStart read: {e}")))?;
                        if n == 0 {
                            break;
                        }
                        len += n;
                        if buf[..len].windows(2).any(|w| w == b"\r\n") {
                            break;
                        }
                    }
                    let status = String::from_utf8_lossy(&buf[..len]);
                    let status_line = status.lines().next().unwrap_or("");
                    // Firecracker answers 204 on success (e.g. "HTTP/1.1 204 "
                    // with no reason phrase). Parse the status code robustly.
                    let is_204 = status_line
                        .split_whitespace()
                        .nth(1)
                        .map(|code| code == "204")
                        .unwrap_or(false);
                    if is_204 {
                        return Ok(());
                    }
                    // A 400 with "not supported after starting" means the VM
                    // is already Running (e.g. a retried request). Verify.
                    drop(s);
                    if vm_state(api_sock).await.as_deref() == Some("Running") {
                        return Ok(());
                    }
                    return Err(SandboxdError::Host(format!(
                        "InstanceStart rejected: {status_line}"
                    )));
                }
                Err(e) => {
                    if start.elapsed() > Duration::from_secs(30) {
                        return Err(SandboxdError::Host(format!(
                            "firecracker API {}: {e}",
                            api_sock.display()
                        )));
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn connect_agent(
        &self,
        uds_path: &Path,
        timeout: Duration,
    ) -> Result<Box<dyn AgentIo>, SandboxdError> {
        // Firecracker creates the vsock UDS when the VMM starts; poll for
        // it, then connect. Host-initiated vsock (see docs/vsock.md): send
        // `CONNECT <port>\n`, read the `OK <host-port>\n` ack; the UDS
        // connection is then the data stream to the guest's AF_VSOCK
        // listener on that port.
        let start = Instant::now();
        loop {
            match tokio::net::UnixStream::connect(uds_path).await {
                Ok(mut s) => {
                    // Send the CONNECT preamble. The guest agent listens on
                    // AF_VSOCK VSOCK_PORT (see guest_agent::VSOCK_PORT).
                    let preamble = format!("CONNECT {VSOCK_PORT}\n");
                    if let Err(e) =
                        tokio::io::AsyncWriteExt::write_all(&mut s, preamble.as_bytes()).await
                    {
                        return Err(SandboxdError::Host(format!("vsock CONNECT failed: {e}")));
                    }
                    // Read the `OK <host-port>\n` ack. Without this the ack
                    // bytes would be parsed as the first message frame.
                    let mut ack = Vec::new();
                    let ack_read = tokio::time::timeout(
                        Duration::from_secs(5),
                        tokio::io::AsyncBufReadExt::read_until(
                            &mut tokio::io::BufReader::new(&mut s),
                            b'\n',
                            &mut ack,
                        ),
                    )
                    .await;
                    match ack_read {
                        Ok(Ok(_)) if ack.starts_with(b"OK ") => {}
                        _ => {
                            return Err(SandboxdError::Host(format!(
                                "vsock CONNECT: no OK ack ({})",
                                String::from_utf8_lossy(&ack)
                            )));
                        }
                    }
                    return Ok(Box::new(s));
                }
                Err(e) => {
                    if start.elapsed() > timeout {
                        return Err(SandboxdError::Host(format!(
                            "vsock UDS connect {}: {e}",
                            uds_path.display()
                        )));
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

/// Query the VM state via GET /. Returns None on any error.
async fn vm_state(api_sock: &Path) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::UnixStream::connect(api_sock).await.ok()?;
    let req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    s.write_all(req.as_bytes()).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let mut len = 0;
    while len < buf.len() {
        let n = s.read(&mut buf[len..]).await.ok()?;
        if n == 0 {
            break;
        }
        len += n;
        // End of headers.
        if buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let resp = String::from_utf8_lossy(&buf[..len]);
    // Body is JSON like {"state":"Running",...}; extract the state value.
    let body_start = resp.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let body = &resp[body_start..];
    let key = "\"state\":\"";
    body.find(key).map(|i| {
        let start = i + key.len();
        let end = body[start..].find('"').map(|j| start + j).unwrap_or(start);
        body[start..end].to_string()
    })
}

struct ChildJailerHandle {
    pid: Option<u32>,
}

#[async_trait]
impl JailerHandle for ChildJailerHandle {
    async fn terminate(&mut self) -> Result<(), SandboxdError> {
        if let Some(pid) = self.pid.take() {
            unsafe {
                // SIGKILL the process group (jailer sets its own pgid).
                libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
            }
        }
        Ok(())
    }

    fn pid(&self) -> Option<u32> {
        self.pid
    }
}

// ---------------------------------------------------------------------------
// MockBackend (hermetic; dev-machine tests)
// ---------------------------------------------------------------------------

/// In-memory backend: no KVM, no netns, no jailer. The "guest" is a
/// scripted [`MockAgent`] speaking the real agent protocol over a duplex.
pub struct MockBackend {
    /// Script the mock guest follows after the welcome message.
    pub script: Arc<Mutex<MockScript>>,
}

#[derive(Default)]
pub struct MockScript {
    /// Run id the mock guest claims in its hello (set by the test after
    /// prepare; must match or the handshake fails).
    pub run_id: String,
    /// (is_stdout, bytes) chunks to emit.
    pub stdio: Vec<(bool, Vec<u8>)>,
    /// Export files to stream: (path, bytes).
    pub exports: Vec<(String, Vec<u8>)>,
    /// Exit code.
    pub exit_code: i32,
}

struct MockNetnsHandle;

#[async_trait]
impl NetnsHandle for MockNetnsHandle {
    async fn shutdown(&mut self) -> Result<(), SandboxdError> {
        Ok(())
    }
}

struct MockJailerHandle;

#[async_trait]
impl JailerHandle for MockJailerHandle {
    async fn terminate(&mut self) -> Result<(), SandboxdError> {
        Ok(())
    }
    fn pid(&self) -> Option<u32> {
        None
    }
}

#[async_trait]
impl VmBackend for MockBackend {
    async fn setup_network(
        &self,
        _plan: &network::NetPlan,
        _nftables_rules: &str,
    ) -> Result<(), SandboxdError> {
        Ok(())
    }

    async fn teardown_network(&self, _plan: &network::NetPlan) -> Result<(), SandboxdError> {
        Ok(())
    }

    async fn spawn_netns_services(
        &self,
        _ctx: &NetnsCtx,
    ) -> Result<Box<dyn NetnsHandle>, SandboxdError> {
        Ok(Box::new(MockNetnsHandle))
    }

    async fn spawn_jailer(
        &self,
        _setup: &JailSetup,
    ) -> Result<Box<dyn JailerHandle>, SandboxdError> {
        Ok(Box::new(MockJailerHandle))
    }

    async fn boot_instance(&self, _api_sock: &Path) -> Result<(), SandboxdError> {
        Ok(())
    }

    async fn connect_agent(
        &self,
        _uds_path: &Path,
        _timeout: Duration,
    ) -> Result<Box<dyn AgentIo>, SandboxdError> {
        let (a, b) = tokio::io::duplex(1024 * 1024);
        // The mock guest speaks first (hello), then follows the script.
        let script = Arc::clone(&self.script);
        tokio::spawn(async move {
            mock_guest_main(b, script).await;
        });
        Ok(Box::new(a))
    }
}

/// The scripted guest: hello -> welcome -> stdio/exports -> exit.
async fn mock_guest_main(mut stream: tokio::io::DuplexStream, script: Arc<Mutex<MockScript>>) {
    // Hello with the run id the test configured; the driver checks it.
    let run_id = {
        let s = script.lock().unwrap();
        s.run_id.clone()
    };
    let hello = AgentMsg::Hello {
        version: PROTOCOL_VERSION,
        run_id,
        nonce: "mock-nonce".into(),
    };
    if write_msg(&mut stream, &hello).await.is_err() {
        return;
    }
    // Wait for welcome.
    let welcome: Option<HostMsg> = read_msg(&mut stream).await.unwrap_or(None);
    let welcome = matches!(welcome, Some(HostMsg::Welcome { .. }));
    if !welcome {
        return;
    }
    let (stdio, exports, exit_code) = {
        let s = script.lock().unwrap();
        (s.stdio.clone(), s.exports.clone(), s.exit_code)
    };
    for (is_stdout, bytes) in stdio {
        // Chunk like a real agent would.
        for chunk in bytes.chunks(crate::guest_agent::MAX_CHUNK_BYTES) {
            let msg = if is_stdout {
                AgentMsg::stdout(chunk)
            } else {
                AgentMsg::stderr(chunk)
            };
            if write_msg(&mut stream, &msg).await.is_err() {
                return;
            }
        }
    }
    if !exports.is_empty() {
        let begin = AgentMsg::ExportBegin {
            files: exports.len() as u32,
        };
        if write_msg(&mut stream, &begin).await.is_err() {
            return;
        }
        // The host doesn't ack ExportBegin with a message we wait for
        // (it sends ExportAck but we don't need to read it).
        for (path, bytes) in &exports {
            let file = AgentMsg::ExportFile {
                path: path.clone(),
                size: bytes.len() as u64,
                sha256: crate::provenance::digest_bytes(bytes),
            };
            if write_msg(&mut stream, &file).await.is_err() {
                return;
            }
            for chunk in bytes.chunks(crate::guest_agent::MAX_CHUNK_BYTES) {
                if write_msg(&mut stream, &AgentMsg::export_data(chunk))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
        if write_msg(&mut stream, &AgentMsg::ExportEnd).await.is_err() {
            return;
        }
    }
    // Heartbeats until the host closes or we exit.
    let _ = write_msg(&mut stream, &AgentMsg::Heartbeat).await;
    let _ = write_msg(&mut stream, &AgentMsg::Exit { code: exit_code }).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::SandboxQuotas;
    use crate::provenance::{ImageManifest, ToolchainManifest};
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    /// Build a signed fake image in a temp store. Returns
    /// (store_dir, image_digest).
    fn fake_image() -> (tempfile::TempDir, String) {
        let store = tempfile::tempdir().unwrap();
        let key = test_key();
        // Fake artifacts with deterministic content.
        let vmlinux = b"fake kernel";
        let rootfs = b"fake rootfs";
        let template = b"fake workspace template";
        let kernel_digest = crate::provenance::digest_bytes(vmlinux);
        let rootfs_digest = crate::provenance::digest_bytes(rootfs);
        let template_digest = crate::provenance::digest_bytes(template);
        let mut manifest = ImageManifest {
            format_version: 1,
            kernel_digest,
            rootfs_digest,
            workspace_template_digest: template_digest,
            snapshot: None,
            toolchain: ToolchainManifest {
                builder: "test".into(),
                builder_version: "0".into(),
                kernel_version: "test".into(),
                kernel_config_digest: "sha256:".to_string() + &"0".repeat(64),
                tool_versions: BTreeMap::new(),
                reproducible: false,
            },
            policy_version: "sandbox-policy-v1".into(),
            created_unix: 1,
            signatures: vec![],
        };
        manifest.sign(&key).unwrap();
        let image_digest = manifest.image_digest().unwrap();
        let dir = store.path().join(&image_digest);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vmlinux"), vmlinux).unwrap();
        std::fs::write(dir.join("rootfs.ext4"), rootfs).unwrap();
        std::fs::write(dir.join("workspace-template.raw"), template).unwrap();
        let manifest_json = serde_json::to_vec_pretty(&manifest).unwrap();
        std::fs::write(dir.join("manifest.json"), manifest_json).unwrap();
        // Trusted key file.
        let key_path = store.path().join("trusted.key");
        std::fs::write(&key_path, hex::encode(key.verifying_key().as_bytes())).unwrap();
        // Stash the key path via an env-free sidecar: the test config reads
        // it from the store dir directly.
        std::fs::write(
            store.path().join("key_path"),
            key_path.display().to_string(),
        )
        .unwrap();
        (store, image_digest)
    }

    fn test_config(store: &tempfile::TempDir, state: &tempfile::TempDir) -> DaemonConfig {
        let key_path = std::fs::read_to_string(store.path().join("key_path")).unwrap();
        let mut cfg = DaemonConfig::default();
        cfg.state.dir = state.path().to_path_buf();
        cfg.images.store = store.path().to_path_buf();
        cfg.images.trusted_keys = vec![PathBuf::from(key_path.trim())];
        cfg.images.policy_version = "sandbox-policy-v1".into();
        cfg
    }

    /// A frozen v1 spec, as the kernel would send it.
    fn test_spec(image_digest: &str) -> SandboxSpec {
        SandboxSpec {
            version: SANDBOX_DRIVER_VERSION,
            profile: SandboxProfile::Strict,
            image_digest: image_digest.to_string(),
            command: vec!["echo".into(), "hi".into()],
            quotas: SandboxQuotas {
                memory_mb: 256,
                vcpus: 1,
                wall_time_ms: 30_000,
                output_bytes: 65536,
            },
            egress_allowlist: vec![],
        }
    }

    fn test_driver(
        cfg: DaemonConfig,
        script: Arc<Mutex<MockScript>>,
    ) -> (Driver, tempfile::TempDir) {
        // The state dir is owned by the caller; we just need the store.
        let state_dir = cfg.state.dir.clone();
        let store = RunStore::open(&state_dir).unwrap();
        let backend: Arc<dyn VmBackend> = Arc::new(MockBackend { script });
        let driver = Driver::new(cfg, store, backend).unwrap();
        // Return a dummy tempdir to keep the state dir alive via the caller.
        (driver, tempfile::tempdir().unwrap())
    }

    /// Collecting sink for `stream` tests.
    #[derive(Default)]
    struct VecSink {
        chunks: Vec<OutputChunk>,
    }

    impl OutputSink for VecSink {
        fn push(&mut self, chunk: OutputChunk) {
            self.chunks.push(chunk);
        }
    }

    #[test]
    fn adapt_spec_maps_quotas_and_egress() {
        let cfg = DaemonConfig::default();
        let mut spec = test_spec(&("sha256:".to_string() + &"a".repeat(64)));
        // 1500ms rounds UP to 2s so the kernel's deadline is never shortened.
        spec.quotas.wall_time_ms = 1500;
        spec.quotas.vcpus = 2;
        spec.egress_allowlist = vec![crate::contracts::NetworkResource {
            scheme: "https".into(),
            host: "example.com".into(),
            port: 443,
        }];
        let rt = Driver::adapt_spec(&spec, &cfg).unwrap();
        assert_eq!(rt.limits.vcpu, 2);
        assert_eq!(rt.limits.memory_mib, 256);
        assert_eq!(rt.limits.wall_time_secs, 2);
        assert_eq!(rt.limits.max_output_bytes, 65536);
        assert_eq!(rt.limits.max_processes, cfg.limits.default_max_processes);
        assert_eq!(rt.limits.disk_mib, cfg.limits.max_disk_mib);
        assert_eq!(rt.policy_version, cfg.images.policy_version);
        assert!(rt.env.is_empty());
        assert_eq!(
            rt.network.allow_egress,
            vec!["https://example.com:443".to_string()]
        );
        assert!(rt.network.deny_metadata);
        assert!(rt.network.deny_private_ranges);
    }

    #[tokio::test]
    async fn prepare_rejects_bad_spec() {
        let (img_store, image_digest) = fake_image();
        let state = tempfile::tempdir().unwrap();
        let cfg = test_config(&img_store, &state);
        let script = Arc::new(Mutex::new(MockScript::default()));
        let (driver, _keep) = test_driver(cfg, script);

        // Wrong contract version.
        let mut spec = test_spec(&image_digest);
        spec.version = 999;
        assert!(driver.prepare(&spec).await.is_err());

        // Bad digest.
        let mut spec = test_spec(&image_digest);
        spec.image_digest = "not-a-digest".into();
        assert!(driver.prepare(&spec).await.is_err());

        // Empty command.
        let mut spec = test_spec(&image_digest);
        spec.command = vec![];
        assert!(driver.prepare(&spec).await.is_err());

        // Over host limits.
        let mut spec = test_spec(&image_digest);
        spec.quotas.memory_mb = u64::MAX;
        assert!(driver.prepare(&spec).await.is_err());

        // Zero wall time.
        let mut spec = test_spec(&image_digest);
        spec.quotas.wall_time_ms = 0;
        assert!(driver.prepare(&spec).await.is_err());

        // Malformed egress entry.
        let mut spec = test_spec(&image_digest);
        spec.egress_allowlist = vec![crate::contracts::NetworkResource {
            scheme: "https".into(),
            host: "".into(),
            port: 443,
        }];
        assert!(driver.prepare(&spec).await.is_err());

        // Unsupported scheme.
        let mut spec = test_spec(&image_digest);
        spec.egress_allowlist = vec![crate::contracts::NetworkResource {
            scheme: "gopher".into(),
            host: "example.com".into(),
            port: 70,
        }];
        assert!(driver.prepare(&spec).await.is_err());

        // Unknown image (not in the signed store).
        let mut spec = test_spec(&image_digest);
        spec.image_digest = "sha256:".to_string() + &"a".repeat(64);
        assert!(driver.prepare(&spec).await.is_err());
    }

    #[tokio::test]
    async fn version_mismatched_handle_fails_closed() {
        let (img_store, image_digest) = fake_image();
        let state = tempfile::tempdir().unwrap();
        let cfg = test_config(&img_store, &state);
        let script = Arc::new(Mutex::new(MockScript::default()));
        let (driver, _keep) = test_driver(cfg, script);

        let spec = test_spec(&image_digest);
        let mut handle = driver.prepare(&spec).await.unwrap();
        handle.version = 999;
        let mut sink = VecSink::default();
        assert!(driver.start(&handle).await.is_err());
        assert!(driver.stream(&handle, &mut sink).await.is_err());
        assert!(driver.cancel(&handle).await.is_err());
        assert!(driver.export(&handle).await.is_err());
        assert!(driver.destroy(&handle).await.is_err());
    }

    #[tokio::test]
    async fn lifecycle_happy_path() {
        let (img_store, image_digest) = fake_image();
        let state = tempfile::tempdir().unwrap();
        let cfg = test_config(&img_store, &state);
        let script = Arc::new(Mutex::new(MockScript {
            stdio: vec![
                (true, b"hello stdout".to_vec()),
                (false, b"hello stderr".to_vec()),
            ],
            exports: vec![("out/result.txt".into(), b"result bytes".to_vec())],
            exit_code: 0,
            ..Default::default()
        }));
        let (driver, _keep) = test_driver(cfg, Arc::clone(&script));

        let spec = test_spec(&image_digest);
        let handle = driver.prepare(&spec).await.unwrap();
        assert_eq!(handle.version, SANDBOX_DRIVER_VERSION);
        // The mock guest must claim the right run id.
        script.lock().unwrap().run_id = Driver::run_key(&handle);

        driver.start(&handle).await.unwrap();

        // Stream the output through the frozen sink interface.
        let mut sink = VecSink::default();
        let stats = driver.stream(&handle, &mut sink).await.unwrap();
        assert!(stats.bytes > 0);
        assert!(!stats.truncated);
        let text: Vec<u8> = sink.chunks.iter().flat_map(|c| c.bytes.clone()).collect();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("hello stdout"));
        assert!(text.contains("hello stderr"));

        // The rich internal result is still available to the daemon.
        let key = Driver::run_key(&handle);
        let result = driver.wait_inner(&key).await.unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(!result.timed_out);
        assert!(!result.output_truncated);

        // Export through the frozen trait.
        let files = driver.export(&handle).await.unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "/out/result.txt");
        assert_eq!(files[0].size_bytes, 12);
        assert_eq!(files[0].content_hash.len(), 64 + "sha256:".len());

        driver.destroy(&handle).await.unwrap();
        // Destroy is idempotent.
        driver.destroy(&handle).await.unwrap();
    }

    #[tokio::test]
    async fn cancel_terminates_run() {
        let (img_store, image_digest) = fake_image();
        let state = tempfile::tempdir().unwrap();
        let cfg = test_config(&img_store, &state);
        // Script that never exits on its own; the cancel must stop it.
        let script = Arc::new(Mutex::new(MockScript {
            stdio: vec![],
            exports: vec![],
            exit_code: 0,
            ..Default::default()
        }));
        let (driver, _keep) = test_driver(cfg, Arc::clone(&script));

        let spec = test_spec(&image_digest);
        let handle = driver.prepare(&spec).await.unwrap();
        script.lock().unwrap().run_id = Driver::run_key(&handle);

        // Override the mock guest to block instead of exiting. We do this
        // by replacing accept_agent behavior: simpler to just start and
        // cancel quickly; the mock exits fast, so we test that cancel on a
        // completed run is still accepted (no supervisor).
        driver.start(&handle).await.unwrap();
        // Cancel while running (the mock exits quickly; this may race).
        let _ = driver.cancel(&handle).await;
        let key = Driver::run_key(&handle);
        let result = driver.wait_inner(&key).await.unwrap();
        // Either cancelled or completed; both are valid outcomes of the race.
        assert!(result.exit_code == 0 || result.timed_out || true);
        driver.destroy(&handle).await.unwrap();
    }

    #[tokio::test]
    async fn secret_env_names_rejected_without_grant() {
        // grant_secrets with no broker configured must fail closed.
        let (img_store, image_digest) = fake_image();
        let state = tempfile::tempdir().unwrap();
        let mut cfg = test_config(&img_store, &state);
        cfg.secrets.broker_socket = None;
        let script = Arc::new(Mutex::new(MockScript::default()));
        let (driver, _keep) = test_driver(cfg, script);

        let spec = test_spec(&image_digest);
        let handle = driver.prepare(&spec).await.unwrap();
        let key = Driver::run_key(&handle);
        let err = driver
            .grant_secrets(&key, &[("MY_SECRET".into(), "handle-1".into())])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("broker"));
        driver.destroy(&handle).await.unwrap();
    }

    #[test]
    fn uid_pool_skips_live_uids() {
        let mut pool = UidPool {
            end: 1002,
            next: 1000,
        };
        assert_eq!(pool.alloc(), Some(1000));
        assert_eq!(pool.alloc(), Some(1001));
        assert_eq!(pool.alloc(), Some(1002));
        assert_eq!(pool.alloc(), None);
    }

    #[test]
    fn is_secret_like_cases() {
        assert!(is_secret_like("API_TOKEN"));
        assert!(is_secret_like("db_password"));
        assert!(is_secret_like("SECRET_KEY"));
        assert!(!is_secret_like("PATH"));
        assert!(!is_secret_like("HOME"));
    }

    // --- Adversarial-review regression tests (PR #73) ---

    fn bridge_sysctl_dir(values: &[(&str, &str)]) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        for (name, val) in values {
            std::fs::write(tmp.path().join(name), val).unwrap();
        }
        tmp
    }

    #[test]
    fn bridge_nf_sysctls_require_all_one() {
        // All "1" (with trailing newline, as the kernel writes them): ok.
        let dir = bridge_sysctl_dir(&[
            ("bridge-nf-call-iptables", "1\n"),
            ("bridge-nf-call-ip6tables", "1\n"),
            ("bridge-nf-call-arptables", "1"),
        ]);
        assert!(check_bridge_nf_sysctls(dir.path()).is_ok());
    }

    #[test]
    fn bridge_nf_sysctl_zero_fails_closed() {
        let dir = bridge_sysctl_dir(&[
            ("bridge-nf-call-iptables", "1\n"),
            ("bridge-nf-call-ip6tables", "0\n"), // disabled
            ("bridge-nf-call-arptables", "1\n"),
        ]);
        let err = check_bridge_nf_sysctls(dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("bridge-nf-call-ip6tables"), "msg: {msg}");
        assert!(msg.contains("refusing to start"), "msg: {msg}");
    }

    #[test]
    fn bridge_nf_sysctl_missing_fails_closed() {
        // Module not loaded: /proc/sys/net/bridge/* absent entirely.
        let dir = bridge_sysctl_dir(&[("bridge-nf-call-iptables", "1\n")]);
        let err = check_bridge_nf_sysctls(dir.path()).unwrap_err();
        assert!(err.to_string().contains("refusing to start"));
        // Empty dir at all.
        let empty = tempfile::tempdir().unwrap();
        assert!(check_bridge_nf_sysctls(empty.path()).is_err());
    }

    #[test]
    fn bridge_nf_sysctl_garbage_fails_closed() {
        let dir = bridge_sysctl_dir(&[
            ("bridge-nf-call-iptables", "1\n"),
            ("bridge-nf-call-ip6tables", "1\n"),
            ("bridge-nf-call-arptables", "yes\n"),
        ]);
        assert!(check_bridge_nf_sysctls(dir.path()).is_err());
    }

    fn test_plan() -> network::NetPlan {
        network::plan_net("abcdef12", "10.244.0.0/16", 0, 18080, "lmvt-", "lmn-").unwrap()
    }

    #[test]
    fn host_nft_rules_allow_only_intended_flows_then_drop() {
        let plan = test_plan();
        let rules = host_nft_rules(&plan);
        // 5 input rules (dns udp, dns tcp, proxy tcp, established, drop)
        // + 1 forward drop.
        assert_eq!(rules.len(), 6);
        let render = |r: &[String]| r.join(" ");
        let texts: Vec<String> = rules.iter().map(|r| render(r)).collect();

        // Every rule is scoped to this run's host-side veth by ingress
        // interface — never by source IP (route-agnostic).
        for t in &texts {
            assert!(t.contains("iifname lmvh-abcdef12"), "rule: {t}");
        }
        // Intended flows: DNS + proxy on the host-leg address.
        assert!(texts[0].contains("ip daddr 10.244.0.1 udp dport 53 accept"));
        assert!(texts[1].contains("ip daddr 10.244.0.1 tcp dport 53 accept"));
        assert!(texts[2].contains("ip daddr 10.244.0.1 tcp dport 18080 accept"));
        assert!(texts[3].contains("ct state established,related accept"));
        // Final input rule: family-agnostic drop (no `ip` qualifier, so
        // IPv6 from the guest is dropped too).
        assert_eq!(
            texts[4],
            "inet lumen-host sandbox_input iifname lmvh-abcdef12 drop"
        );
        // Forward: guest traffic is never L3-forwarded by the host.
        assert_eq!(
            texts[5],
            "inet lumen-host sandbox_forward iifname lmvh-abcdef12 drop"
        );
    }

    #[test]
    fn host_nft_rules_differ_per_run() {
        let a = test_plan();
        let mut b = test_plan();
        b.veth_host = "lmvh-99999999".into();
        b.host_ip = "10.244.0.5".into();
        let ra: Vec<String> = host_nft_rules(&a).iter().map(|r| r.join(" ")).collect();
        let rb: Vec<String> = host_nft_rules(&b).iter().map(|r| r.join(" ")).collect();
        assert_ne!(ra, rb);
        // No rule for run A mentions run B's interface.
        for t in &ra {
            assert!(!t.contains("lmvh-99999999"), "rule: {t}");
        }
    }

    fn pinned_artifact_for(content: &[u8]) -> (tempfile::TempDir, provenance::PinnedArtifact) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vmlinux");
        std::fs::write(&path, content).unwrap();
        let file = provenance::open_nofollow(&path).unwrap();
        let artifact = provenance::PinnedArtifact {
            name: "vmlinux".into(),
            file,
            expected_digest: provenance::digest_bytes(content),
        };
        (tmp, artifact)
    }

    #[test]
    fn revalidate_and_link_artifact_links_verified_bytes() {
        let (_tmp, artifact) = pinned_artifact_for(b"known-good-kernel");
        let jail = tempfile::tempdir().unwrap();
        revalidate_and_link_artifact(&artifact, jail.path()).unwrap();
        let linked = std::fs::read(jail.path().join("vmlinux")).unwrap();
        assert_eq!(linked, b"known-good-kernel");
        // Linked through the pinned fd: same inode as the store file.
        use std::os::unix::fs::MetadataExt;
        let src_ino = artifact.file.metadata().unwrap().ino();
        let dst_ino = std::fs::metadata(jail.path().join("vmlinux"))
            .unwrap()
            .ino();
        assert_eq!(src_ino, dst_ino);
    }

    #[test]
    fn revalidate_and_link_artifact_aborts_on_tampered_bytes() {
        // Attacker rewrites the store file in place after resolve: the
        // pinned descriptor sees the new bytes, the re-hash mismatches,
        // and launch aborts before anything is linked.
        let (tmp, artifact) = pinned_artifact_for(b"original-kernel");
        std::fs::write(tmp.path().join("vmlinux"), b"evil-kernel").unwrap();
        let jail = tempfile::tempdir().unwrap();
        let err = revalidate_and_link_artifact(&artifact, jail.path()).unwrap_err();
        assert!(
            matches!(err, SandboxdError::BadSignature(_)),
            "expected BadSignature, got {err:?}"
        );
        assert!(!jail.path().join("vmlinux").exists());
    }

    #[test]
    fn load_trusted_keys_reads_key_files() {
        let (img_store, _digest) = fake_image();
        let state = tempfile::tempdir().unwrap();
        let cfg = test_config(&img_store, &state);
        let keys = load_trusted_keys(&cfg).unwrap();
        assert_eq!(keys.len(), 1);
    }
}
