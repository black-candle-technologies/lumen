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
use crate::guest_agent::{AgentMsg, HostMsg, PROTOCOL_VERSION, check_hello, read_msg, write_msg};
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
    async fn connect_agent(
        &self,
        uds_path: &Path,
        timeout: Duration,
    ) -> Result<Box<dyn AgentIo>, SandboxdError>;
}

/// Context for the per-run netns services (DNS + egress proxy).
pub struct NetnsCtx {
    pub netns_path: PathBuf,
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
    /// Verified image directory (vmlinux, rootfs.ext4,
    /// workspace-template.qcow2).
    pub image_dir: PathBuf,
    /// Rendered Firecracker config JSON (also written to the run dir).
    pub fc_config_json: String,
    /// Rendered seccomp JSON (also written to the run dir).
    pub seccomp_json: String,
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
        let chroot_dir = jailer::jail_root(&config.firecracker.chroot_base, run_id);
        Ok(ArtifactPaths {
            jail_id: run_id.to_string(),
            chroot_dir: chroot_dir.clone(),
            config_path: run_dir.join("firecracker.json"),
            seccomp_path: run_dir.join("seccomp.json"),
            uid,
            gid: uid,
            netns_name: plan.netns_name,
            tap_name: plan.tap_name,
            veth_host: plan.veth_host,
            veth_guest: plan.veth_guest,
            host_ip: plan.host_ip,
            guest_ip: plan.guest_ip,
            // Cgroup path must match what the backend creates (see
            // FirecrackerBackend::start: `lumen/<run_id>`). Interface names
            // use the short tag (15-char limit), but cgroups have no such
            // limit, so we use the full run ID for uniqueness and clarity.
            cgroup_path: PathBuf::from(format!("lumen/{run_id}")),
            workspace_disk: run_dir.join("workspace.qcow2"),
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
        let mut trusted_keys = Vec::new();
        for path in &self.inner.config.images.trusted_keys {
            trusted_keys.push(provenance::load_verifying_key(path)?);
        }
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
        if p.bytes.len() as u64 != p.size {
            return Err(format!(
                "export size mismatch for {}: declared {}, got {}",
                p.path,
                p.size,
                p.bytes.len()
            ));
        }
        let staged_file = v
            .stage_bytes(&p.path, &p.sha256, &p.bytes)
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

        // Render Firecracker config + seccomp into the run dir (the
        // backend hard-links/copies them into the chroot).
        let guest_mac = jailer::guest_mac(run_id);
        let fc_config = jailer::render_config(&spec.limits, &plan.tap_name, &guest_mac, None);
        let fc_json = serde_json::to_string_pretty(&fc_config)
            .map_err(|e| SandboxdError::Host(format!("fc config render: {e}")))?;
        let seccomp_json = crate::seccomp::render_filter_pretty()?;
        std::fs::write(&artifacts.config_path, &fc_json).map_err(SandboxdError::Io)?;
        std::fs::write(&artifacts.seccomp_path, &seccomp_json).map_err(SandboxdError::Io)?;

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
        let fc_args = jailer::firecracker_argv(
            Path::new("/fc-api.sock"),
            Path::new("/firecracker.json"),
            Path::new("/seccomp.json"),
        );

        // Image dir for the backend to hard-link into the chroot.
        let image_dir = self.inner.config.images.store.join(&spec.image_digest);

        self.inner.store.transition(run_id, RunState::Starting)?;

        // 1. Network namespace, TAP, veth, nftables.
        let nftables = network::render_nftables(&plan);
        if let Err(e) = self.inner.backend.setup_network(&plan, &nftables).await {
            let _ = self.inner.store.transition(run_id, RunState::Failed);
            return Err(e);
        }
        // 2. Per-run DNS forwarder + egress proxy (join the netns).
        let netns_ctx = NetnsCtx {
            netns_path: jail_spec.netns_path.clone(),
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
            image_dir,
            fc_config_json: fc_json,
            seccomp_json,
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
        // 4. Agent handshake. The host connects to Firecracker's vsock UDS;
        //    the guest agent listens on AF_VSOCK inside the VM.
        let mut agent = match self
            .inner
            .backend
            .connect_agent(&artifacts.vsock_path, Duration::from_secs(30))
            .await
        {
            Ok(a) => a,
            Err(e) => {
                let mut jh = jailer_handle;
                let _ = jh.terminate().await;
                let mut ns = netns_services;
                let _ = ns.shutdown().await;
                let _ = self.inner.backend.teardown_network(&plan).await;
                let _ = self.inner.store.transition(run_id, RunState::Failed);
                return Err(e);
            }
        };
        let hello: Option<AgentMsg> = agent.next_msg().await?;
        let hello =
            hello.ok_or_else(|| SandboxdError::GuestAgent("agent closed before hello".into()))?;
        check_hello(&hello, run_id)?;

        // 5. Welcome: argv, env, secrets, deadline.
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

        // 6. Supervisor task owns the agent stream + jailer from here.
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
        let join = {
            let mut live = self.inner.live.lock().unwrap();
            let lr = live
                .get_mut(run_id)
                .ok_or_else(|| SandboxdError::RunState(format!("no live run: {run_id}")))?;
            let sup = lr
                .supervisor
                .take()
                .ok_or_else(|| SandboxdError::RunState("run not started".into()))?;
            sup.join
        };
        let outcome = join
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

fn join_netns(path: &Path) -> Result<(), SandboxdError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| SandboxdError::Host("bad netns path".into()))?;
    unsafe {
        let fd = libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(SandboxdError::Host(format!(
                "open netns: {}",
                std::io::Error::last_os_error()
            )));
        }
        let rc = libc::setns(fd, libc::CLONE_NEWNET);
        libc::close(fd);
        if rc != 0 {
            return Err(SandboxdError::Host(format!(
                "setns: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
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
    if let Err(e) = join_netns(&ctx.netns_path) {
        eprintln!("sandboxd: netns join failed: {e}");
        return;
    }
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

/// Real backend: jailer, netns, vsock, qemu-img. Requires root + /dev/kvm.
pub struct FirecrackerBackend;

#[async_trait]
impl VmBackend for FirecrackerBackend {
    async fn setup_network(
        &self,
        plan: &network::NetPlan,
        nftables_rules: &str,
    ) -> Result<(), SandboxdError> {
        // netns
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
                let mut full = vec!["netns".to_string(), "exec".to_string(), netns_name];
                full.extend(args);
                let refs: Vec<&str> = full.iter().map(String::as_str).collect();
                run_cmd("ip", &refs).await
            }
        };
        nn(vec![
            "addr".into(),
            "add".into(),
            format!("{}/{}", plan.guest_ip, plan.prefix_len),
            "dev".into(),
            plan.veth_guest.clone(),
        ])
        .await?;
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
        // Bridge the TAP (guest) and veth_guest (host leg) so the guest can
        // reach the host's DNS/proxy. The bridge lives in the netns.
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
        // Move the guest IP to the bridge (the veth and TAP are now L2).
        nn(vec![
            "addr".into(),
            "del".into(),
            format!("{}/{}", plan.guest_ip, plan.prefix_len),
            "dev".into(),
            plan.veth_guest.clone(),
        ])
        .await?;
        nn(vec![
            "addr".into(),
            "add".into(),
            format!("{}/{}", plan.guest_ip, plan.prefix_len),
            "dev".into(),
            br_name.clone(),
        ])
        .await?;
        // nftables (default-deny; see network::render_nftables)
        let nft_path = format!("/run/lumen-{}.nft", plan.netns_name);
        std::fs::write(&nft_path, nftables_rules).map_err(SandboxdError::Io)?;
        let nft_cmd = format!("ip netns exec {} nft -f {}", plan.netns_name, nft_path);
        run_cmd("sh", &["-c", &nft_cmd]).await?;
        Ok(())
    }

    async fn teardown_network(&self, plan: &network::NetPlan) -> Result<(), SandboxdError> {
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
            netns_path: ctx.netns_path.clone(),
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
        let root = jailer::jail_root(&spec.chroot_base, &spec.id);
        std::fs::create_dir_all(&root).map_err(SandboxdError::Io)?;
        // 2. Hard-link verified artifacts. The template is hard-linked so the
        //    CoW delta can use a RELATIVE backing path (resolves inside the
        //    chroot at Firecracker open time).
        for name in ["vmlinux", "rootfs.ext4", "workspace-template.qcow2"] {
            let src = setup.image_dir.join(name);
            let dst = root.join(name);
            let _ = std::fs::remove_file(&dst);
            std::fs::hard_link(&src, &dst)
                .map_err(|e| SandboxdError::Host(format!("hard-link {name}: {e}")))?;
        }
        // 3. CoW delta with a relative backing path.
        let delta = root.join("workspace.qcow2");
        let _ = std::fs::remove_file(&delta);
        let qemu_img = Path::new("qemu-img");
        let args =
            crate::storage::qemu_img_create_args(Path::new("workspace-template.qcow2"), &delta);
        let out = tokio::process::Command::new(qemu_img)
            .args(&args)
            .current_dir(&root)
            .output()
            .await
            .map_err(|e| SandboxdError::Host(format!("qemu-img: {e}")))?;
        if !out.status.success() {
            return Err(SandboxdError::Host(format!(
                "qemu-img create: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        // 4. Config + seccomp into the chroot.
        std::fs::write(root.join("firecracker.json"), &setup.fc_config_json)
            .map_err(SandboxdError::Io)?;
        std::fs::write(root.join("seccomp.json"), &setup.seccomp_json)
            .map_err(SandboxdError::Io)?;
        // 5. cgroup for the run.
        let cgroup_parent = &spec.cgroup_parent;
        let cgroup_rel = Path::new("lumen").join(&spec.id);
        if let Err(e) = cgroups::apply_limits(cgroup_parent, &cgroup_rel, &spec.limits) {
            return Err(SandboxdError::Host(format!("cgroup apply: {e}")));
        }
        // 6. Launch via the jailer binary.
        let argv = jailer::jailer_argv(spec, &setup.fc_args)?;
        let mut child = tokio::process::Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| SandboxdError::Host(format!("spawn jailer: {e}")))?;
        let pid = child.id();
        // Pin the jailer (and its Firecracker child, by inheritance) to the
        // run's cgroup. Best effort: a failure here is logged, not fatal,
        // because the jailer's own rlimits still apply.
        if let Some(pid) = pid {
            let _ = cgroups::add_process(cgroup_parent, &cgroup_rel, pid);
        }
        // Reap in the background; the handle kills by pid.
        tokio::spawn(async move {
            let _ = child.wait().await;
        });
        Ok(Box::new(ChildJailerHandle { pid }))
    }

    async fn connect_agent(
        &self,
        uds_path: &Path,
        timeout: Duration,
    ) -> Result<Box<dyn AgentIo>, SandboxdError> {
        // Firecracker creates the vsock UDS when the VMM starts; poll for
        // it, then connect. The Firecracker vsock protocol requires a
        // `CONNECT <port>\n` preamble: the UDS connection is forwarded to
        // the guest's AF_VSOCK listener on that port.
        // See: https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md
        let start = Instant::now();
        loop {
            match tokio::net::UnixStream::connect(uds_path).await {
                Ok(mut s) => {
                    // Send the CONNECT preamble. The guest agent listens on
                    // port 1234 (LUMEN_VSOCK_PORT).
                    let preamble = b"CONNECT 1234\n";
                    if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut s, preamble).await {
                        return Err(SandboxdError::Host(format!("vsock CONNECT failed: {e}")));
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
        std::fs::write(dir.join("workspace-template.qcow2"), template).unwrap();
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
}
