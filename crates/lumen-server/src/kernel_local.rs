//! [`KernelClient`] backed by the frozen Phase-0 spike [`LocalKernel`].
//!
//! # The seam
//!
//! Phase-3's host logic speaks its own contract shapes (defined in
//! [`crate::kernel_client`]; they predate the frozen `lumen-protocol`
//! facade), while the kernel speaks the frozen `pi_boundary` contracts.
//! This module is the conversion boundary between the two worlds:
//!
//! - [`LocalKernelClient::decide`] converts the host envelope to the frozen
//!   [`lumen_core::pi_boundary::ActionEnvelope`], calls
//!   [`lumen_core::pi_boundary::Kernel::evaluate`] (lease-chain resolution,
//!   replay protection, audit), and converts the frozen decision back.
//! - [`LocalKernelClient::append_audit`] appends to the kernel's hash-chained
//!   [`lumen_core::pi_boundary::AuditLog`].
//! - [`LocalKernelClient::issue_session_lease`] / `issue_session_child_lease`
//!   mint leases in the kernel registry; [`LocalKernelClient`]'s
//!   `revoke_session` revokes them via
//!   [`lumen_core::pi_boundary::LocalKernel::revoke_lease`].
//!
//! # Honest scope: spike backend, not the Phase-1 lease engine
//!
//! The backend here is `pi_boundary::LocalKernel`, which documents itself
//! as the Phase-0 spike ("stub policy + in-memory lease registry"); Phase 1
//! was to replace the stub policy with the real lease engine. That
//! replacement has not been assembled: the Phase-1 authority primitives
//! exist as separate pieces — `lumen_core::lease` (`mint_root_lease`,
//! `mint_child_lease`, `mint_one_shot_lease`, `SessionRegistry`,
//! `RevocationIndex`, signed `LeaseDocument`), `canonical`, `budget`,
//! `nonce`, `kernel_audit`, and the durable stores in `lumen-db` — but
//! there is no concrete type implementing `pi_boundary::Kernel` over them.
//!
//! Assembling that service is a design decision, not a mechanical port:
//! it must decide key custody (`KernelKeys`), state ownership and
//! threading (`SessionRegistry` / `RevocationIndex` are `&mut`-style
//! in-memory structures), persistence (in-memory vs `lumen-db`), and the
//! async boundary — and then the host envelope conversion in this module
//! must be re-pointed at it. Until that lands, this client proves the
//! conversion boundary and the fail-closed behavior against the spike.
//! Do not describe this client as "the real Phase-1 kernel".
//!
//! Kernel-side semantics are resolved **in favor of frozen**: the digest the
//! kernel audits is the frozen envelope's digest, and the decision logic is
//! the frozen policy. The host-facing `PolicyDecision::bind` check keeps
//! working because the converted decision carries the *host* envelope's
//! digest in `action_digest`.
//!
//! # Lossy mappings (documented, fail-closed)
//!
//! - `expected_effects`: `SecretUse` and `MessageSend` have no counterpart in
//!   the frozen `EffectClasses`; they are preserved on the host envelope but
//!   cannot be expressed to the frozen kernel. (The frozen phase-0 policy
//!   denies anything but a pure read anyway.)
//! - `resources.paths` carry no rights on the host shape; the frozen contract
//!   requires per-resource rights. Paths are marked `Write` when the action
//!   declares `Write`, otherwise `Read`.
//! - `resources.hosts` are `scheme://host:port` strings; they are parsed into
//!   the frozen typed network resources (malformed entries fail the
//!   conversion, fail closed).
//! - `secret_refs` carry no purpose on the host shape; the frozen
//!   `SecretRef.purpose` is left empty.
//! - Host audit kinds are free-form strings; the frozen `AuditEventKind` is a
//!   closed enum. `"tool_committed"` maps to `ToolExecuted`; every other host
//!   kind maps to `ActionProposed`, with the original kind preserved verbatim
//!   at the front of `detail`.
//!
//! # Not wired
//!
//! `verify_lease` and `request_one_shot_lease` return
//! [`crate::kernel_client::KernelError::Unavailable`]. The local kernel
//! backend is the spike lease registry (`LeaseRecord`s keyed by `LeaseId`);
//! it has no signed-`LeaseDocument` API, and the host's `LeaseDocument` /
//! `OneShotGrant` shapes are not wire-compatible with
//! `lumen_core::lease`'s signed types (opaque `scope`/`budget` values,
//! different canonical JSON). Faking verification would be a security lie,
//! so these stay explicitly unwired until a signed-lease backend lands. No
//! live host path calls them (verified by grep over `lumen-server`).

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use lumen_core::pi_boundary::{
    self, AUDIT_EVENT_VERSION, ActionEnvelope as FrozenEnvelope, AuditActor,
    AuditEvent as FrozenAuditEvent, AuditEventKind, AuditLog, DecisionOutcome,
    EffectClasses as FrozenEffectClasses, InputRef as FrozenInputRef, Kernel, LeaseId, LocalKernel,
    NetworkResource as FrozenNet, Obligation as FrozenObligation, PathResource as FrozenPath,
    PathRights as FrozenRights, PolicyDecision as FrozenDecision, ResourceSet as FrozenResources,
    SecretRef as FrozenSecret, ToolRef as FrozenToolRef,
};
use uuid::Uuid;

use crate::kernel_client::{
    ACTION_ENVELOPE_VERSION as HOST_ENVELOPE_VERSION, ActionEnvelope, AuditEvent as HostAuditEvent,
    AuditRef, EffectClass, KernelClient, KernelError, KernelFuture, LeaseDocument,
    LeaseVerification, Obligation, OneShotGrant, POLICY_DECISION_VERSION as HOST_DECISION_VERSION,
    PolicyDecision, now_ms, now_rfc3339, rfc3339_to_ms,
};
use crate::kernel_client::{Decision, EnvelopeError};

/// [`KernelClient`] implementation backed by a real [`LocalKernel`].
///
/// Owns the kernel (shared by `Arc`) plus an index of the leases this
/// client issued per session subject, so `revoke_session` can revoke the
/// real leases through [`LocalKernel::revoke_lease`].
pub struct LocalKernelClient {
    kernel: Arc<LocalKernel>,
    issued: Mutex<HashMap<String, Vec<LeaseId>>>,
}

impl LocalKernelClient {
    pub fn new(kernel: Arc<LocalKernel>) -> Self {
        Self {
            kernel,
            issued: Mutex::new(HashMap::new()),
        }
    }

    /// The underlying kernel (for tests and introspection).
    pub fn kernel(&self) -> &Arc<LocalKernel> {
        &self.kernel
    }

    /// The kernel's audit log (for tests: chain verification).
    pub fn audit_log(&self) -> &AuditLog {
        self.kernel.audit_log()
    }

    /// Mint a real root lease for `subject` in the kernel registry and
    /// track it for [`KernelClient::revoke_session`].
    pub fn issue_session_lease(
        &self,
        subject: &str,
        path_prefixes: Vec<String>,
        verbs: Vec<String>,
        expires_at_ms: i64,
    ) -> Result<LeaseId, KernelError> {
        let id = self
            .kernel
            .issue_root_lease(subject, path_prefixes, verbs, expires_at_ms)
            .map_err(|e| KernelError::Unavailable(e.to_string()))?;
        self.track(subject, id);
        Ok(id)
    }

    /// Mint a real child lease under `parent` and track it for `subject`.
    pub fn issue_session_child_lease(
        &self,
        parent: LeaseId,
        subject: &str,
        path_prefixes: Vec<String>,
        verbs: Vec<String>,
        expires_at_ms: i64,
    ) -> Result<LeaseId, KernelError> {
        let id = self
            .kernel
            .issue_child_lease(parent, subject, path_prefixes, verbs, expires_at_ms)
            .map_err(|e| KernelError::Unavailable(e.to_string()))?;
        self.track(subject, id);
        Ok(id)
    }

    /// Lease ids this client issued for `subject` (test introspection).
    pub fn issued_for(&self, subject: &str) -> Vec<LeaseId> {
        self.issued
            .lock()
            .unwrap()
            .get(subject)
            .cloned()
            .unwrap_or_default()
    }

    fn track(&self, subject: &str, id: LeaseId) {
        self.issued
            .lock()
            .unwrap()
            .entry(subject.to_string())
            .or_default()
            .push(id);
    }
}

/// Convert a host envelope to the frozen contract shape. Structural
/// problems fail the conversion (fail closed); semantic problems (unknown
/// lease, out-of-scope path) are the kernel's decision to make.
fn to_frozen_envelope(env: &ActionEnvelope) -> Result<FrozenEnvelope, KernelError> {
    // Structural validation first: versions, UUID shape, timestamp shape.
    env.validate()?;
    if env.protocol_version != pi_boundary::ACTION_ENVELOPE_VERSION {
        return Err(EnvelopeError::VersionMismatch(
            env.protocol_version,
            pi_boundary::ACTION_ENVELOPE_VERSION,
        )
        .into());
    }
    debug_assert_eq!(
        HOST_ENVELOPE_VERSION,
        pi_boundary::ACTION_ENVELOPE_VERSION,
        "host and frozen envelope versions drifted"
    );

    let action_id = Uuid::parse_str(&env.action_id)
        .map_err(|_| EnvelopeError::BadActionId(env.action_id.clone()))?;

    let arguments = match &env.arguments {
        serde_json::Value::Object(map) => map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        _ => {
            return Err(EnvelopeError::Deserialize(
                "envelope arguments must be a JSON object".to_string(),
            )
            .into());
        }
    };

    let inputs = env
        .input_hashes
        .iter()
        .map(|h| FrozenInputRef {
            content_hash: h.clone(),
            snapshot_id: None,
        })
        .collect();

    let write = env.expected_effects.contains(&EffectClass::Write);
    let paths = env
        .resources
        .paths
        .iter()
        .map(|p| FrozenPath {
            path: p.clone(),
            rights: if write {
                FrozenRights::Write
            } else {
                FrozenRights::Read
            },
        })
        .collect();

    let mut network = Vec::with_capacity(env.resources.hosts.len());
    for dest in &env.resources.hosts {
        network.push(parse_network_dest(dest)?);
    }

    let secrets = env
        .resources
        .secret_refs
        .iter()
        .map(|id| FrozenSecret {
            id: id.clone(),
            // The host shape carries no purpose; the frozen field is
            // required but unused by the phase-0 policy.
            purpose: String::new(),
        })
        .collect();

    let mut effects = FrozenEffectClasses {
        file_read: false,
        file_write: false,
        network_egress: false,
        network_ingress: false,
        process_spawn: false,
    };
    for class in &env.expected_effects {
        match class {
            EffectClass::Read => effects.file_read = true,
            EffectClass::Write => effects.file_write = true,
            // `Network` covers egress here; the frozen contract has no
            // ingress flag expressible from the host shape, and the
            // phase-0 policy denies network actions regardless.
            EffectClass::Network => effects.network_egress = true,
            EffectClass::Execute => effects.process_spawn = true,
            // No frozen counterpart; preserved on the host envelope only.
            EffectClass::SecretUse | EffectClass::MessageSend => {}
        }
    }

    let mut lease_chain = Vec::with_capacity(env.lease_chain.len());
    for id in &env.lease_chain {
        let uuid = Uuid::parse_str(id)
            .map_err(|_| EnvelopeError::Deserialize(format!("bad lease id '{id}'")))?;
        lease_chain.push(LeaseId::from_uuid(uuid));
    }

    let expires_at_ms = rfc3339_to_ms(&env.expires_at)
        .ok_or_else(|| EnvelopeError::BadExpiry(env.expires_at.clone()))?;

    Ok(FrozenEnvelope {
        version: pi_boundary::ACTION_ENVELOPE_VERSION,
        action_id,
        session_id: env.session_id.clone(),
        tool: FrozenToolRef {
            name: env.tool.name.clone(),
            version: env.tool.version.clone(),
        },
        arguments,
        inputs,
        resources: FrozenResources {
            paths,
            network,
            secrets,
        },
        expected_effects: effects,
        lease_chain,
        nonce: env.nonce.clone(),
        expires_at_ms,
    })
}

/// Parse a host `scheme://host:port` destination into the frozen typed shape.
fn parse_network_dest(dest: &str) -> Result<FrozenNet, KernelError> {
    let (scheme, rest) = dest
        .split_once("://")
        .ok_or_else(|| EnvelopeError::Deserialize(format!("bad network destination '{dest}'")))?;
    // `rsplit_once` keeps the port split correct for bracketed IPv6 hosts.
    let (host, port) = rest
        .rsplit_once(':')
        .ok_or_else(|| EnvelopeError::Deserialize(format!("bad network destination '{dest}'")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| EnvelopeError::Deserialize(format!("bad network destination '{dest}'")))?;
    if scheme.is_empty() || host.is_empty() {
        return Err(EnvelopeError::Deserialize(format!("bad network destination '{dest}'")).into());
    }
    Ok(FrozenNet {
        scheme: scheme.to_string(),
        host: host.to_string(),
        port,
    })
}

/// Convert a frozen decision back to the host shape, binding it to the
/// host envelope's digest so [`PolicyDecision::bind`] keeps working.
fn to_host_decision(
    frozen: &FrozenDecision,
    envelope: &ActionEnvelope,
) -> Result<PolicyDecision, KernelError> {
    let action_digest = envelope.digest()?;
    let decision = match &frozen.outcome {
        DecisionOutcome::Allow { obligations } => {
            // The leaf lease (chain head) is what authorized this action.
            let lease_id = envelope
                .lease_chain
                .first()
                .cloned()
                .unwrap_or_else(|| "none".to_string());
            Decision::Allow {
                lease_id,
                obligations: obligations.iter().map(to_host_obligation).collect(),
            }
        }
        DecisionOutcome::Deny { reason } => Decision::Deny {
            reason: format!("{}: {}", reason.code, reason.detail),
        },
        DecisionOutcome::PendingApproval {
            approval_id,
            reason,
        } => Decision::PendingApproval {
            approval_request_id: approval_id.clone(),
            reason: reason.clone(),
        },
    };
    Ok(PolicyDecision {
        protocol_version: HOST_DECISION_VERSION,
        action_digest,
        decision,
        decided_at: now_rfc3339(),
    })
}

fn to_host_obligation(ob: &FrozenObligation) -> Obligation {
    match ob {
        FrozenObligation::TruncateOutput { max_bytes } => Obligation {
            kind: "truncate_output".to_string(),
            params: serde_json::json!({ "max_bytes": max_bytes }),
        },
        FrozenObligation::RedactSecrets => Obligation {
            kind: "redact_secrets".to_string(),
            params: serde_json::json!({}),
        },
        FrozenObligation::RequireSandboxProfile { profile } => Obligation {
            kind: "require_sandbox_profile".to_string(),
            params: serde_json::json!({ "profile": profile }),
        },
    }
}

/// Map a host audit kind onto the frozen closed enum. The original kind is
/// preserved verbatim at the front of `detail`, so no information is lost.
fn map_audit_kind(kind: &str) -> AuditEventKind {
    match kind {
        "tool_committed" => AuditEventKind::ToolExecuted,
        _ => AuditEventKind::ActionProposed,
    }
}

fn to_frozen_audit_event(event: &HostAuditEvent) -> FrozenAuditEvent {
    let payload = serde_json::to_string(&event.payload).unwrap_or_default();
    FrozenAuditEvent {
        version: AUDIT_EVENT_VERSION,
        event_id: Uuid::new_v4(),
        sequence: 0, // assigned by AuditLog::append
        timestamp_ms: now_ms(),
        actor: AuditActor::Session {
            session_id: event.session_id.clone(),
        },
        kind: map_audit_kind(&event.kind),
        session_id: event.session_id.clone(),
        action_digest: event
            .action_digest
            .clone()
            .unwrap_or_else(|| "none".to_string()),
        decision: None,
        detail: format!("host_kind={} payload={}", event.kind, payload),
        prev_hash: String::new(), // assigned by AuditLog::append
        hash: String::new(),      // assigned by AuditLog::append
    }
}

impl KernelClient for LocalKernelClient {
    fn decide<'a>(&'a self, envelope: &'a ActionEnvelope) -> KernelFuture<'a, PolicyDecision> {
        let kernel = Arc::clone(&self.kernel);
        Box::pin(async move {
            let frozen = to_frozen_envelope(envelope)?;
            // The real decision: lease-chain resolution, replay protection,
            // and the kernel's own audit write happen inside `evaluate`.
            let frozen_decision = kernel
                .evaluate(&frozen)
                .map_err(|e| KernelError::Unavailable(e.to_string()))?;
            to_host_decision(&frozen_decision, envelope)
        })
    }

    fn verify_lease<'a>(
        &'a self,
        _lease: &'a LeaseDocument,
    ) -> KernelFuture<'a, LeaseVerification> {
        Box::pin(async move {
            Err(KernelError::Unavailable(
                "verify_lease is not wired to the local kernel backend: the spike lease \
                 registry has no signed-LeaseDocument API (see module docs)"
                    .to_string(),
            ))
        })
    }

    fn request_one_shot_lease<'a>(
        &'a self,
        _grant: &'a OneShotGrant,
    ) -> KernelFuture<'a, crate::kernel_client::LeaseDocument> {
        Box::pin(async move {
            Err(KernelError::Unavailable(
                "request_one_shot_lease is not wired to the local kernel backend: \
                 one-shot minting lives in lumen_core::lease, whose signed types are \
                 not wire-compatible with the host LeaseDocument shape (see module docs)"
                    .to_string(),
            ))
        })
    }

    fn revoke_session<'a>(&'a self, session_subject: &'a str) -> KernelFuture<'a, ()> {
        let kernel = Arc::clone(&self.kernel);
        let ids: Vec<LeaseId> = self
            .issued
            .lock()
            .unwrap()
            .remove(session_subject)
            .unwrap_or_default();
        Box::pin(async move {
            for id in ids {
                kernel
                    .revoke_lease(id)
                    .map_err(|e| KernelError::Unavailable(format!("revoke lease {id}: {e}")))?;
            }
            Ok(())
        })
    }

    fn append_audit<'a>(&'a self, event: &'a HostAuditEvent) -> KernelFuture<'a, AuditRef> {
        let kernel = Arc::clone(&self.kernel);
        let frozen = to_frozen_audit_event(event);
        let event_id = frozen.event_id.to_string();
        Box::pin(async move {
            kernel
                .audit_log()
                .append(frozen)
                .map_err(|e| KernelError::AuditFailed(e.to_string()))?;
            // Read back the stored event for its chain hash.
            let stored = kernel
                .audit_log()
                .events()
                .into_iter()
                .rev()
                .find(|e| e.event_id.to_string() == event_id)
                .ok_or_else(|| {
                    KernelError::AuditFailed("audit event vanished after append".to_string())
                })?;
            Ok(AuditRef {
                event_id,
                chain_hash: stored.hash,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_client::{
        ActionEnvelope as HostEnvelope, ResourceSet, ToolRef, deadline_rfc3339,
    };
    use lumen_core::pi_boundary::LocalKernelConfig;

    fn test_kernel() -> Arc<LocalKernel> {
        Arc::new(LocalKernel::new(LocalKernelConfig::default()))
    }

    fn read_envelope(session: &str, lease_chain: Vec<String>, path: &str) -> HostEnvelope {
        HostEnvelope {
            protocol_version: HOST_ENVELOPE_VERSION,
            action_id: Uuid::new_v4().to_string(),
            session_id: session.to_string(),
            tool: ToolRef {
                name: "bct.read_file".to_string(),
                version: "1.0.0".to_string(),
            },
            arguments: serde_json::json!({ "path": path }),
            input_hashes: vec![],
            resources: ResourceSet {
                paths: vec![path.to_string()],
                hosts: vec![],
                secret_refs: vec![],
            },
            lease_chain,
            nonce: Uuid::new_v4().to_string(),
            expires_at: deadline_rfc3339(60),
            expected_effects: vec![EffectClass::Read],
        }
    }

    #[tokio::test]
    async fn real_kernel_denies_without_lease() {
        let client = LocalKernelClient::new(test_kernel());
        let env = read_envelope("sess-1", vec![], "/leased/a.txt");
        let decision = client.decide(&env).await.expect("decide must not error");
        assert!(matches!(decision.decision, Decision::Deny { .. }));
        // The decision binds to the host envelope: the pipeline's check passes.
        decision
            .bind(&env)
            .expect("decision must bind to its envelope");
        // And the kernel really audited it: the chain verifies.
        client
            .audit_log()
            .verify()
            .expect("audit chain must verify");
        assert!(client.audit_log().len() >= 2); // proposed + denied
    }

    #[tokio::test]
    async fn real_kernel_allows_with_lease_and_denies_after_revoke() {
        let client = LocalKernelClient::new(test_kernel());
        let lease = client
            .issue_session_lease(
                "sess-2",
                vec!["/leased".into()],
                vec!["read".into()],
                now_ms() + 3_600_000,
            )
            .expect("issue lease");
        let chain = vec![lease.to_string()];

        let env = read_envelope("sess-2", chain.clone(), "/leased/a.txt");
        let decision = client.decide(&env).await.expect("decide must not error");
        match &decision.decision {
            Decision::Allow {
                lease_id,
                obligations,
            } => {
                assert_eq!(lease_id, &lease.to_string());
                assert!(!obligations.is_empty());
            }
            other => panic!("expected Allow from the real kernel, got {other:?}"),
        }
        decision.bind(&env).expect("decision must bind");

        // Revoke the session's leases through the real kernel: the next
        // decision must deny (revoked), proving lease revocation is real.
        client.revoke_session("sess-2").await.expect("revoke");
        let env2 = read_envelope("sess-2", chain, "/leased/a.txt");
        let decision2 = client.decide(&env2).await.expect("decide must not error");
        assert!(
            matches!(decision2.decision, Decision::Deny { .. }),
            "revoked lease must deny, got {:?}",
            decision2.decision
        );
        client
            .audit_log()
            .verify()
            .expect("audit chain must verify");
    }

    #[tokio::test]
    async fn real_kernel_denies_out_of_scope_path() {
        let client = LocalKernelClient::new(test_kernel());
        let lease = client
            .issue_session_lease(
                "sess-3",
                vec!["/leased".into()],
                vec!["read".into()],
                now_ms() + 3_600_000,
            )
            .expect("issue lease");
        let env = read_envelope("sess-3", vec![lease.to_string()], "/elsewhere/a.txt");
        let decision = client.decide(&env).await.expect("decide must not error");
        assert!(matches!(decision.decision, Decision::Deny { .. }));
    }

    #[tokio::test]
    async fn append_audit_lands_in_real_chain() {
        let client = LocalKernelClient::new(test_kernel());
        let event = HostAuditEvent {
            kind: "tool_committed".to_string(),
            session_id: "sess-4".to_string(),
            action_digest: Some("abc123".to_string()),
            payload: serde_json::json!({ "tool": "bct.read_file" }),
        };
        let audit_ref = client.append_audit(&event).await.expect("append");
        assert!(!audit_ref.event_id.is_empty());
        assert_eq!(audit_ref.chain_hash.len(), 64);
        // The stored event preserves the host kind verbatim in detail.
        let stored = client
            .audit_log()
            .events()
            .into_iter()
            .find(|e| e.event_id.to_string() == audit_ref.event_id)
            .expect("event must be in the log");
        assert!(stored.detail.starts_with("host_kind=tool_committed"));
        assert_eq!(stored.kind, AuditEventKind::ToolExecuted);
        client
            .audit_log()
            .verify()
            .expect("audit chain must verify");
    }

    #[tokio::test]
    async fn conversion_rejects_structurally_bad_envelopes() {
        let client = LocalKernelClient::new(test_kernel());
        let mut env = read_envelope("sess-5", vec![], "/leased/a.txt");
        env.arguments = serde_json::json!(["not", "an", "object"]);
        let err = client
            .decide(&env)
            .await
            .expect_err("non-object args must fail");
        assert!(matches!(err, KernelError::BadEnvelope(_)));

        let env = read_envelope("sess-5", vec!["not-a-uuid".into()], "/leased/a.txt");
        let err = client
            .decide(&env)
            .await
            .expect_err("bad lease id must fail");
        assert!(matches!(err, KernelError::BadEnvelope(_)));
    }

    #[tokio::test]
    async fn signed_lease_paths_are_honestly_unwired() {
        let client = LocalKernelClient::new(test_kernel());
        let lease = LeaseDocument {
            protocol_version: 1,
            lease_id: "x".into(),
            parent_id: None,
            subject: "s".into(),
            issuer_key_id: "k".into(),
            issued_at_ms: 0,
            scope: serde_json::json!({}),
            limits: crate::kernel_client::LeaseLimits {
                not_before_ms: 0,
                expires_at_ms: 0,
                budget: serde_json::json!({}),
                max_executions: None,
                single_use: false,
            },
            depth: 0,
            depth_limit: 0,
            lease_nonce: "n".into(),
            signature: "sig".into(),
        };
        let err = client
            .verify_lease(&lease)
            .await
            .expect_err("verify_lease must be honestly unwired");
        assert!(matches!(err, KernelError::Unavailable(_)));
    }
}
