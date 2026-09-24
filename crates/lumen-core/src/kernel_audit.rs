//! Kernel audit foundation (Phase 1D): append-only hash-chained events,
//! host-key checkpoints, secret-safe redaction, and provenance queries.
//!
//! Events are [`lumen_protocol::AuditEvent`] v1 records: `seq`, `prev_hash`,
//! `hash` form a tamper-evident chain (see the phase-0 contract). The kernel
//! appends through [`KernelAuditLog`], which enforces redaction before an
//! event is constructed — secrets must never reach the `details` field.
//!
//! Periodically the kernel signs a checkpoint ([`lumen_protocol::AuditLink`])
//! with the host key, bounding the damage window of a host compromise.
//! Verification is independent: [`verify_chain_with_checkpoints`] replays the
//! chain and checks every checkpoint signature from the host *verifying* key.
//!
//! Queries reconstruct provenance: action digest → session → lease ancestry →
//! approval → run. Lease ancestry resolution needs the lease store; the query
//! helpers take the pieces they need so they stay pure.

use std::collections::HashMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use lumen_protocol::{
    AUDIT_EVENT_VERSION, AuditError, AuditEvent, AuditLink,
    audit::{append, verify_chain},
    canonical,
};

use crate::lease::{KernelKeys, LeaseResolver, ms_to_rfc3339};

#[derive(Debug, Error)]
pub enum KernelAuditError {
    #[error("audit contract error: {0}")]
    Contract(#[from] AuditError),
    #[error("canonicalization failed")]
    Canonical,
    #[error("bad checkpoint signature")]
    BadCheckpointSignature,
    #[error("checkpoint for seq {0} does not match chain hash {1}")]
    CheckpointMismatch(u64, String),
    #[error("checkpoint key {0} is not the host key")]
    WrongCheckpointKey(String),
    #[error("no events to checkpoint")]
    EmptyChain,
    #[error("encoding error: {0}")]
    Encoding(String),
}

// ---------------------------------------------------------------------------
// Deterministic redaction
// ---------------------------------------------------------------------------

/// Object keys whose values are always secrets. Matched case-insensitively.
/// `secret_refs` is deliberately NOT in this list: references are opaque
/// identifiers the kernel needs for queries; the secret material itself never
/// appears in audit details.
const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "auth_token",
    "access_token",
    "refresh_token",
    "id_token",
    "bearer",
    "authorization",
    "private_key",
    "privatekey",
    "client_secret",
    "signing_key",
    "seed",
    "seed_phrase",
    "mnemonic",
    "credentials",
    "cookie",
    "set_cookie",
];

/// Prefixes that mark a *value* as secret material regardless of its key.
const SENSITIVE_VALUE_PREFIXES: &[&str] = &[
    "sk-",
    "sk-ant-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "AKIA",
    "-----BEGIN",
];

pub const REDACTED: &str = "[REDACTED]";

/// Deterministically redact secrets from a JSON value, in place. Same input
/// always produces the same output; redacted values carry no information
/// about the original length or content.
pub fn redact_details(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                if SENSITIVE_KEYS.iter().any(|k| k.eq_ignore_ascii_case(key)) {
                    *val = Value::String(REDACTED.to_string());
                } else {
                    redact_details(val);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_details(item);
            }
        }
        Value::String(s) if SENSITIVE_VALUE_PREFIXES.iter().any(|p| s.starts_with(p)) => {
            *s = REDACTED.to_string();
        }
        Value::String(_) => {}
        _ => {}
    }
}

/// A wrapper whose serialized and debug forms never reveal the inner value.
/// Use for secret material that must cross a function boundary near audit
/// code.
pub struct Secret<T>(T);

impl<T> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T> Serialize for Secret<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED)
    }
}

// ---------------------------------------------------------------------------
// Append-only log
// ---------------------------------------------------------------------------

/// Where sealed events go. The in-memory implementation backs tests; the
/// database implementation lives in `lumen-db`.
pub trait AuditStore {
    fn append_event(&mut self, event: AuditEvent);
    fn events(&self) -> &[AuditEvent];
    fn checkpoint(&mut self, link: AuditLink);
    fn checkpoints(&self) -> &[AuditLink];
}

#[derive(Default)]
pub struct MemoryAuditStore {
    events: Vec<AuditEvent>,
    checkpoints: Vec<AuditLink>,
}

impl AuditStore for MemoryAuditStore {
    fn append_event(&mut self, event: AuditEvent) {
        self.events.push(event);
    }

    fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    fn checkpoint(&mut self, link: AuditLink) {
        self.checkpoints.push(link);
    }

    fn checkpoints(&self) -> &[AuditLink] {
        &self.checkpoints
    }
}

/// The kernel's audit log: seals events into the hash chain, redacts details,
/// and issues host-key checkpoints.
pub struct KernelAuditLog<S: AuditStore> {
    store: S,
}

impl<S: AuditStore> KernelAuditLog<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// Append an event. `details` are redacted deterministically *before*
    /// the event is sealed, so no secret can enter the chain even if the
    /// caller forgot.
    pub fn append(
        &mut self,
        actor: &str,
        action_digest: &str,
        decision: &str,
        now_ms: i64,
        mut details: Value,
    ) -> Result<AuditEvent, KernelAuditError> {
        redact_details(&mut details);
        let prev = self.store.events().last();
        let seq = prev.map(|e| e.seq + 1).unwrap_or(0);
        let event = AuditEvent {
            protocol_version: AUDIT_EVENT_VERSION,
            seq,
            ts: ms_to_rfc3339(now_ms),
            actor: actor.to_string(),
            action_digest: action_digest.to_string(),
            decision: decision.to_string(),
            prev_hash: String::new(),
            hash: String::new(),
            details,
        };
        let sealed = append(prev, event)?;
        self.store.append_event(sealed.clone());
        Ok(sealed)
    }

    /// Sign a checkpoint over the chain prefix ending at `upto_seq`
    /// (inclusive) with the host key.
    pub fn checkpoint(
        &mut self,
        upto_seq: u64,
        keys: &KernelKeys,
    ) -> Result<AuditLink, KernelAuditError> {
        let event = self
            .store
            .events()
            .iter()
            .find(|e| e.seq == upto_seq)
            .ok_or(KernelAuditError::EmptyChain)?;
        let bytes = checkpoint_signing_bytes(upto_seq, &event.hash, &keys.host_key_id)?;
        let signature = hex::encode(keys.host_sign(&bytes).to_bytes());
        let link = AuditLink {
            seq: upto_seq,
            hash: event.hash.clone(),
            signature,
            key_id: keys.host_key_id.clone(),
        };
        self.store.checkpoint(link.clone());
        Ok(link)
    }

    /// Verify the full chain plus every stored checkpoint against the host
    /// *verifying* key. Reports the first break found: gaps are visible.
    pub fn verify(
        &self,
        host_key: &VerifyingKey,
        expected_key_id: &str,
    ) -> Result<(), KernelAuditError> {
        let events = self.store.events();
        verify_chain(events)?;
        for link in self.store.checkpoints() {
            if link.key_id != expected_key_id {
                return Err(KernelAuditError::WrongCheckpointKey(link.key_id.clone()));
            }
            let event = events
                .iter()
                .find(|e| e.seq == link.seq)
                .ok_or_else(|| KernelAuditError::CheckpointMismatch(link.seq, link.hash.clone()))?;
            if event.hash != link.hash {
                return Err(KernelAuditError::CheckpointMismatch(
                    link.seq,
                    link.hash.clone(),
                ));
            }
            let bytes = checkpoint_signing_bytes(link.seq, &link.hash, &link.key_id)?;
            let sig_bytes: [u8; 64] = hex::decode(&link.signature)
                .map_err(|_| KernelAuditError::BadCheckpointSignature)?
                .try_into()
                .map_err(|_| KernelAuditError::BadCheckpointSignature)?;
            host_key
                .verify(&bytes, &Signature::from_bytes(&sig_bytes))
                .map_err(|_| KernelAuditError::BadCheckpointSignature)?;
        }
        Ok(())
    }
}

/// Canonical bytes covered by a checkpoint signature. Public so the durable
/// (SQL) audit store signs checkpoints over exactly the same bytes as the
/// in-memory kernel log.
pub fn checkpoint_signing_bytes(
    seq: u64,
    hash: &str,
    key_id: &str,
) -> Result<Vec<u8>, KernelAuditError> {
    #[derive(Serialize)]
    struct CheckpointView<'a> {
        protocol: &'a str,
        seq: u64,
        hash: &'a str,
        key_id: &'a str,
    }
    let view = CheckpointView {
        protocol: "lumen-audit-checkpoint/v1",
        seq,
        hash,
        key_id,
    };
    let value =
        serde_json::to_value(view).map_err(|e| KernelAuditError::Encoding(e.to_string()))?;
    canonical::canonical_json(&value)
        .map(|s| s.into_bytes())
        .map_err(|_| KernelAuditError::Canonical)
}

/// Verify an externally supplied chain and checkpoint set (independent
/// verification path, e.g. for auditors holding only the host verifying key).
pub fn verify_chain_with_checkpoints(
    events: &[AuditEvent],
    checkpoints: &[AuditLink],
    host_key: &VerifyingKey,
    expected_key_id: &str,
) -> Result<(), KernelAuditError> {
    let mut store = MemoryAuditStore::default();
    for e in events {
        store.append_event(e.clone());
    }
    for c in checkpoints {
        store.checkpoint(c.clone());
    }
    KernelAuditLog::new(store).verify(host_key, expected_key_id)
}

// ---------------------------------------------------------------------------
// Provenance queries
// ---------------------------------------------------------------------------

/// Query helpers over a sealed event slice. Lease-ancestry queries resolve
/// through the lease store: from any action digest we reach the lease, and
/// from the lease we walk to the root.
pub struct AuditQueries<'a> {
    events: &'a [AuditEvent],
}

impl<'a> AuditQueries<'a> {
    pub fn new(events: &'a [AuditEvent]) -> Self {
        Self { events }
    }

    /// All events for one action digest, in chain order.
    pub fn events_for_action(&self, action_digest: &str) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| e.action_digest == action_digest)
            .collect()
    }

    /// All events by one actor (session address, `kernel`, or `host`).
    pub fn events_for_actor(&self, actor: &str) -> Vec<&AuditEvent> {
        self.events.iter().filter(|e| e.actor == actor).collect()
    }

    /// Events that reference a lease id in their details.
    pub fn events_for_lease(&self, lease_id: &str) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                e.details
                    .get("lease_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id == lease_id)
            })
            .collect()
    }

    /// Events for a full lease ancestry, leaf → root.
    pub fn events_for_lease_ancestry(
        &self,
        leaf_lease_id: &str,
        leases: &dyn LeaseResolver,
    ) -> Vec<&AuditEvent> {
        let mut ids = vec![leaf_lease_id.to_string()];
        let mut current = leaf_lease_id.to_string();
        for _ in 0..128 {
            match leases.lease(&current).and_then(|d| d.parent_id.clone()) {
                Some(parent) => {
                    ids.push(parent.clone());
                    current = parent;
                }
                None => break,
            }
        }
        let id_set: std::collections::HashSet<&str> = ids.iter().map(String::as_str).collect();
        self.events
            .iter()
            .filter(|e| {
                e.details
                    .get("lease_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id_set.contains(id))
            })
            .collect()
    }

    /// Events for one approval request id.
    pub fn events_for_approval(&self, approval_id: &str) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                e.details
                    .get("approval_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id == approval_id)
            })
            .collect()
    }

    /// Chain-ordered window, for paged inspection.
    pub fn events_in_range(&self, from_seq: u64, to_seq: u64) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| e.seq >= from_seq && e.seq <= to_seq)
            .collect()
    }

    /// Index: action digest → first seq mentioning it.
    pub fn action_index(&self) -> HashMap<&str, u64> {
        let mut index = HashMap::new();
        for e in self.events {
            if !e.action_digest.is_empty() {
                index.entry(e.action_digest.as_str()).or_insert(e.seq);
            }
        }
        index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lumen_protocol::audit::GENESIS_PREV_HASH;
    use serde_json::json;

    fn test_log() -> KernelAuditLog<MemoryAuditStore> {
        KernelAuditLog::new(MemoryAuditStore::default())
    }

    #[test]
    fn append_chains_and_redacts() {
        let mut log = test_log();
        let e0 = log
            .append(
                "kernel",
                "digest-1",
                "lease.allow",
                1000,
                json!({"lease_id": "lease-1", "api_key": "sk-secret-value", "note": "ok"}),
            )
            .unwrap();
        assert_eq!(e0.seq, 0);
        assert_eq!(e0.prev_hash, GENESIS_PREV_HASH);
        // The secret never entered the chain.
        assert_eq!(e0.details["api_key"], json!("[REDACTED]"));
        assert_eq!(e0.details["note"], json!("ok"));
        let e1 = log
            .append("kernel", "digest-1", "lease.deny", 2000, json!({}))
            .unwrap();
        assert_eq!(e1.seq, 1);
        assert_eq!(e1.prev_hash, e0.hash);
        // With no checkpoints, verification reduces to chain verification.
        let keys = KernelKeys::generate();
        log.verify(&keys.host_verifying(), &keys.host_key_id)
            .unwrap();
    }

    #[test]
    fn checkpoint_and_verify() {
        let keys = KernelKeys::generate();
        let mut log = test_log();
        log.append(
            "kernel",
            "d1",
            "lease.allow",
            1000,
            json!({"lease_id": "l1"}),
        )
        .unwrap();
        log.append(
            "kernel",
            "d2",
            "lease.deny",
            2000,
            json!({"lease_id": "l2"}),
        )
        .unwrap();
        let link = log.checkpoint(1, &keys).unwrap();
        assert_eq!(link.key_id, keys.host_key_id);
        log.verify(&keys.host_verifying(), &keys.host_key_id)
            .unwrap();

        // Tampering with a sealed event breaks verification.
        let mut tampered = MemoryAuditStore::default();
        for e in log.store().events() {
            let mut e = e.clone();
            if e.seq == 0 {
                e.decision = "lease.allow.tampered".to_string();
            }
            tampered.append_event(e);
        }
        for c in log.store().checkpoints() {
            tampered.checkpoint(c.clone());
        }
        let bad = KernelAuditLog::new(tampered);
        assert!(
            bad.verify(&keys.host_verifying(), &keys.host_key_id)
                .is_err()
        );

        // A checkpoint signed by a different key is rejected.
        let other = KernelKeys::generate();
        let mut log2 = test_log();
        log2.append("kernel", "d1", "lease.allow", 1000, json!({}))
            .unwrap();
        log2.checkpoint(0, &other).unwrap();
        assert!(matches!(
            log2.verify(&keys.host_verifying(), &keys.host_key_id),
            Err(KernelAuditError::WrongCheckpointKey(_))
        ));
    }

    #[test]
    fn redaction_is_deterministic() {
        let mut a = json!({
            "Password": "hunter2",
            "nested": {"access_token": "tok", "safe": 1},
            "list": [{"cookie": "c"}, "sk-abc123"],
            "secret_refs": ["db-password"],
        });
        redact_details(&mut a);
        let mut b = a.clone();
        redact_details(&mut b);
        assert_eq!(a, b);
        assert_eq!(a["Password"], json!("[REDACTED]"));
        assert_eq!(a["nested"]["access_token"], json!("[REDACTED]"));
        assert_eq!(a["list"][0]["cookie"], json!("[REDACTED]"));
        assert_eq!(a["list"][1], json!("[REDACTED]"));
        // References survive: they are opaque identifiers, not secrets.
        assert_eq!(a["secret_refs"], json!(["db-password"]));
    }

    #[test]
    fn secret_wrapper_never_leaks() {
        let s = Secret::new("super-secret-value".to_string());
        assert_eq!(format!("{s:?}"), "[REDACTED]");
        assert_eq!(serde_json::to_value(&s).unwrap(), json!("[REDACTED]"));
        assert_eq!(s.expose(), "super-secret-value");
    }

    #[test]
    fn queries_find_provenance() {
        let mut log = test_log();
        log.append(
            "ed25519:session",
            "digest-9",
            "lease.allow",
            1000,
            json!({"lease_id": "lease-9", "approval_id": "appr-9"}),
        )
        .unwrap();
        log.append("kernel", "", "checkpoint", 2000, json!({}))
            .unwrap();
        let q = AuditQueries::new(log.store().events());
        assert_eq!(q.events_for_action("digest-9").len(), 1);
        assert_eq!(q.events_for_actor("ed25519:session").len(), 1);
        assert_eq!(q.events_for_lease("lease-9").len(), 1);
        assert_eq!(q.events_for_approval("appr-9").len(), 1);
        assert_eq!(q.events_in_range(0, 0).len(), 1);
        assert_eq!(q.action_index()["digest-9"], 0);
    }
}
