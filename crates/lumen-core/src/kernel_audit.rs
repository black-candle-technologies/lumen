//! Kernel audit log: append-only hash-chained audit events with host-key
//! checkpoints.
//!
//! The wire contract is the frozen [`lumen_core::pi_boundary::AuditEvent`]
//! (v1): `version`, `event_id`, `sequence`, `timestamp_ms`, typed
//! [`AuditActor`], typed [`AuditEventKind`], `session_id`, `action_digest`,
//! optional `decision`, `detail` (a canonical JSON string), and the
//! `prev_hash`/`hash` chain link. The kernel appends sealed events, seals
//! checkpoints with the host key, and verifies the chain independently of
//! any store.
//!
//! [`AuditLink`] (checkpoint link records) is a kernel-internal runtime
//! type, not a wire contract: checkpoints are local records, never sent
//! across the trust boundary.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::lease::KernelKeys;
use crate::pi_boundary::{
    AUDIT_EVENT_VERSION, AuditActor, AuditEvent, AuditEventKind, canonical_json,
};

/// Genesis `prev_hash`: the frozen contract uses `"0" * 64` for the first event.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Errors from the kernel audit log.
#[derive(Debug, Error)]
pub enum KernelAuditError {
    #[error("audit chain broken at seq {0}: {1}")]
    ChainBreak(u64, String),
    #[error("checkpoint signature invalid: {0}")]
    BadCheckpoint(String),
    #[error("checkpoint signed by unexpected key {0}")]
    WrongCheckpointKey(String),
    #[error("event field invalid: {0}")]
    BadEvent(String),
    #[error("boundary error: {0}")]
    Boundary(#[from] crate::pi_boundary::BoundaryError),
}

/// A host-key-signed checkpoint over a chain prefix.
///
/// Kernel-internal runtime record (not a wire contract): the signature binds
/// `(key_id, through_seq, chain_hash)` so an independent verifier can confirm
/// the chain prefix without trusting the store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLink {
    pub key_id: String,
    pub through_seq: u64,
    pub chain_hash: String,
    /// Hex-encoded Ed25519 signature over the canonical signing bytes.
    pub signature: String,
}

impl AuditLink {
    fn signing_bytes(&self) -> Result<Vec<u8>, KernelAuditError> {
        let value = serde_json::json!({
            "key_id": self.key_id,
            "through_seq": self.through_seq,
            "chain_hash": self.chain_hash,
        });
        canonical_json(&value).map_err(KernelAuditError::Boundary)
    }

    pub fn sign(&mut self, keys: &KernelKeys) {
        self.key_id = keys.host_key_id.clone();
        // Sign over the final key_id so the signature covers it.
        let bytes = self
            .signing_bytes()
            .expect("checkpoint signing bytes are infallible");
        self.signature = hex::encode(keys.host_sign(&bytes).to_bytes());
    }

    pub fn verify(
        &self,
        key: &ed25519_dalek::VerifyingKey,
        expected_key_id: &str,
    ) -> Result<(), KernelAuditError> {
        if self.key_id != expected_key_id {
            return Err(KernelAuditError::WrongCheckpointKey(self.key_id.clone()));
        }
        let bytes = self.signing_bytes()?;
        let sig = hex::decode(&self.signature)
            .map_err(|e| KernelAuditError::BadCheckpoint(e.to_string()))?;
        let sig = ed25519_dalek::Signature::from_slice(&sig)
            .map_err(|e| KernelAuditError::BadCheckpoint(e.to_string()))?;
        use ed25519_dalek::Verifier;
        key.verify(&bytes, &sig)
            .map_err(|e| KernelAuditError::BadCheckpoint(e.to_string()))?;
        Ok(())
    }
}

/// Storage for audit events and checkpoints. The log owns sequencing and
/// sealing; the store is a dumb append-only sink.
pub trait AuditStore {
    fn append_event(&mut self, event: AuditEvent);
    fn checkpoint(&mut self, link: AuditLink);
    fn events(&self) -> &[AuditEvent];
    fn checkpoints(&self) -> &[AuditLink];
}

/// Shared in-memory store for tests and single-process kernels.
#[derive(Default)]
pub struct MemoryAuditStore {
    events: Vec<AuditEvent>,
    checkpoints: Vec<AuditLink>,
}

impl AuditStore for MemoryAuditStore {
    fn append_event(&mut self, event: AuditEvent) {
        self.events.push(event);
    }

    fn checkpoint(&mut self, link: AuditLink) {
        self.checkpoints.push(link);
    }

    fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    fn checkpoints(&self) -> &[AuditLink] {
        &self.checkpoints
    }
}

/// The kernel audit log: sequences, seals, and hash-chains frozen
/// [`AuditEvent`]s, and anchors checkpoints with the host key.
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

    fn prev_link(&self) -> (u64, String) {
        match self.store.events().last() {
            Some(e) => (e.sequence + 1, e.hash.clone()),
            None => (0, GENESIS_PREV_HASH.to_string()),
        }
    }

    /// Append one event: redacts secrets from `details`, assigns the next
    /// sequence number, seals the hash chain, and stores the event.
    ///
    /// `decision` is the kernel's decision summary (`"allow"`, `"deny"`,
    /// `"pending"`) or `None` when the event is not a policy decision.
    /// `detail` is stored as a canonical JSON string per the frozen contract.
    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &mut self,
        actor: &str,
        kind: AuditEventKind,
        session_id: &str,
        action_digest: &str,
        decision: Option<&str>,
        now_ms: i64,
        details: Value,
    ) -> Result<AuditEvent, KernelAuditError> {
        // The frozen contract allows `"none"` for transport-level events; only
        // an empty digest is rejected.
        if action_digest.is_empty() {
            return Err(KernelAuditError::BadEvent(
                "action_digest must not be empty".to_string(),
            ));
        }
        let actor_ty = parse_actor(actor)?;
        let detail = render_detail(&details)?;
        let (sequence, prev_hash) = self.prev_link();
        let mut event = AuditEvent {
            version: AUDIT_EVENT_VERSION,
            event_id: uuid::Uuid::new_v4(),
            sequence,
            timestamp_ms: now_ms,
            actor: actor_ty,
            kind,
            session_id: session_id.to_string(),
            action_digest: action_digest.to_string(),
            decision: decision.map(str::to_string),
            detail,
            prev_hash,
            hash: String::new(),
        };
        let hash = event
            .compute_hash(&event.prev_hash)
            .map_err(KernelAuditError::Boundary)?;
        event.hash = hash;
        self.store.append_event(event.clone());
        Ok(event)
    }

    /// Checkpoint the chain through `through_seq` with the host key.
    pub fn checkpoint(
        &mut self,
        through_seq: u64,
        keys: &KernelKeys,
    ) -> Result<AuditLink, KernelAuditError> {
        let event = self
            .store
            .events()
            .iter()
            .find(|e| e.sequence == through_seq)
            .ok_or_else(|| KernelAuditError::BadEvent(format!("no event at seq {through_seq}")))?;
        let mut link = AuditLink {
            key_id: String::new(),
            through_seq,
            chain_hash: event.hash.clone(),
            signature: String::new(),
        };
        link.sign(keys);
        self.store.checkpoint(link.clone());
        Ok(link)
    }

    /// Verify the full chain plus every checkpoint, in order.
    pub fn verify(
        &self,
        host_key: &ed25519_dalek::VerifyingKey,
        expected_key_id: &str,
    ) -> Result<(), KernelAuditError> {
        verify_event_chain(self.store.events())?;
        for cp in self.store.checkpoints() {
            cp.verify(host_key, expected_key_id)?;
            // The checkpoint must anchor a real chain prefix.
            let anchored = self
                .store
                .events()
                .iter()
                .find(|e| e.sequence == cp.through_seq)
                .is_some_and(|e| e.hash == cp.chain_hash);
            if !anchored {
                return Err(KernelAuditError::BadCheckpoint(format!(
                    "checkpoint through seq {} does not match the chain",
                    cp.through_seq
                )));
            }
        }
        Ok(())
    }
}

/// Verify a slice of frozen audit events: version, gapless sequencing from
/// 0, and every `prev_hash`/`hash` link recomputed independently.
pub fn verify_event_chain(events: &[AuditEvent]) -> Result<(), KernelAuditError> {
    let mut prev_hash = GENESIS_PREV_HASH.to_string();
    for (i, e) in events.iter().enumerate() {
        if e.version != AUDIT_EVENT_VERSION {
            return Err(KernelAuditError::ChainBreak(
                e.sequence,
                format!("unsupported audit event version {}", e.version),
            ));
        }
        if e.sequence != i as u64 {
            return Err(KernelAuditError::ChainBreak(
                e.sequence,
                format!("sequence gap: expected {i}, found {}", e.sequence),
            ));
        }
        if e.prev_hash != prev_hash {
            return Err(KernelAuditError::ChainBreak(
                e.sequence,
                "prev_hash does not match previous event hash".to_string(),
            ));
        }
        let recomputed = e
            .compute_hash(&e.prev_hash)
            .map_err(KernelAuditError::Boundary)?;
        if recomputed != e.hash {
            return Err(KernelAuditError::ChainBreak(
                e.sequence,
                "event hash does not recompute".to_string(),
            ));
        }
        prev_hash = e.hash.clone();
    }
    Ok(())
}

/// Parse a kernel actor string into the frozen [`AuditActor`].
///
/// `"kernel"` → [`AuditActor::Kernel`]; an `ed25519:`-prefixed subject →
/// [`AuditActor::Session`]; anything else → [`AuditActor::Human`].
/// Parse the kernel's canonical actor string back into a typed [`AuditActor`].
///
/// This is the inverse of [`actor_to_string`]: `"kernel"` maps to
/// [`AuditActor::Kernel`], `"ed25519:<id>"` to [`AuditActor::Session`], and
/// anything else to [`AuditActor::Human`]. The full `"ed25519:..."` string is
/// retained in `session_id`, matching the frozen fixture semantics.
pub fn parse_actor(actor: &str) -> Result<AuditActor, KernelAuditError> {
    if actor.is_empty() {
        return Err(KernelAuditError::BadEvent(
            "actor must not be empty".to_string(),
        ));
    }
    Ok(if actor == "kernel" {
        AuditActor::Kernel
    } else if actor.starts_with("ed25519:") {
        AuditActor::Session {
            session_id: actor.to_string(),
        }
    } else {
        AuditActor::Human {
            subject: actor.to_string(),
        }
    })
}

/// The kernel's canonical string form of a typed [`AuditActor`], used as the
/// durable actor column in the database. Round-trips through [`parse_actor`].
pub fn actor_to_string(actor: &AuditActor) -> String {
    match actor {
        AuditActor::Kernel => "kernel".to_string(),
        AuditActor::Session { session_id } => session_id.clone(),
        AuditActor::Human { subject } => subject.clone(),
    }
}

/// Redact secrets from `details` and render the canonical JSON string the
/// frozen audit contract stores in `AuditEvent.detail`. Shared by the
/// in-memory log and durable stores so both seal byte-identical details.
pub fn render_detail(details: &Value) -> Result<String, KernelAuditError> {
    let mut redacted = details.clone();
    redact_details(&mut redacted);
    let detail_bytes = canonical_json(&redacted).map_err(KernelAuditError::Boundary)?;
    String::from_utf8(detail_bytes)
        .map_err(|e| KernelAuditError::BadEvent(format!("detail not UTF-8: {e}")))
}

/// Seal a fully-formed [`AuditEvent`] against its previous chain link:
/// assigns `prev_hash` and computes `hash` per the frozen contract. Used by
/// durable stores that assign their own sequence numbers (the in-memory log
/// above seals through [`KernelAuditLog::append`] instead).
pub fn seal_event(mut event: AuditEvent, prev_hash: &str) -> Result<AuditEvent, KernelAuditError> {
    event.prev_hash = prev_hash.to_string();
    event.hash = event
        .compute_hash(prev_hash)
        .map_err(KernelAuditError::Boundary)?;
    Ok(event)
}

/// Provenance queries over a verified event slice.
pub struct AuditQueries<'a> {
    events: &'a [AuditEvent],
}

impl<'a> AuditQueries<'a> {
    pub fn new(events: &'a [AuditEvent]) -> Self {
        Self { events }
    }

    /// All events mentioning an action digest.
    pub fn events_for_action(&self, action_digest: &str) -> Vec<&'a AuditEvent> {
        self.events
            .iter()
            .filter(|e| e.action_digest == action_digest)
            .collect()
    }

    /// All events by an actor. The actor may be given as the kernel actor
    /// string (`"kernel"`, `"ed25519:<id>"`, or a human subject).
    pub fn events_for_actor(&self, actor: &str) -> Vec<&'a AuditEvent> {
        let parsed = parse_actor(actor);
        self.events
            .iter()
            .filter(|e| parsed.as_ref().is_ok_and(|want| &e.actor == want))
            .collect()
    }

    /// All events whose detail mentions a lease id.
    pub fn events_for_lease(&self, lease_id: &str) -> Vec<&'a AuditEvent> {
        self.events
            .iter()
            .filter(|e| detail_field(&e.detail, "lease_id").as_deref() == Some(lease_id))
            .collect()
    }

    /// All events for a lease plus every event for any ancestor lease named
    /// in `ancestors` (leaf → root order).
    pub fn events_for_lease_ancestry(
        &self,
        lease_id: &str,
        ancestors: &[String],
    ) -> Vec<&'a AuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                detail_field(&e.detail, "lease_id")
                    .is_some_and(|id| id == lease_id || ancestors.iter().any(|a| a == &id))
            })
            .collect()
    }

    /// All events tied to an approval request id.
    pub fn events_for_approval(&self, approval_id: &str) -> Vec<&'a AuditEvent> {
        self.events
            .iter()
            .filter(|e| detail_field(&e.detail, "approval_id").as_deref() == Some(approval_id))
            .collect()
    }

    /// Chain-ordered window, for paged inspection.
    pub fn events_in_range(&self, from_seq: u64, to_seq: u64) -> Vec<&'a AuditEvent> {
        self.events
            .iter()
            .filter(|e| e.sequence >= from_seq && e.sequence <= to_seq)
            .collect()
    }

    /// Index: action digest → first seq mentioning it.
    pub fn action_index(&self) -> HashMap<&str, u64> {
        let mut index = HashMap::new();
        for e in self.events {
            if !e.action_digest.is_empty() {
                index.entry(e.action_digest.as_str()).or_insert(e.sequence);
            }
        }
        index
    }
}

/// Extract a string field from an event's canonical-JSON detail.
fn detail_field(detail: &str, field: &str) -> Option<String> {
    let value: Value = serde_json::from_str(detail).ok()?;
    value.get(field)?.as_str().map(str::to_string)
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// Secret used exactly once; redacts on Debug/Serialize, exposes explicitly.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str("[REDACTED]")
    }
}

/// Redact secret-shaped values in place, deterministically: key names
/// matching secret patterns, or string values that look like credentials,
/// become `"[REDACTED]"`. Runs before canonicalization so redaction is part
/// of the sealed bytes.
pub fn redact_details(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if k == "secret_refs" {
                    // References are opaque identifiers, not secrets.
                    continue;
                }
                if is_secret_key(k) {
                    *v = Value::String("[REDACTED]".to_string());
                } else {
                    redact_details(v);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                match item {
                    Value::String(s) if looks_like_secret_value(s) => {
                        *item = Value::String("[REDACTED]".to_string());
                    }
                    _ => redact_details(item),
                }
            }
        }
        Value::String(s) if looks_like_secret_value(s) => {
            *s = "[REDACTED]".to_string();
        }
        Value::String(_) => {}
        _ => {}
    }
}

fn is_secret_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    [
        "secret",
        "password",
        "passwd",
        "token",
        "api_key",
        "apikey",
        "cookie",
        "credential",
    ]
    .iter()
    .any(|pat| lower.contains(pat))
}

fn looks_like_secret_value(s: &str) -> bool {
    // Heuristic: sk-… shaped bearer tokens. Key-name redaction covers the
    // rest; values under innocent keys are left alone unless they look like
    // credentials.
    s.starts_with("sk-") && s.len() > 8
}

#[cfg(test)]
mod tests {
    use super::*;
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
                AuditEventKind::PolicyAllowed,
                "ed25519:session-1",
                "ef12fc688bf209abc99880f536068f00b051c504230654cf3f69f5173b80ed07",
                Some("allow"),
                1000,
                json!({"lease_id": "lease-1", "api_key": "sk-secret-value", "note": "ok"}),
            )
            .unwrap();
        assert_eq!(e0.sequence, 0);
        assert_eq!(e0.prev_hash, GENESIS_PREV_HASH);
        // The secret never entered the chain: detail is canonical JSON with
        // the redaction marker sealed in.
        let detail: Value = serde_json::from_str(&e0.detail).unwrap();
        assert_eq!(detail["api_key"], json!("[REDACTED]"));
        assert_eq!(detail["note"], json!("ok"));
        assert_eq!(e0.actor, AuditActor::Kernel);
        assert_eq!(e0.kind, AuditEventKind::PolicyAllowed);
        let e1 = log
            .append(
                "kernel",
                AuditEventKind::PolicyDenied,
                "ed25519:session-1",
                "ef12fc688bf209abc99880f536068f00b051c504230654cf3f69f5173b80ed07",
                Some("deny"),
                2000,
                json!({}),
            )
            .unwrap();
        assert_eq!(e1.sequence, 1);
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
        let digest = "ef12fc688bf209abc99880f536068f00b051c504230654cf3f69f5173b80ed07";
        log.append(
            "kernel",
            AuditEventKind::PolicyAllowed,
            "ed25519:session-1",
            digest,
            Some("allow"),
            1000,
            json!({"lease_id": "l1"}),
        )
        .unwrap();
        log.append(
            "kernel",
            AuditEventKind::PolicyDenied,
            "ed25519:session-1",
            digest,
            Some("deny"),
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
            if e.sequence == 0 {
                e.decision = Some("tampered".to_string());
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
        log2.append(
            "kernel",
            AuditEventKind::PolicyAllowed,
            "ed25519:session-1",
            digest,
            Some("allow"),
            1000,
            json!({}),
        )
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
        let digest = "ef12fc688bf209abc99880f536068f00b051c504230654cf3f69f5173b80ed07";
        log.append(
            "ed25519:session",
            AuditEventKind::PolicyAllowed,
            "session",
            digest,
            Some("allow"),
            1000,
            json!({"lease_id": "lease-9", "approval_id": "appr-9"}),
        )
        .unwrap();
        log.append(
            "kernel",
            AuditEventKind::PolicyDenied,
            "session",
            "none",
            Some("deny"),
            2000,
            json!({}),
        )
        .unwrap();
        let q = AuditQueries::new(log.store().events());
        assert_eq!(q.events_for_action(digest).len(), 1);
        assert_eq!(q.events_for_actor("ed25519:session").len(), 1);
        assert_eq!(q.events_for_lease("lease-9").len(), 1);
        assert_eq!(q.events_for_approval("appr-9").len(), 1);
        assert_eq!(q.events_in_range(0, 0).len(), 1);
        assert_eq!(q.action_index()[digest], 0);
    }

    #[test]
    fn actor_parsing() {
        assert_eq!(parse_actor("kernel").unwrap(), AuditActor::Kernel);
        // The full "ed25519:..." address is retained, matching the frozen
        // fixture semantics ("session_id":"ed25519:fixture-session-address").
        assert_eq!(
            parse_actor("ed25519:abc").unwrap(),
            AuditActor::Session {
                session_id: "ed25519:abc".to_string()
            }
        );
        assert_eq!(
            parse_actor("riley").unwrap(),
            AuditActor::Human {
                subject: "riley".to_string()
            }
        );
        assert!(parse_actor("").is_err());
    }

    #[test]
    fn actor_string_round_trips() {
        for s in ["kernel", "ed25519:abc", "riley"] {
            assert_eq!(actor_to_string(&parse_actor(s).unwrap()), s);
        }
    }
}
