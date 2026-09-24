//! Outbound effect model: typed verbs, lease-scoped authority, idempotency,
//! receipt persistence, and fail-closed audit gating.
//!
//! Every outbound messaging effect flows through [`OutboundPipeline`]:
//!
//! 1. Validate the request (verb-specific required fields).
//! 2. Idempotency check — a replayed key returns the stored receipt; the
//!    provider is never called twice for one key.
//! 3. Kernel lease check over a [`lumen_core::action::ActionEnvelope`] whose
//!    kind is the verb (`message.send`, `message.edit`, ...) and whose
//!    capability scope names the exact target resource.
//! 4. Pre-send audit record. If audit persistence is unavailable, the send
//!    is BLOCKED — reasoning may continue, sending may not.
//! 5. Adapter executes the provider call with the kernel-brokered credential.
//! 6. Receipt persisted and post-send audit recorded.
//!
//! TODO(PHASE4): when the kernel gains per-verb capability names
//! (`message.edit`, `message.moderate`, ...), map each verb to its own
//! [`lumen_core::capability::CapabilityName`] here. Until then all verbs
//! carry `message.send` and are distinguished by action kind.

use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use lumen_core::{
    action::{ActionEnvelope, ActionId, ActionKind, CanonicalValue, RunId},
    capability::{Capability, CapabilityName, ResourceScope, ScopeError},
    identity::{ComponentId, IdentityError, PrincipalId, WorkspaceId},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    adapters::{AdapterError, MessagingAdapter, ProviderReceipt},
    attachments::AttachmentRef,
    envelope::{ConnectionId, Conversation, EnvelopeError, Provider, ProviderMessageId},
};

/// Distinct leased verbs. Send, edit, react, delete, moderate, and upload are
/// separate verbs so a lease for `message.send` never authorizes a delete.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundVerb {
    Send,
    Edit,
    React,
    Delete,
    Moderate,
    Upload,
}

impl OutboundVerb {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Edit => "edit",
            Self::React => "react",
            Self::Delete => "delete",
            Self::Moderate => "moderate",
            Self::Upload => "upload",
        }
    }

    /// Kernel action kind for the verb: `message.send`, `message.edit`, ...
    pub fn action_kind(self) -> ActionKind {
        ActionKind::new(format!("message.{}", self.as_str()))
            .expect("verb action kinds are statically valid")
    }

    /// Capability name for the verb.
    ///
    /// TODO(PHASE4): split into per-verb names when the kernel defines them.
    pub const fn capability_name(self) -> CapabilityName {
        CapabilityName::MessageSend
    }
}

/// Idempotency key: one UUIDv4 per intended effect. Replays with the same key
/// return the stored receipt without touching the provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct IdempotencyKey(Uuid);

impl IdempotencyKey {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_str(&self) -> String {
        self.0.to_string()
    }
}

impl Default for IdempotencyKey {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Where the effect lands. Scoped to the exact resource for lease checks.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundTarget {
    Conversation(Conversation),
    DirectRecipient { external_id: String },
}

impl OutboundTarget {
    /// Typed policy resource type, e.g. `messaging.channel`.
    pub const fn resource_type(&self) -> &'static str {
        match self {
            Self::Conversation(_) => "messaging.channel",
            Self::DirectRecipient { .. } => "messaging.recipient",
        }
    }

    /// Exact scope value, e.g. `discord:channel:123` or `courier:dm:ed25519:...`.
    pub fn scope_value(&self, provider: Provider) -> String {
        match self {
            Self::Conversation(conversation) => {
                let mut value =
                    format!("{}:channel:{}", provider.as_str(), conversation.channel_id);
                if let Some(server) = &conversation.server_id {
                    value.push_str(&format!(":server:{server}"));
                }
                if let Some(thread) = &conversation.thread_id {
                    value.push_str(&format!(":thread:{thread}"));
                }
                value
            }
            Self::DirectRecipient { external_id } => {
                format!("{}:dm:{external_id}", provider.as_str())
            }
        }
    }

    /// Human/operator-safe summary without secrets.
    pub fn summary(&self, provider: Provider) -> String {
        match self {
            Self::Conversation(conversation) => {
                format!("{} channel {}", provider.as_str(), conversation.channel_id)
            }
            Self::DirectRecipient { .. } => format!("{} direct message", provider.as_str()),
        }
    }
}

/// VHL approval carried on an outbound request.
///
/// The kernel mints the approval (immutable action digest + nonce); the
/// adapter only *carries* these fields so the provider message can reference
/// the exact approved effect. This type never mints digests or nonces.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VhlApprovalCarriage {
    /// Opaque approval id, carried as a string (kernel-minted).
    pub approval_id: String,
    /// Immutable digest of the approved [`ActionEnvelope`] (kernel-minted).
    pub action_digest: String,
    /// Single-use nonce (kernel-minted).
    pub nonce: String,
    pub expires_at_millis: i64,
}

impl VhlApprovalCarriage {
    pub fn new(
        approval_id: impl Into<String>,
        action_digest: impl Into<String>,
        nonce: impl Into<String>,
        expires_at_millis: i64,
    ) -> Result<Self, OutboundError> {
        let approval_id = approval_id.into();
        let action_digest = action_digest.into();
        let nonce = nonce.into();
        if action_digest.is_empty() || action_digest.len() > 128 {
            return Err(OutboundError::InvalidApprovalCarriage {
                field: "action_digest",
            });
        }
        if nonce.is_empty() || nonce.len() > 128 {
            return Err(OutboundError::InvalidApprovalCarriage { field: "nonce" });
        }
        Ok(Self {
            approval_id,
            action_digest,
            nonce,
            expires_at_millis,
        })
    }

    /// Build the carriage from the phase-4 backend's real approval request.
    /// The kernel mints the request; the outbound path only carries the
    /// reference. Validation still applies: a malformed kernel request
    /// fails here rather than on the wire.
    pub fn from_vhl_request(
        request: &lumen_core::vhl::VhlApprovalRequest,
    ) -> Result<Self, OutboundError> {
        Self::new(
            request.request_id.clone(),
            request.action_digest.clone(),
            request.nonce.clone(),
            request.expires_at_ms,
        )
    }
}

/// A single outbound messaging effect awaiting kernel authorization.
#[derive(Clone, Debug)]
pub struct OutboundRequest {
    pub verb: OutboundVerb,
    pub idempotency_key: IdempotencyKey,
    pub provider: Provider,
    pub connection_id: ConnectionId,
    pub target: OutboundTarget,
    pub text: Option<String>,
    /// The provider message being edited/reacted-to/deleted.
    pub target_message_id: Option<ProviderMessageId>,
    /// Emoji or provider reaction token for [`OutboundVerb::React`].
    pub reaction: Option<String>,
    pub attachment_refs: Vec<AttachmentRef>,
    /// VHL approval reference carried with the message, when the effect was
    /// approved through VHL rather than a lease.
    pub approval: Option<VhlApprovalCarriage>,
    pub actor: PrincipalId,
    pub workspace_id: WorkspaceId,
    pub run_id: RunId,
    pub requesting_component: ComponentId,
}

impl OutboundRequest {
    /// Verb-specific validation. Runs before any lease check or provider call.
    pub fn validate(&self) -> Result<(), OutboundError> {
        match self.verb {
            OutboundVerb::Send | OutboundVerb::Upload => {
                let has_text = self.text.as_ref().is_some_and(|t| !t.trim().is_empty());
                if !has_text && self.attachment_refs.is_empty() {
                    return Err(OutboundError::Validation {
                        reason: "send/upload requires text or attachments",
                    });
                }
                if self.target_message_id.is_some() {
                    return Err(OutboundError::Validation {
                        reason: "send/upload must not set target_message_id",
                    });
                }
            }
            OutboundVerb::Edit => {
                if self.target_message_id.is_none() {
                    return Err(OutboundError::Validation {
                        reason: "edit requires target_message_id",
                    });
                }
                if !self.text.as_ref().is_some_and(|t| !t.trim().is_empty()) {
                    return Err(OutboundError::Validation {
                        reason: "edit requires non-empty text",
                    });
                }
            }
            OutboundVerb::React => {
                if self.target_message_id.is_none() || self.reaction.is_none() {
                    return Err(OutboundError::Validation {
                        reason: "react requires target_message_id and reaction",
                    });
                }
            }
            OutboundVerb::Delete | OutboundVerb::Moderate => {
                if self.target_message_id.is_none() {
                    return Err(OutboundError::Validation {
                        reason: "delete/moderate requires target_message_id",
                    });
                }
            }
        }
        if let Some(text) = &self.text
            && text.chars().count() > crate::envelope::MAX_CONTENT_CHARS
        {
            return Err(OutboundError::Validation {
                reason: "text exceeds maximum content size",
            });
        }
        Ok(())
    }

    /// Builds the kernel [`ActionEnvelope`] for the lease check. The action
    /// digest binds the exact effect: verb, provider, connection, exact
    /// target scope, idempotency key, and a SHA-256 of the content (the raw
    /// text is included so the kernel's own fingerprint covers it).
    pub fn to_action_envelope(&self) -> Result<ActionEnvelope, OutboundError> {
        let scope = ResourceScope::exact(
            self.target.resource_type(),
            self.target.scope_value(self.provider),
        )
        .map_err(OutboundError::Scope)?;
        let capability = Capability::new(self.verb.capability_name(), scope);

        let mut args = vec![
            ("verb", CanonicalValue::from(self.verb.as_str())),
            ("provider", CanonicalValue::from(self.provider.as_str())),
            (
                "connection_id",
                CanonicalValue::from(self.connection_id.as_str()),
            ),
            (
                "idempotency_key",
                CanonicalValue::from(self.idempotency_key.as_str()),
            ),
            (
                "target",
                CanonicalValue::from(self.target.scope_value(self.provider)),
            ),
        ];
        if let Some(text) = &self.text {
            let mut hasher = Sha256::new();
            hasher.update(text.as_bytes());
            args.push((
                "content_sha256",
                CanonicalValue::from(format!("{:x}", hasher.finalize())),
            ));
            args.push(("text", CanonicalValue::from(text.clone())));
        }
        if let Some(message_id) = &self.target_message_id {
            args.push((
                "target_message_id",
                CanonicalValue::from(message_id.as_str()),
            ));
        }
        if let Some(reaction) = &self.reaction {
            args.push(("reaction", CanonicalValue::from(reaction.clone())));
        }
        if let Some(approval) = &self.approval {
            args.push((
                "approval_digest",
                CanonicalValue::from(approval.action_digest.clone()),
            ));
            args.push((
                "approval_nonce",
                CanonicalValue::from(approval.nonce.clone()),
            ));
        }

        Ok(ActionEnvelope::new(
            ActionId::new(),
            self.run_id,
            self.workspace_id,
            self.actor.clone(),
            self.requesting_component.clone(),
            self.verb.action_kind(),
            CanonicalValue::object(args),
            vec![capability],
        ))
    }

    /// Stable fingerprint of the exact effect this request describes: verb,
    /// provider, connection, target scope, and content. Stored in the
    /// [`DeliveryReceipt`] so a replayed idempotency key for a *different*
    /// request fails instead of returning a foreign receipt.
    pub fn action_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        let mut field = |value: &str| {
            hasher.update(value.as_bytes());
            hasher.update([0]);
        };
        field(self.verb.as_str());
        field(self.provider.as_str());
        field(self.connection_id.as_str());
        field(&self.target.scope_value(self.provider));
        field(
            self.target_message_id
                .as_ref()
                .map(|id| id.as_str())
                .unwrap_or(""),
        );
        field(self.reaction.as_deref().unwrap_or(""));
        field(self.text.as_deref().unwrap_or(""));
        format!("{:x}", hasher.finalize())
    }
}

/// Kernel integration seam for outbound effects.
///
/// TODO(PHASE4): this trait's real implementation lives behind the kernel's
/// lease/policy/audit services. Phase-4 also lands the session-identity API;
/// when it does, `check_lease` callers should bind the ephemeral per-session
/// Courier identity as the actor rather than a long-lived principal.
pub trait KernelPort: Send + Sync {
    /// Evaluates the action against leases/policy. `Err` blocks the effect.
    fn check_lease(&self, action: &ActionEnvelope) -> Result<(), LeaseDenial>;
    /// Persists an audit event. `Err` blocks the effect (fail closed).
    fn record_audit(&self, event: &OutboundAuditEvent) -> Result<(), AuditUnavailable>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseDenial {
    pub reason: String,
}

impl std::fmt::Display for LeaseDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl LeaseDenial {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditUnavailable {
    pub reason: String,
}

impl AuditUnavailable {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// Audit event for an outbound messaging effect. Carries no secrets and no
/// raw provider credentials — only the idempotency key and target summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundAuditEvent {
    pub idempotency_key: IdempotencyKey,
    pub verb: OutboundVerb,
    pub provider: Provider,
    pub target_summary: String,
    pub phase: AuditPhase,
    pub outcome: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditPhase {
    PreSend,
    PostSend,
}

/// Provider receipt correlated to the idempotency key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeliveryReceipt {
    pub idempotency_key: IdempotencyKey,
    pub provider: Provider,
    pub provider_message_id: String,
    pub verb: OutboundVerb,
    /// [`OutboundRequest::action_fingerprint`] of the request that produced
    /// this receipt. A replayed key for a *different* request fails instead
    /// of returning a foreign receipt.
    pub action_fingerprint: String,
    pub sent_at_millis: i64,
}

/// Outcome of atomically reserving an idempotency key.
#[derive(Clone, Debug)]
pub enum KeyReservation {
    /// A completed send already recorded this receipt: return it without
    /// touching the provider.
    Existing(DeliveryReceipt),
    /// Another caller already holds the reservation: the provider must not be
    /// called again for this key right now. Retry later with the same key.
    InFlight,
    /// This caller owns the send. It must [`ReceiptStore::complete`] on
    /// success or [`ReceiptStore::abandon`] on failure so later retries can
    /// proceed.
    Reserved,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReceiptError {
    #[error("receipt store unavailable")]
    Unavailable,
}

/// Idempotency-keyed receipt persistence.
///
/// Reservation is atomic: two concurrent `reserve` calls for the same key can
/// never both return [`KeyReservation::Reserved`], so the provider is never
/// called twice for one key. A poisoned lock maps to
/// [`ReceiptError::Unavailable`] — fail closed, never treated as missing.
pub trait ReceiptStore: Send + Sync {
    fn reserve(&self, key: &IdempotencyKey) -> Result<KeyReservation, ReceiptError>;
    fn complete(&self, receipt: DeliveryReceipt) -> Result<(), ReceiptError>;
    /// Releases a reservation without recording a receipt (the send failed
    /// or was blocked after reserving). Best-effort: on a poisoned lock the
    /// reservation stays in-flight and later retries fail closed with
    /// `InFlight` until the process restarts.
    fn abandon(&self, key: &IdempotencyKey);
}

#[derive(Debug, Default)]
pub struct MemoryReceiptStore {
    inner: Mutex<MemoryReceipts>,
}

#[derive(Debug, Default)]
struct MemoryReceipts {
    completed: HashMap<IdempotencyKey, DeliveryReceipt>,
    in_flight: HashSet<IdempotencyKey>,
}

impl MemoryReceiptStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ReceiptStore for MemoryReceiptStore {
    fn reserve(&self, key: &IdempotencyKey) -> Result<KeyReservation, ReceiptError> {
        let mut inner = self.inner.lock().map_err(|_| ReceiptError::Unavailable)?;
        if let Some(receipt) = inner.completed.get(key) {
            return Ok(KeyReservation::Existing(receipt.clone()));
        }
        if !inner.in_flight.insert(*key) {
            return Ok(KeyReservation::InFlight);
        }
        Ok(KeyReservation::Reserved)
    }

    fn complete(&self, receipt: DeliveryReceipt) -> Result<(), ReceiptError> {
        let mut inner = self.inner.lock().map_err(|_| ReceiptError::Unavailable)?;
        inner.in_flight.remove(&receipt.idempotency_key);
        inner.completed.insert(receipt.idempotency_key, receipt);
        Ok(())
    }

    fn abandon(&self, key: &IdempotencyKey) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.in_flight.remove(key);
        }
    }
}

/// Executes outbound requests through the kernel gates.
///
/// The pipeline owns no provider credentials and performs no provider I/O
/// itself; the adapter does, with the kernel-brokered credential handle.
pub struct OutboundPipeline<K: KernelPort, R: ReceiptStore> {
    kernel: K,
    receipts: R,
}

impl<K: KernelPort, R: ReceiptStore> OutboundPipeline<K, R> {
    pub fn new(kernel: K, receipts: R) -> Self {
        Self { kernel, receipts }
    }

    /// Executes one outbound effect:
    /// validate -> provider/connection binding -> capability -> idempotency
    /// reservation -> lease -> pre-send audit -> provider call -> receipt ->
    /// post-send audit.
    pub async fn execute<A: MessagingAdapter>(
        &self,
        adapter: &A,
        request: &OutboundRequest,
    ) -> Result<DeliveryReceipt, OutboundError> {
        request.validate()?;

        // The adapter must be the one this request was authorized for: the
        // provider and the bound connection are checked before the lease
        // check, so a request authorized for one connection can never
        // execute through an adapter bound to another.
        if adapter.provider() != request.provider {
            return Err(OutboundError::Validation {
                reason: "adapter provider does not match request provider",
            });
        }
        match adapter.bound_connection_id() {
            Some(bound) if bound == &request.connection_id => {}
            _ => {
                return Err(OutboundError::ConnectionMismatch {
                    reason: "adapter is not bound to the request connection",
                });
            }
        }

        // Declared-capability check: the adapter must declare the verb it is
        // asked to execute.
        if !adapter
            .descriptor()
            .capabilities
            .outbound_verbs
            .iter()
            .any(|verb| verb == request.verb.as_str())
        {
            return Err(OutboundError::UnsupportedVerb { verb: request.verb });
        }

        // Idempotency reservation BEFORE the lease check. The reservation is
        // atomic, so two concurrent sends for one key cannot both reach the
        // provider: the second sees Existing or InFlight.
        let fingerprint = request.action_fingerprint();
        match self.receipts.reserve(&request.idempotency_key) {
            Ok(KeyReservation::Reserved) => {}
            Ok(KeyReservation::InFlight) => {
                return Err(OutboundError::IdempotencyConflict {
                    reason: "a send for this idempotency key is already in flight",
                });
            }
            Ok(KeyReservation::Existing(receipt)) => {
                // The key must identify the same effect: a reused key for a
                // different request fails instead of returning a foreign
                // receipt.
                if receipt.action_fingerprint != fingerprint {
                    return Err(OutboundError::Validation {
                        reason: "idempotency key was already used for a different request",
                    });
                }
                return Ok(receipt);
            }
            Err(unavailable) => {
                return Err(OutboundError::ReceiptUnavailable {
                    reason: unavailable.to_string(),
                });
            }
        }

        // From here the reservation is ours: every exit path completes or
        // abandons it, so a later retry of the same key can proceed.
        let outcome = self.send_once(adapter, request, fingerprint).await;
        match outcome {
            Ok(receipt) => {
                self.receipts
                    .complete(receipt.clone())
                    .map_err(|unavailable| OutboundError::ReceiptUnavailable {
                        reason: unavailable.to_string(),
                    })?;

                // Post-send audit failure is surfaced with the receipt
                // attached: the message already went out, so the caller must
                // reconcile rather than retry (retrying would violate
                // idempotency).
                if let Err(unavailable) = self.kernel.record_audit(&OutboundAuditEvent {
                    idempotency_key: request.idempotency_key,
                    verb: request.verb,
                    provider: request.provider,
                    target_summary: request.target.summary(request.provider),
                    phase: AuditPhase::PostSend,
                    outcome: "sent".to_owned(),
                }) {
                    return Err(OutboundError::PostSendAuditFailed {
                        receipt,
                        reason: unavailable.reason,
                    });
                }

                Ok(receipt)
            }
            Err(err) => {
                self.receipts.abandon(&request.idempotency_key);
                Err(err)
            }
        }
    }

    /// Lease -> pre-send audit -> provider call. Runs only after the caller
    /// has reserved the idempotency key.
    async fn send_once<A: MessagingAdapter>(
        &self,
        adapter: &A,
        request: &OutboundRequest,
        fingerprint: String,
    ) -> Result<DeliveryReceipt, OutboundError> {
        let action = request.to_action_envelope()?;

        self.kernel
            .check_lease(&action)
            .map_err(OutboundError::LeaseDenied)?;

        // Fail closed: no audit persistence, no send.
        self.kernel
            .record_audit(&OutboundAuditEvent {
                idempotency_key: request.idempotency_key,
                verb: request.verb,
                provider: request.provider,
                target_summary: request.target.summary(request.provider),
                phase: AuditPhase::PreSend,
                outcome: "authorized".to_owned(),
            })
            .map_err(|unavailable| OutboundError::AuditUnavailable {
                reason: unavailable.reason,
            })?;

        let provider_receipt: ProviderReceipt =
            adapter
                .execute_outbound(request)
                .await
                .map_err(|err| match err {
                    AdapterError::NotBound
                    | AdapterError::Revoked { .. }
                    | AdapterError::AuthLost { .. }
                    | AdapterError::Disabled => OutboundError::AdapterBlocked {
                        reason: err.to_string(),
                    },
                    other => OutboundError::Adapter {
                        reason: other.to_string(),
                    },
                })?;

        Ok(DeliveryReceipt {
            idempotency_key: request.idempotency_key,
            provider: request.provider,
            provider_message_id: provider_receipt.provider_message_id,
            verb: request.verb,
            action_fingerprint: fingerprint,
            sent_at_millis: now_millis(),
        })
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum OutboundError {
    #[error("outbound request invalid: {reason}")]
    Validation { reason: &'static str },
    #[error("lease denied: {0}")]
    LeaseDenied(LeaseDenial),
    #[error("audit persistence unavailable, send blocked: {reason}")]
    AuditUnavailable { reason: String },
    #[error("adapter blocked the effect: {reason}")]
    AdapterBlocked { reason: String },
    #[error("adapter error: {reason}")]
    Adapter { reason: String },
    #[error("adapter does not declare support for verb {verb:?}")]
    UnsupportedVerb { verb: OutboundVerb },
    #[error("adapter is not bound to the request connection: {reason}")]
    ConnectionMismatch { reason: &'static str },
    #[error("idempotency key is already in flight; retry later with the same key: {reason}")]
    IdempotencyConflict { reason: &'static str },
    #[error("receipt store unavailable, send blocked: {reason}")]
    ReceiptUnavailable { reason: String },
    #[error("post-send audit failed; receipt persisted, reconcile instead of retrying: {reason}")]
    PostSendAuditFailed {
        receipt: DeliveryReceipt,
        reason: String,
    },
    #[error("invalid approval carriage field: {field}")]
    InvalidApprovalCarriage { field: &'static str },
    #[error("scope error: {0}")]
    Scope(#[from] ScopeError),
    #[error("envelope error: {0}")]
    Envelope(#[from] EnvelopeError),
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub struct TestKernelPort {
        pub lease: Result<(), LeaseDenial>,
        pub audit: Result<(), AuditUnavailable>,
        pub fail_post_send_audit: bool,
        pub seen_actions: Mutex<Vec<String>>,
    }

    impl TestKernelPort {
        pub fn allow() -> Self {
            Self {
                lease: Ok(()),
                audit: Ok(()),
                fail_post_send_audit: false,
                seen_actions: Mutex::new(Vec::new()),
            }
        }

        pub fn deny_lease(reason: &str) -> Self {
            Self {
                lease: Err(LeaseDenial::new(reason)),
                audit: Ok(()),
                fail_post_send_audit: false,
                seen_actions: Mutex::new(Vec::new()),
            }
        }

        pub fn audit_down(reason: &str) -> Self {
            Self {
                lease: Ok(()),
                audit: Err(AuditUnavailable::new(reason)),
                fail_post_send_audit: false,
                seen_actions: Mutex::new(Vec::new()),
            }
        }
    }

    impl KernelPort for TestKernelPort {
        fn check_lease(&self, action: &ActionEnvelope) -> Result<(), LeaseDenial> {
            self.seen_actions
                .lock()
                .unwrap()
                .push(action.kind().as_str().to_owned());
            self.lease.clone()
        }

        fn record_audit(&self, event: &OutboundAuditEvent) -> Result<(), AuditUnavailable> {
            if self.fail_post_send_audit && event.phase == AuditPhase::PostSend {
                return Err(AuditUnavailable::new("post-send store down"));
            }
            self.audit.clone()
        }
    }

    pub fn test_request(verb: OutboundVerb) -> OutboundRequest {
        OutboundRequest {
            verb,
            idempotency_key: IdempotencyKey::new(),
            provider: Provider::Courier,
            connection_id: ConnectionId::new("conn-1").unwrap(),
            target: OutboundTarget::DirectRecipient {
                external_id: "ed25519:peer".to_owned(),
            },
            text: Some("hello".to_owned()),
            target_message_id: None,
            reaction: None,
            attachment_refs: Vec::new(),
            approval: None,
            actor: PrincipalId::new("bct", "agent").unwrap(),
            workspace_id: WorkspaceId::new(),
            run_id: RunId::new(),
            requesting_component: ComponentId::new("lumen-messaging").unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::{
        AdapterCapabilities, AdapterDescriptor, AdapterVersion, ConnectionBinding, ConnectionState,
        CredentialHandle, IngestError, MessagingAdapter,
    };
    use crate::envelope::MessageEnvelope;
    use async_trait::async_trait;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use test_support::{TestKernelPort, test_request};

    struct FakeAdapter {
        descriptor: AdapterDescriptor,
        calls: Arc<AtomicUsize>,
        bound: bool,
        bound_connection: Option<ConnectionId>,
    }

    impl FakeAdapter {
        fn new() -> Self {
            Self {
                descriptor: AdapterDescriptor::new(
                    "courier",
                    AdapterVersion::new("0.1.0").unwrap(),
                    AdapterCapabilities {
                        inbound_events: vec!["message.created".to_owned()],
                        outbound_verbs: vec!["send".to_owned()],
                    },
                ),
                calls: Arc::new(AtomicUsize::new(0)),
                bound: true,
                bound_connection: Some(ConnectionId::new("conn-1").unwrap()),
            }
        }
    }

    #[async_trait]
    impl MessagingAdapter for FakeAdapter {
        fn descriptor(&self) -> &AdapterDescriptor {
            &self.descriptor
        }

        fn descriptor_provider(&self) -> Provider {
            Provider::Courier
        }

        fn bound_connection_id(&self) -> Option<&ConnectionId> {
            if self.bound {
                self.bound_connection.as_ref()
            } else {
                None
            }
        }

        fn state(&self) -> ConnectionState {
            if self.bound {
                ConnectionState::Bound
            } else {
                ConnectionState::Unbound
            }
        }

        async fn bind(
            &mut self,
            _binding: ConnectionBinding,
            _config: &crate::MessagingConfig,
        ) -> Result<(), AdapterError> {
            self.bound = true;
            Ok(())
        }

        fn revoke(&mut self) {
            self.bound = false;
        }

        fn ingest(
            &self,
            _raw_event: &[u8],
            _now_millis: i64,
        ) -> Result<Option<MessageEnvelope>, IngestError> {
            Err(IngestError::MalformedEvent {
                reason: "fake".to_owned(),
            })
        }

        async fn execute_outbound(
            &self,
            _request: &OutboundRequest,
        ) -> Result<ProviderReceipt, AdapterError> {
            if !self.bound {
                return Err(AdapterError::NotBound);
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ProviderReceipt::now(Provider::Courier, "provider-msg-1"))
        }
    }

    fn pipeline(kernel: TestKernelPort) -> OutboundPipeline<TestKernelPort, MemoryReceiptStore> {
        OutboundPipeline::new(kernel, MemoryReceiptStore::new())
    }

    #[tokio::test]
    async fn happy_path_records_receipt() {
        let adapter = FakeAdapter::new();
        let pipeline = pipeline(TestKernelPort::allow());
        let request = test_request(OutboundVerb::Send);
        let receipt = pipeline.execute(&adapter, &request).await.unwrap();
        assert_eq!(receipt.idempotency_key, request.idempotency_key);
        assert_eq!(receipt.provider_message_id, "provider-msg-1");
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn idempotent_replay_does_not_resend() {
        let adapter = FakeAdapter::new();
        let pipeline = pipeline(TestKernelPort::allow());
        let request = test_request(OutboundVerb::Send);
        let first = pipeline.execute(&adapter, &request).await.unwrap();
        let second = pipeline.execute(&adapter, &request).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn lease_denial_blocks_before_provider_call() {
        let adapter = FakeAdapter::new();
        let kernel = TestKernelPort::deny_lease("no lease for messaging.recipient");
        let pipeline = pipeline(kernel);
        let request = test_request(OutboundVerb::Send);
        let err = pipeline.execute(&adapter, &request).await.unwrap_err();
        assert!(matches!(err, OutboundError::LeaseDenied(_)));
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn audit_outage_blocks_send() {
        let adapter = FakeAdapter::new();
        let pipeline = pipeline(TestKernelPort::audit_down("sqlite locked"));
        let request = test_request(OutboundVerb::Send);
        let err = pipeline.execute(&adapter, &request).await.unwrap_err();
        assert!(matches!(err, OutboundError::AuditUnavailable { .. }));
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn post_send_audit_failure_surfaces_receipt() {
        let adapter = FakeAdapter::new();
        let mut kernel = TestKernelPort::allow();
        kernel.fail_post_send_audit = true;
        let pipeline = pipeline(kernel);
        let request = test_request(OutboundVerb::Send);
        let err = pipeline.execute(&adapter, &request).await.unwrap_err();
        match err {
            OutboundError::PostSendAuditFailed { receipt, .. } => {
                assert_eq!(receipt.idempotency_key, request.idempotency_key);
            }
            other => panic!("expected PostSendAuditFailed, got {other:?}"),
        }
        // The send happened exactly once; a retry replays the receipt.
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unbound_adapter_blocks() {
        let mut adapter = FakeAdapter::new();
        adapter.bound = false;
        let pipeline = pipeline(TestKernelPort::allow());
        let request = test_request(OutboundVerb::Send);
        let err = pipeline.execute(&adapter, &request).await.unwrap_err();
        // The binding check fires before the provider call: the adapter can
        // never be reached through a connection it is not bound to.
        assert!(matches!(err, OutboundError::ConnectionMismatch { .. }));
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn adapter_bound_to_different_connection_blocks() {
        let mut adapter = FakeAdapter::new();
        adapter.bound_connection = Some(ConnectionId::new("conn-9").unwrap());
        let pipeline = pipeline(TestKernelPort::allow());
        let request = test_request(OutboundVerb::Send);
        let err = pipeline.execute(&adapter, &request).await.unwrap_err();
        assert!(matches!(err, OutboundError::ConnectionMismatch { .. }));
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn provider_mismatch_blocks() {
        let adapter = FakeAdapter::new();
        let pipeline = pipeline(TestKernelPort::allow());
        let mut request = test_request(OutboundVerb::Send);
        request.provider = Provider::Discord;
        let err = pipeline.execute(&adapter, &request).await.unwrap_err();
        assert!(matches!(err, OutboundError::Validation { .. }));
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn concurrent_sends_for_one_key_send_once() {
        let adapter = Arc::new(FakeAdapter::new());
        let pipeline = Arc::new(pipeline(TestKernelPort::allow()));
        let request = test_request(OutboundVerb::Send);
        let mut handles = Vec::new();
        for _ in 0..16 {
            let adapter = Arc::clone(&adapter);
            let pipeline = Arc::clone(&pipeline);
            let request = request.clone();
            handles.push(tokio::spawn(async move {
                pipeline.execute(adapter.as_ref(), &request).await
            }));
        }
        let mut receipts = Vec::new();
        for handle in handles {
            match handle.await.unwrap() {
                Ok(receipt) => receipts.push(receipt),
                // The reservation loser: retry later with the same key.
                Err(OutboundError::IdempotencyConflict { .. }) => {}
                Err(other) => panic!("expected receipt or IdempotencyConflict, got {other:?}"),
            }
        }
        // Exactly one caller reached the provider; the rest either lost the
        // reservation race or replayed the completed receipt.
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
        assert!(!receipts.is_empty());
        for receipt in &receipts {
            assert_eq!(receipt, &receipts[0]);
        }
    }

    #[tokio::test]
    async fn idempotency_key_reused_for_different_request_fails() {
        let adapter = FakeAdapter::new();
        let pipeline = pipeline(TestKernelPort::allow());
        let request = test_request(OutboundVerb::Send);
        let receipt = pipeline.execute(&adapter, &request).await.unwrap();

        let mut other = test_request(OutboundVerb::Send);
        other.idempotency_key = request.idempotency_key;
        other.text = Some("different effect".to_owned());
        let err = pipeline.execute(&adapter, &other).await.unwrap_err();
        assert!(matches!(err, OutboundError::Validation { .. }));
        // The provider was never called for the mismatched request.
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
        assert_eq!(receipt.action_fingerprint, request.action_fingerprint());
    }

    #[test]
    fn fingerprints_distinguish_different_effects() {
        let request = test_request(OutboundVerb::Send);
        assert_eq!(
            request.action_fingerprint(),
            request.clone().action_fingerprint()
        );
        let mut other = test_request(OutboundVerb::Send);
        other.text = Some("different effect".to_owned());
        assert_ne!(request.action_fingerprint(), other.action_fingerprint());
    }

    #[test]
    fn store_reservation_is_atomic() {
        let store = MemoryReceiptStore::new();
        let key = IdempotencyKey::new();
        assert!(matches!(store.reserve(&key), Ok(KeyReservation::Reserved)));
        assert!(matches!(store.reserve(&key), Ok(KeyReservation::InFlight)));
        store.abandon(&key);
        assert!(matches!(store.reserve(&key), Ok(KeyReservation::Reserved)));
    }

    #[tokio::test]
    async fn failed_send_releases_reservation_for_retry() {
        #[derive(Debug, Clone)]
        struct SharedReceipts(Arc<MemoryReceiptStore>);

        impl ReceiptStore for SharedReceipts {
            fn reserve(&self, key: &IdempotencyKey) -> Result<KeyReservation, ReceiptError> {
                self.0.reserve(key)
            }
            fn complete(&self, receipt: DeliveryReceipt) -> Result<(), ReceiptError> {
                self.0.complete(receipt)
            }
            fn abandon(&self, key: &IdempotencyKey) {
                self.0.abandon(key)
            }
        }

        let adapter = FakeAdapter::new();
        let receipts = SharedReceipts(Arc::new(MemoryReceiptStore::new()));

        // The reservation is taken, then the lease denial abandons it.
        let denied =
            OutboundPipeline::new(TestKernelPort::deny_lease("no lease"), receipts.clone());
        let request = test_request(OutboundVerb::Send);
        let err = denied.execute(&adapter, &request).await.unwrap_err();
        assert!(matches!(err, OutboundError::LeaseDenied(_)));
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 0);

        // The same key succeeds once the lease is granted: the reservation
        // did not leak.
        let allowed = OutboundPipeline::new(TestKernelPort::allow(), receipts);
        let receipt = allowed.execute(&adapter, &request).await.unwrap();
        assert_eq!(receipt.idempotency_key, request.idempotency_key);
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn validation_runs_first() {
        let adapter = FakeAdapter::new();
        let kernel = TestKernelPort::allow();
        let pipeline = pipeline(kernel);
        // React without a target message is invalid.
        let mut request = test_request(OutboundVerb::React);
        request.reaction = Some("👍".to_owned());
        let err = pipeline.execute(&adapter, &request).await.unwrap_err();
        assert!(matches!(err, OutboundError::Validation { .. }));
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn verb_action_kinds_are_distinct() {
        let kinds: Vec<String> = [
            OutboundVerb::Send,
            OutboundVerb::Edit,
            OutboundVerb::React,
            OutboundVerb::Delete,
            OutboundVerb::Moderate,
            OutboundVerb::Upload,
        ]
        .iter()
        .map(|v| v.action_kind().as_str().to_owned())
        .collect();
        let mut deduped = kinds.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(kinds.len(), deduped.len());
        assert!(kinds.contains(&"message.send".to_owned()));
        assert!(kinds.contains(&"message.delete".to_owned()));
    }

    #[test]
    fn action_envelope_scopes_exact_target() {
        let request = test_request(OutboundVerb::Send);
        let envelope = request.to_action_envelope().unwrap();
        assert_eq!(envelope.kind().as_str(), "message.send");
        let capabilities = envelope.required_capabilities();
        assert_eq!(capabilities.len(), 1);
        assert_eq!(
            capabilities[0].name(),
            lumen_core::capability::CapabilityName::MessageSend
        );
        // Fingerprint binds the exact effect; different targets differ.
        let mut other = test_request(OutboundVerb::Send);
        other.target = OutboundTarget::DirectRecipient {
            external_id: "ed25519:other".to_owned(),
        };
        assert_ne!(
            envelope.fingerprint().as_str(),
            other.to_action_envelope().unwrap().fingerprint().as_str()
        );
    }

    #[test]
    fn vhl_carriage_carries_but_never_mints() {
        // The digest and nonce arrive from the kernel; the constructor only
        // validates shape, it cannot invent them.
        let carriage =
            VhlApprovalCarriage::new("approval-1", "abc123digest", "nonce-1", 1_000_000).unwrap();
        assert_eq!(carriage.approval_id, "approval-1");
        assert_eq!(carriage.action_digest, "abc123digest");
        assert!(VhlApprovalCarriage::new("a", "", "n", 1).is_err());
        assert!(VhlApprovalCarriage::new("a", "d", "", 1).is_err());
    }

    #[test]
    fn credential_handle_never_leaks_into_audit_event() {
        let handle = CredentialHandle::new("token-abc").unwrap();
        let event = OutboundAuditEvent {
            idempotency_key: IdempotencyKey::new(),
            verb: OutboundVerb::Send,
            provider: Provider::Courier,
            target_summary: "courier direct message".to_owned(),
            phase: AuditPhase::PreSend,
            outcome: "authorized".to_owned(),
        };
        let debug = format!("{event:?}");
        assert!(!debug.contains(handle.as_str()));
        assert!(!debug.contains("token-abc"));
    }
}
