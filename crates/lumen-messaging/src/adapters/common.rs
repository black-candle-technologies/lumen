//! Shared adapter framework: lifecycle, credentials, and the adapter trait.
//!
//! Lifecycle (design § Adapter lifecycle):
//! 1. Authenticate and bind the provider connection to a Black Candle account.
//! 2. Register a reviewed adapter version and its declared capabilities.
//! 3. Ingest events into the normalized envelope; map principals explicitly.
//! 4. Route replies/mutations through kernel lease checks, metering, audit.
//! 5. Revoke: disable the adapter and invalidate its credential handle.
//!
//! Failure posture: lost auth, identity ambiguity, duplicate uncertainty, or
//! audit failure BLOCKS outbound effects. Reasoning may continue; sending
//! may not.

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    adapters::MessagingConfig,
    dedupe::{DedupeError, DedupeOutcome},
    envelope::{ConnectionId, MessageEnvelope, Provider},
    outbound::OutboundRequest,
};

/// Reviewed adapter version. Validated as a short dotted identifier so audit
/// records can name exactly which reviewed code ingested an event.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AdapterVersion(String);

impl AdapterVersion {
    pub fn new(value: impl Into<String>) -> Result<Self, AdapterError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
        {
            return Err(AdapterError::InvalidVersion);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Declared event and action capabilities of a reviewed adapter version.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdapterCapabilities {
    /// Inbound event kinds the adapter can ingest, e.g. `message.created`.
    pub inbound_events: Vec<String>,
    /// Outbound verbs the adapter can execute, e.g. `send`, `edit`.
    pub outbound_verbs: Vec<String>,
}

/// Immutable descriptor of a reviewed adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdapterDescriptor {
    pub name: String,
    pub version: AdapterVersion,
    pub capabilities: AdapterCapabilities,
}

impl AdapterDescriptor {
    pub fn new(
        name: impl Into<String>,
        version: AdapterVersion,
        capabilities: AdapterCapabilities,
    ) -> Self {
        Self {
            name: name.into(),
            version,
            capabilities,
        }
    }
}

/// Opaque handle to brokered provider credentials.
///
/// The actual secret (bot token, CLI identity material) is brokered
/// host-side by the kernel and never exposed to Pi or guests. This handle
/// names it; it is never logged (see the redacted [`std::fmt::Debug`]).
#[derive(Clone, Eq, PartialEq)]
pub struct CredentialHandle(String);

impl CredentialHandle {
    pub fn new(handle: impl Into<String>) -> Result<Self, AdapterError> {
        let handle = handle.into();
        if handle.is_empty() || handle.len() > 256 {
            return Err(AdapterError::InvalidCredentialHandle);
        }
        Ok(Self(handle))
    }

    /// Returns the handle to the kernel-side broker only. Adapters must not
    /// forward this to Pi, logs, or audit detail fields.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for CredentialHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialHandle(<redacted>)")
    }
}

/// Binds a provider connection to a Black Candle account with a brokered
/// credential handle.
#[derive(Clone, Debug)]
pub struct ConnectionBinding {
    pub connection_id: ConnectionId,
    pub black_candle_account: String,
    pub credential: CredentialHandle,
}

impl ConnectionBinding {
    pub fn new(
        connection_id: ConnectionId,
        black_candle_account: impl Into<String>,
        credential: CredentialHandle,
    ) -> Result<Self, AdapterError> {
        let black_candle_account = black_candle_account.into();
        if black_candle_account.is_empty() || black_candle_account.len() > 256 {
            return Err(AdapterError::InvalidAccount);
        }
        Ok(Self {
            connection_id,
            black_candle_account,
            credential,
        })
    }
}

/// Lifecycle state of an adapter connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Unbound,
    Bound,
    /// Disabled by operator or config; credential handle invalidated.
    Revoked {
        reason: String,
    },
    /// Provider authentication was lost; outbound effects blocked until
    /// re-bound.
    AuthLost {
        reason: String,
    },
}

/// Provider receipt for an executed outbound effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderReceipt {
    pub provider: Provider,
    pub provider_message_id: String,
    pub sent_at_millis: i64,
}

impl ProviderReceipt {
    pub fn now(provider: Provider, provider_message_id: impl Into<String>) -> Self {
        let sent_at_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        Self {
            provider,
            provider_message_id: provider_message_id.into(),
            sent_at_millis,
        }
    }
}

/// The adapter contract every messaging adapter implements.
#[async_trait]
pub trait MessagingAdapter: Send + Sync {
    fn descriptor(&self) -> &AdapterDescriptor;

    fn provider(&self) -> Provider {
        self.descriptor_provider()
    }

    /// Provider derived from the descriptor name; override if they differ.
    fn descriptor_provider(&self) -> Provider;

    fn state(&self) -> ConnectionState;

    fn is_bound(&self) -> bool {
        matches!(self.state(), ConnectionState::Bound)
    }

    /// Step 1-2 of the lifecycle: authenticate, bind to the Black Candle
    /// account, and validate the reviewed version + enablement flags.
    /// Implementations must refuse to bind when disabled by config.
    async fn bind(
        &mut self,
        binding: ConnectionBinding,
        config: &MessagingConfig,
    ) -> Result<(), AdapterError>;

    /// Step 5: disable the adapter and invalidate the credential handle.
    /// After revoke, outbound effects are blocked.
    fn revoke(&mut self);

    /// Step 3: verify provider signatures/authenticated session, deduplicate,
    /// map the sender explicitly, quarantine attachments, and normalize into
    /// the envelope. Returns `Ok(None)` for a known redelivery (the first
    /// delivery already entered the pipeline). Must fail closed on signature
    /// failure, ambiguous identity, or duplicate uncertainty.
    fn ingest(
        &self,
        raw_event: &[u8],
        now_millis: i64,
    ) -> Result<Option<MessageEnvelope>, IngestError>;

    /// Step 4 is enforced by the [`crate::outbound::OutboundPipeline`]
    /// *before* this is called: by the time `execute_outbound` runs, the
    /// lease check and the pre-send audit record have succeeded. The adapter
    /// performs the provider call with the kernel-brokered credential and
    /// returns the provider receipt.
    async fn execute_outbound(
        &self,
        request: &OutboundRequest,
    ) -> Result<ProviderReceipt, AdapterError>;
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AdapterError {
    #[error("adapter is disabled by configuration")]
    Disabled,
    #[error("adapter is not bound")]
    NotBound,
    #[error("adapter was revoked: {reason}")]
    Revoked { reason: String },
    #[error("provider authentication lost: {reason}")]
    AuthLost { reason: String },
    #[error("invalid adapter version")]
    InvalidVersion,
    #[error("invalid credential handle")]
    InvalidCredentialHandle,
    #[error("invalid Black Candle account")]
    InvalidAccount,
    #[error("provider transport error: {reason}")]
    Transport { reason: String },
    #[error("provider session identity unavailable: {reason}")]
    IdentityUnavailable { reason: String },
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IngestError {
    #[error("provider signature verification failed")]
    SignatureVerificationFailed,
    #[error("provider authentication lost: {reason}")]
    AuthLost { reason: String },
    #[error("sender identity is ambiguous; refusing to map")]
    AmbiguousIdentity,
    #[error("sender identity has no mapping; refusing to map")]
    UnknownIdentity,
    #[error("duplicate state uncertain; refusing to ingest")]
    DuplicateUncertain,
    #[error("malformed provider event: {reason}")]
    MalformedEvent { reason: String },
    #[error("adapter is disabled")]
    AdapterDisabled,
    #[error("attachment rejected: {reason}")]
    AttachmentRejected { reason: String },
}

/// Decision of the dedupe gate applied before an event may enter a Pi session.
///
/// Known redeliveries collapse to [`DedupeDecision::Skip`]: the first
/// delivery already entered the pipeline, so a redelivery is provider noise,
/// not a new event. Only a dedupe-store outage fails closed
/// ([`IngestError::DuplicateUncertain`]), because then newness cannot be
/// proven and double entry into a Pi session must not be risked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DedupeDecision {
    /// First sighting: proceed with ingest.
    Proceed,
    /// Known redelivery: skip silently.
    Skip,
}

impl DedupeDecision {
    /// Maps a [`crate::dedupe::DedupeStore`] outcome to a gate decision.
    pub fn decide(
        outcome: Result<DedupeOutcome, DedupeError>,
    ) -> Result<DedupeDecision, IngestError> {
        match outcome {
            Ok(DedupeOutcome::New) => Ok(DedupeDecision::Proceed),
            Ok(DedupeOutcome::Duplicate { .. }) => Ok(DedupeDecision::Skip),
            Err(DedupeError::Unavailable) => Err(IngestError::DuplicateUncertain),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_handle_is_redacted_in_debug() {
        let handle = CredentialHandle::new("super-secret-token").unwrap();
        let debug = format!("{handle:?}");
        assert!(!debug.contains("super-secret-token"));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn version_validation() {
        assert!(AdapterVersion::new("0.1.0").is_ok());
        assert!(AdapterVersion::new("0.1.0-beta_2").is_ok());
        assert!(AdapterVersion::new("").is_err());
        assert!(AdapterVersion::new("0.1.0 with spaces").is_err());
    }
}
