//! Provider-neutral message envelope (Adapter -> host).
//!
//! Every adapter normalizes provider events into [`MessageEnvelope`]. The
//! envelope is *data*, not a command grant: provider identity may inform
//! policy, but only a valid lease or an exact action-bound approval authorizes
//! an external effect.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::attachments::AttachmentRef;

/// Envelope schema version. Bump when fields change incompatibly.
pub const SCHEMA_VERSION: u16 = 1;

/// Maximum normalized text content accepted into an envelope.
pub const MAX_CONTENT_CHARS: usize = 100_000;

/// How far into the future `received_at` may be before it is rejected
/// (clock skew allowance).
pub const RECEIVED_SKEW_FUTURE_MILLIS: i64 = 5 * 60 * 1000;

/// How old an event may be before it is rejected as stale.
pub const RECEIVED_MAX_AGE_MILLIS: i64 = 7 * 24 * 60 * 60 * 1000;

/// Messaging provider that produced the event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Courier,
    Discord,
    Signal,
}

impl Provider {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Courier => "courier",
            Self::Discord => "discord",
            Self::Signal => "signal",
        }
    }
}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Host-managed account or bot connection the event arrived on.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ConnectionId(String);

impl ConnectionId {
    pub fn new(value: impl Into<String>) -> Result<Self, EnvelopeError> {
        let value = value.into();
        validate_identifier("connection_id", &value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Where the message lives: server/channel/thread or a direct chat.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Conversation {
    /// Server/guild identifier, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    /// Channel identifier (provider-native).
    pub channel_id: String,
    /// Thread identifier, if the message is in a thread.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    /// Peer identifier for direct chats.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_peer: Option<String>,
}

impl Conversation {
    pub fn channel(channel_id: impl Into<String>) -> Result<Self, EnvelopeError> {
        let channel_id = channel_id.into();
        validate_identifier("channel_id", &channel_id)?;
        Ok(Self {
            server_id: None,
            channel_id,
            thread_id: None,
            direct_peer: None,
        })
    }

    pub fn direct(peer: impl Into<String>) -> Result<Self, EnvelopeError> {
        let peer = peer.into();
        validate_identifier("direct_peer", &peer)?;
        Ok(Self {
            server_id: None,
            channel_id: format!("dm:{peer}"),
            thread_id: None,
            direct_peer: Some(peer),
        })
    }
}

/// How far the sender's identity got through explicit mapping.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SenderVerification {
    /// Explicitly mapped to exactly one principal.
    Verified,
    /// Maps to more than one principal; fail closed downstream.
    Ambiguous,
    /// No mapping registered; fail closed downstream.
    Unknown,
}

/// Trust properties of the transport that delivered the message.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportTrust {
    /// Provider transport is end-to-end encrypted to the recipient.
    #[default]
    EndToEndEncrypted,
    /// Encryption terminates at the provider, account, or linked device and
    /// Lumen receives plaintext (e.g. Courier bridged messages, or a future
    /// Signal linked-device path). Content is untrusted input.
    ProviderTerminated,
}

/// Provider identity plus its verified mapping state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SenderIdentity {
    /// Provider-native identity (Courier address, Discord user id, ...).
    pub external_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub verification: SenderVerification,
}

impl SenderIdentity {
    pub fn new(
        external_id: impl Into<String>,
        verification: SenderVerification,
    ) -> Result<Self, EnvelopeError> {
        let external_id = external_id.into();
        validate_identifier("sender.external_id", &external_id)?;
        Ok(Self {
            external_id,
            display_name: None,
            verification,
        })
    }

    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }
}

/// Provider-native message identifier.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProviderMessageId(String);

impl ProviderMessageId {
    pub fn new(value: impl Into<String>) -> Result<Self, EnvelopeError> {
        let value = value.into();
        validate_identifier("message_id", &value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable deduplication key: SHA-256 over provider, connection, and the
/// provider message id. Dedupe checks happen *before* an event may enter a
/// Pi session.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DedupeKey(String);

impl DedupeKey {
    pub fn compute(
        provider: Provider,
        connection_id: &ConnectionId,
        message_id: &ProviderMessageId,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(provider.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(connection_id.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(message_id.as_str().as_bytes());
        Self(format!("{:x}", hasher.finalize()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Thread / quote / correlation context for replies.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplyContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quotes_message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

/// Adapter provenance retained on every envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Provenance {
    /// Reviewed adapter name, e.g. `courier`.
    pub adapter: String,
    /// Reviewed adapter version that ingested the event.
    pub adapter_version: String,
    /// SHA-256 hex digest of the raw provider event bytes.
    pub raw_event_digest: String,
}

impl Provenance {
    pub fn new(
        adapter: impl Into<String>,
        adapter_version: impl Into<String>,
        raw_event: &[u8],
    ) -> Result<Self, EnvelopeError> {
        let adapter = adapter.into();
        let adapter_version = adapter_version.into();
        validate_identifier("provenance.adapter", &adapter)?;
        validate_identifier("provenance.adapter_version", &adapter_version)?;
        let mut hasher = Sha256::new();
        hasher.update(raw_event);
        Ok(Self {
            adapter,
            adapter_version,
            raw_event_digest: format!("{:x}", hasher.finalize()),
        })
    }
}

/// The provider-neutral message envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MessageEnvelope {
    pub schema_version: u16,
    pub provider: Provider,
    pub connection_id: ConnectionId,
    pub conversation: Conversation,
    pub sender: SenderIdentity,
    pub message_id: ProviderMessageId,
    pub dedupe_key: DedupeKey,
    /// Normalized text content. Sanitized (no control characters); may be empty
    /// when the message is attachment-only.
    pub content: String,
    pub attachment_refs: Vec<AttachmentRef>,
    #[serde(default)]
    pub reply_context: ReplyContext,
    /// Provider event time, Unix millis.
    pub received_at_millis: i64,
    pub provenance: Provenance,
    /// Trust properties of the delivering transport.
    pub transport_trust: TransportTrust,
}

impl MessageEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: Provider,
        connection_id: ConnectionId,
        conversation: Conversation,
        sender: SenderIdentity,
        message_id: ProviderMessageId,
        content: impl Into<String>,
        attachment_refs: Vec<AttachmentRef>,
        reply_context: ReplyContext,
        received_at_millis: i64,
        provenance: Provenance,
        transport_trust: TransportTrust,
        now_millis: i64,
    ) -> Result<Self, EnvelopeError> {
        let content = sanitize_content(content.into())?;
        validate_received_at(received_at_millis, now_millis)?;
        let dedupe_key = DedupeKey::compute(provider, &connection_id, &message_id);
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            provider,
            connection_id,
            conversation,
            sender,
            message_id,
            dedupe_key,
            content,
            attachment_refs,
            reply_context,
            received_at_millis,
            provenance,
            transport_trust,
        })
    }

    /// True when the sender mapping resolved to exactly one principal.
    /// Anything else must fail closed before an effect is authorized.
    pub fn sender_is_verified(&self) -> bool {
        self.sender.verification == SenderVerification::Verified
    }

    /// True when the content must be treated as untrusted input even from a
    /// verified sender (transport encryption terminated before Lumen).
    pub fn transport_is_untrusted(&self) -> bool {
        self.transport_trust == TransportTrust::ProviderTerminated
    }
}

fn validate_identifier(field: &str, value: &str) -> Result<(), EnvelopeError> {
    if value.is_empty() || value.len() > 512 {
        return Err(EnvelopeError::InvalidIdentifier {
            field: field.to_owned(),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(EnvelopeError::InvalidIdentifier {
            field: field.to_owned(),
        });
    }
    Ok(())
}

fn sanitize_content(content: String) -> Result<String, EnvelopeError> {
    if content.chars().count() > MAX_CONTENT_CHARS {
        return Err(EnvelopeError::ContentTooLarge {
            chars: content.chars().count(),
        });
    }
    // Strip control characters except tab/newline; the envelope is data that
    // may be shown to the model, so keep it plain text.
    let sanitized: String = content
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();
    Ok(sanitized)
}

fn validate_received_at(received_at_millis: i64, now_millis: i64) -> Result<(), EnvelopeError> {
    if received_at_millis > now_millis + RECEIVED_SKEW_FUTURE_MILLIS {
        return Err(EnvelopeError::ReceivedAtInFuture {
            received_at_millis,
            now_millis,
        });
    }
    if received_at_millis < now_millis - RECEIVED_MAX_AGE_MILLIS {
        return Err(EnvelopeError::ReceivedAtTooOld {
            received_at_millis,
            now_millis,
        });
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EnvelopeError {
    #[error("identifier invalid: {field}")]
    InvalidIdentifier { field: String },
    #[error("content too large: {chars} chars")]
    ContentTooLarge { chars: usize },
    #[error("received_at {received_at_millis} is in the future (now {now_millis})")]
    ReceivedAtInFuture {
        received_at_millis: i64,
        now_millis: i64,
    },
    #[error(
        "received_at {received_at_millis} is older than the retention window (now {now_millis})"
    )]
    ReceivedAtTooOld {
        received_at_millis: i64,
        now_millis: i64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_millis() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    fn envelope(content: &str, received_at: i64) -> Result<MessageEnvelope, EnvelopeError> {
        MessageEnvelope::new(
            Provider::Courier,
            ConnectionId::new("conn-1")?,
            Conversation::direct("ed25519:abc")?,
            SenderIdentity::new("ed25519:abc", SenderVerification::Verified)?,
            ProviderMessageId::new("msg-1")?,
            content,
            vec![],
            ReplyContext::default(),
            received_at,
            Provenance::new("courier", "0.1.0", b"raw")?,
            TransportTrust::EndToEndEncrypted,
            now_millis(),
        )
    }

    #[test]
    fn dedupe_key_is_stable_and_provider_scoped() {
        let a = DedupeKey::compute(
            Provider::Courier,
            &ConnectionId::new("c").unwrap(),
            &ProviderMessageId::new("m").unwrap(),
        );
        let b = DedupeKey::compute(
            Provider::Courier,
            &ConnectionId::new("c").unwrap(),
            &ProviderMessageId::new("m").unwrap(),
        );
        let c = DedupeKey::compute(
            Provider::Discord,
            &ConnectionId::new("c").unwrap(),
            &ProviderMessageId::new("m").unwrap(),
        );
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.as_str().len(), 64);
    }

    #[test]
    fn rejects_future_and_stale_timestamps() {
        let now = now_millis();
        // Margin well beyond scheduling jitter: the test and the validator
        // read the clock separately, so a 1ms boundary flakes under load.
        assert!(envelope("hi", now + RECEIVED_SKEW_FUTURE_MILLIS + 60_000).is_err());
        assert!(envelope("hi", now - RECEIVED_MAX_AGE_MILLIS - 60_000).is_err());
        assert!(envelope("hi", now).is_ok());
    }

    #[test]
    fn rejects_oversize_content_and_control_chars() {
        let now = now_millis();
        let big = "x".repeat(MAX_CONTENT_CHARS + 1);
        assert!(matches!(
            envelope(&big, now),
            Err(EnvelopeError::ContentTooLarge { .. })
        ));
        let env = envelope("a\x00b\x07c", now).unwrap();
        assert_eq!(env.content, "abc");
    }

    #[test]
    fn sender_verification_gate() {
        let now = now_millis();
        let verified = envelope("hi", now).unwrap();
        assert!(verified.sender_is_verified());

        let unknown = MessageEnvelope::new(
            Provider::Discord,
            ConnectionId::new("conn-1").unwrap(),
            Conversation::channel("chan-1").unwrap(),
            SenderIdentity::new("user-9", SenderVerification::Unknown).unwrap(),
            ProviderMessageId::new("msg-2").unwrap(),
            "hi",
            vec![],
            ReplyContext::default(),
            now,
            Provenance::new("discord", "0.1.0", b"raw").unwrap(),
            TransportTrust::EndToEndEncrypted,
            now,
        )
        .unwrap();
        assert!(!unknown.sender_is_verified());
    }
}
