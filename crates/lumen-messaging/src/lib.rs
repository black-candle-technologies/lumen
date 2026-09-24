//! Messaging adapters for the Lumen host.
//!
//! Adapters live at the host edge: they translate provider events into the
//! provider-neutral [`MessageEnvelope`] and route every outbound effect
//! through the kernel's lease checks, metering, and audit. They do NOT run
//! inside Pi, they never expose provider credentials to the model, and an
//! incoming message is never treated as authorization to act.
//!
//! Uniform authority rule: no messaging provider can extend a lease, approve
//! its own request, or bypass VHL. A message can ask; only the kernel can
//! authorize.
//!
//! # Adapter enablement
//!
//! - **Courier** is the native, first-class channel and is enabled by default.
//! - **Discord** is a separate scoped beta: it requires the `discord` Cargo
//!   feature AND the runtime `discord_enabled` flag.
//! - **Signal** has no official, supported bot/application surface; its
//!   adapter is disabled by default and refuses to bind. See
//!   `docs/messaging/signal-eligibility.md`.
//!
//! # Phase integration seams
//!
//! Points where phase-4 (session identity / VHL) plugs in are marked with
//! `TODO(PHASE4)` comments. This crate carries approval digests and nonces; it
//! never mints them.

pub mod adapters;
pub mod attachments;
pub mod dedupe;
pub mod envelope;
pub mod outbound;
pub mod principals;

pub use adapters::{
    AdapterCapabilities, AdapterDescriptor, AdapterError, AdapterVersion, ConnectionBinding,
    ConnectionState, CredentialHandle, DedupeDecision, IngestError, MessagingAdapter,
    ProviderReceipt,
};
pub use attachments::{
    AttachmentPolicy, AttachmentRef, QuarantineError, QuarantineStatus, QuarantinedAttachment,
    ScanVerdict, quarantine,
};
pub use dedupe::{DedupeOutcome, DedupeStore, MemoryDedupeStore};
pub use envelope::{
    ConnectionId, Conversation, DedupeKey, EnvelopeError, MessageEnvelope, Provenance, Provider,
    ProviderMessageId, ReplyContext, SenderIdentity, SenderVerification, TransportTrust,
};
pub use outbound::{
    AuditUnavailable, DeliveryReceipt, IdempotencyKey, KernelPort, LeaseDenial, MemoryReceiptStore,
    OutboundAuditEvent, OutboundError, OutboundPipeline, OutboundRequest, OutboundTarget,
    OutboundVerb, ReceiptStore, VhlApprovalCarriage,
};
pub use principals::{MappingError, PrincipalMappingRegistry, PrincipalResolution};

/// Runtime enablement flags for the messaging adapters.
///
/// Courier is first-class and on by default. Discord is double-gated (Cargo
/// `discord` feature + this flag). Signal stays off until an official bot
/// surface exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessagingConfig {
    pub courier_enabled: bool,
    pub discord_enabled: bool,
    pub signal_enabled: bool,
}

impl Default for MessagingConfig {
    fn default() -> Self {
        Self {
            courier_enabled: true,
            discord_enabled: false,
            signal_enabled: false,
        }
    }
}

impl MessagingConfig {
    /// Reads `LUMEN_MESSAGING_COURIER`, `LUMEN_MESSAGING_DISCORD`, and
    /// `LUMEN_MESSAGING_SIGNAL` (`1`/`true` enable, anything else disables).
    /// Unset variables keep the defaults above.
    pub fn from_env() -> Self {
        fn flag(name: &str, default: bool) -> bool {
            match std::env::var(name) {
                Ok(value) => {
                    let value = value.trim().to_ascii_lowercase();
                    value == "1" || value == "true" || value == "yes" || value == "on"
                }
                Err(_) => default,
            }
        }

        Self {
            courier_enabled: flag("LUMEN_MESSAGING_COURIER", true),
            discord_enabled: flag("LUMEN_MESSAGING_DISCORD", false),
            signal_enabled: flag("LUMEN_MESSAGING_SIGNAL", false),
        }
    }
}
