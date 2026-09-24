//! Signal adapter: disabled pending an official bot/application surface.
//!
//! Eligibility decision: **not eligible** (see
//! `docs/messaging/signal-eligibility.md`). Signal offers no official,
//! supported bot or application API; the only automation paths are
//! unofficial linked-device clients (`signal-cli`, `signal-cli-rest-api`)
//! acting as a personal user account. That does not satisfy Lumen's
//! credential, identity, audit, and lifecycle requirements, so the adapter
//! refuses to bind and this module exposes no transport.
//!
//! The [`Provider::Signal`] envelope variant still exists so a future
//! eligible adapter can normalize into it without a schema change.

use async_trait::async_trait;
use thiserror::Error;

use crate::{
    MessagingConfig,
    adapters::{
        AdapterCapabilities, AdapterDescriptor, AdapterError, AdapterVersion, ConnectionBinding,
        ConnectionState, IngestError, MessagingAdapter, ProviderReceipt,
    },
    envelope::{MessageEnvelope, Provider},
    outbound::OutboundRequest,
};

/// Reviewed adapter version for audit provenance.
pub const ADAPTER_VERSION: &str = "0.1.0";

/// Machine-readable eligibility verdict. See
/// `docs/messaging/signal-eligibility.md` for the full decision record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalEligibility {
    /// No official, supported bot/application surface exists as of the
    /// decision date. The adapter stays disabled.
    NotEligible { decided: &'static str },
}

impl SignalEligibility {
    pub const CURRENT: Self = Self::NotEligible {
        decided: "2026-09-23",
    };

    /// False until an official, supported bot/application surface exists and
    /// the eligibility record is updated.
    pub const fn is_eligible(self) -> bool {
        match self {
            Self::NotEligible { .. } => false,
        }
    }

    pub const fn reason(self) -> &'static str {
        match self {
            Self::NotEligible { .. } => {
                "no official Signal bot/application surface exists; unofficial linked-device automation does not qualify (see docs/messaging/signal-eligibility.md)"
            }
        }
    }
}

/// Placeholder adapter that always refuses to bind. It exists so the
/// disabled state is explicit and typed rather than a missing module.
pub struct SignalAdapter {
    descriptor: AdapterDescriptor,
}

impl SignalAdapter {
    pub fn new() -> Self {
        Self {
            descriptor: AdapterDescriptor::new(
                "signal",
                AdapterVersion::new(ADAPTER_VERSION).expect("adapter version is valid"),
                AdapterCapabilities::default(),
            ),
        }
    }

    pub const fn eligibility() -> SignalEligibility {
        SignalEligibility::CURRENT
    }
}

impl Default for SignalAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MessagingAdapter for SignalAdapter {
    fn descriptor(&self) -> &AdapterDescriptor {
        &self.descriptor
    }

    fn descriptor_provider(&self) -> Provider {
        Provider::Signal
    }

    fn state(&self) -> ConnectionState {
        ConnectionState::Unbound
    }

    async fn bind(
        &mut self,
        _binding: ConnectionBinding,
        _config: &MessagingConfig,
    ) -> Result<(), AdapterError> {
        Err(AdapterError::Disabled)
    }

    fn revoke(&mut self) {}

    fn ingest(
        &self,
        _raw_event: &[u8],
        _now_millis: i64,
    ) -> Result<Option<MessageEnvelope>, IngestError> {
        Err(IngestError::AdapterDisabled)
    }

    async fn execute_outbound(
        &self,
        _request: &OutboundRequest,
    ) -> Result<ProviderReceipt, AdapterError> {
        Err(AdapterError::Disabled)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SignalError {
    #[error("signal adapter is disabled: {0}")]
    Disabled(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eligibility_is_not_eligible() {
        assert!(!SignalAdapter::eligibility().is_eligible());
        assert!(
            SignalAdapter::eligibility()
                .reason()
                .contains("signal-eligibility.md")
        );
    }

    #[test]
    fn bind_always_refuses() {
        let mut adapter = SignalAdapter::new();
        let binding = ConnectionBinding::new(
            crate::envelope::ConnectionId::new("c").unwrap(),
            "bct",
            crate::adapters::CredentialHandle::new("h").unwrap(),
        )
        .unwrap();
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(adapter.bind(binding, &MessagingConfig::default()));
        assert_eq!(result.unwrap_err(), AdapterError::Disabled);
    }
}
