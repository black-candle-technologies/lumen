//! Messaging adapters: reviewed host-side bridges between providers and
//! the Lumen kernel.

pub mod common;
pub mod courier;
#[cfg(feature = "discord")]
pub mod discord;
pub mod signal;

pub use common::{
    AdapterCapabilities, AdapterDescriptor, AdapterError, AdapterVersion, ConnectionBinding,
    ConnectionState, CredentialHandle, DedupeDecision, IngestError, MessagingAdapter,
    ProviderReceipt,
};
pub use courier::{
    ADAPTER_VERSION as COURIER_ADAPTER_VERSION, CourierAdapter, CourierAddress, CourierConfig,
    CourierError, CourierStdioTransport, HandoffArtifact, HandoffSignature,
    MAX_HANDOFF_PAYLOAD_BYTES, SessionIdentityBinding, VhlCourierCarriage,
};
#[cfg(feature = "discord")]
pub use discord::{
    ADAPTER_VERSION as DISCORD_ADAPTER_VERSION, DiscordAdapter, DiscordBotConfig, DiscordError,
    DiscordEventKind, DiscordGatewayEvent, DiscordIntents, DiscordResource, DiscordRestCall,
    verify_interaction_signature,
};
pub use signal::{
    ADAPTER_VERSION as SIGNAL_ADAPTER_VERSION, SignalAdapter, SignalEligibility, SignalError,
};

use std::collections::HashMap;

use crate::MessagingConfig;

/// Registry of reviewed adapters: name -> adapter.
///
/// The registry owns enablement state. Disabling an adapter revokes it
/// (credential handle invalidated, outbound blocked) without affecting the
/// kernel or other channels.
#[derive(Default)]
pub struct AdapterRegistry {
    adapters: HashMap<String, Box<dyn MessagingAdapter>>,
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, adapter: Box<dyn MessagingAdapter>) {
        self.adapters
            .insert(adapter.descriptor().name.clone(), adapter);
    }

    pub fn get(&self, name: &str) -> Option<&dyn MessagingAdapter> {
        self.adapters.get(name).map(|a| a.as_ref())
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut dyn MessagingAdapter> {
        let boxed = self.adapters.get_mut(name)?;
        Some(&mut **boxed)
    }

    /// Disables an adapter: revokes it and drops it from the registry.
    /// Returns true if the adapter was present.
    pub fn disable(&mut self, name: &str) -> bool {
        if let Some(mut adapter) = self.adapters.remove(name) {
            adapter.revoke();
            true
        } else {
            false
        }
    }

    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.adapters.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty()
    }
}

/// Builds the default registry from the runtime config: Courier when
/// enabled, Discord only when its double gate passes, Signal never (it
/// refuses to bind by eligibility).
///
/// `courier_factory` supplies the Courier adapter because it needs the
/// principal registry and dedupe store owned by the host.
pub fn default_registry(
    config: &MessagingConfig,
    courier_factory: impl FnOnce() -> CourierAdapter,
) -> AdapterRegistry {
    let mut registry = AdapterRegistry::new();
    if config.courier_enabled {
        registry.register(Box::new(courier_factory()));
    }
    // Discord: constructed and registered by the host with its bot config;
    // the double gate (Cargo feature + runtime flag) is enforced again at
    // bind time. Signal: intentionally absent — no eligible transport.
    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dedupe::MemoryDedupeStore;
    use crate::principals::PrincipalMappingRegistry;
    use std::sync::Arc;

    #[test]
    fn disable_revokes_and_removes() {
        let mut registry = AdapterRegistry::new();
        let adapter = CourierAdapter::new(
            CourierConfig::default(),
            Arc::new(PrincipalMappingRegistry::new()),
            Arc::new(MemoryDedupeStore::new(60_000)),
        );
        registry.register(Box::new(adapter));
        assert_eq!(registry.names(), vec!["courier"]);
        assert!(registry.disable("courier"));
        assert!(registry.is_empty());
        assert!(!registry.disable("courier"));
    }

    #[test]
    fn default_registry_respects_courier_flag() {
        let factory = || {
            CourierAdapter::new(
                CourierConfig::default(),
                Arc::new(PrincipalMappingRegistry::new()),
                Arc::new(MemoryDedupeStore::new(60_000)),
            )
        };
        let config = MessagingConfig::default();
        assert_eq!(default_registry(&config, factory).names(), vec!["courier"]);
        let config = MessagingConfig {
            courier_enabled: false,
            ..Default::default()
        };
        let factory = || {
            CourierAdapter::new(
                CourierConfig::default(),
                Arc::new(PrincipalMappingRegistry::new()),
                Arc::new(MemoryDedupeStore::new(60_000)),
            )
        };
        assert!(default_registry(&config, factory).is_empty());
    }
}
