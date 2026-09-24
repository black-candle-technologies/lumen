//! Explicit external-identity mapping with fail-closed ambiguity.
//!
//! Every adapter maps provider-native identities (Courier address, Discord
//! user id, ...) to kernel principals through this registry. There is no
//! implicit or fuzzy matching: an identity with no mapping, or one that maps
//! to more than one principal, resolves to [`PrincipalResolution::Unknown`]
//! or [`PrincipalResolution::Ambiguous`], and downstream code must fail
//! closed on both.
//!
//! TODO(PHASE4): the registry's principal values are
//! [`lumen_core::identity::PrincipalId`]. When phase-4 lands the session
//! identity API, session-scoped mappings (per-session ephemeral Courier
//! identities) should be registered here with a session-scoped lifetime
//! rather than inventing a parallel identity store.

use std::collections::HashMap;

use lumen_core::identity::PrincipalId;
use thiserror::Error;

use crate::envelope::{Provider, SenderVerification};

/// Resolution of an external identity against the explicit mapping registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrincipalResolution {
    /// Exactly one principal. Safe to proceed.
    Mapped(PrincipalId),
    /// No mapping registered. Fail closed.
    Unknown,
    /// More than one principal registered. Fail closed.
    Ambiguous,
}

impl PrincipalResolution {
    /// The [`SenderVerification`] state that belongs on the envelope.
    pub fn verification(&self) -> SenderVerification {
        match self {
            Self::Mapped(_) => SenderVerification::Verified,
            Self::Unknown => SenderVerification::Unknown,
            Self::Ambiguous => SenderVerification::Ambiguous,
        }
    }

    /// Convenience gate: `Some(principal)` only for the unambiguous case.
    pub fn principal(&self) -> Option<PrincipalId> {
        match self {
            Self::Mapped(principal) => Some(principal.clone()),
            Self::Unknown | Self::Ambiguous => None,
        }
    }
}

/// Explicit (provider, external id) -> principal mapping registry.
#[derive(Clone, Debug, Default)]
pub struct PrincipalMappingRegistry {
    entries: HashMap<(Provider, String), Vec<PrincipalId>>,
}

impl PrincipalMappingRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an explicit mapping. Registering the same
    /// (provider, external id, principal) twice is idempotent. Registering a
    /// *different* principal for an already-mapped identity is allowed but
    /// makes [`Self::resolve`] return [`PrincipalResolution::Ambiguous`]
    /// until the conflict is removed — ambiguity fails closed, it never
    /// picks a winner.
    pub fn register(
        &mut self,
        provider: Provider,
        external_id: impl Into<String>,
        principal: PrincipalId,
    ) -> Result<(), MappingError> {
        let external_id = external_id.into();
        if external_id.is_empty() || external_id.len() > 512 {
            return Err(MappingError::InvalidExternalId);
        }
        let principals = self.entries.entry((provider, external_id)).or_default();
        if !principals.contains(&principal) {
            principals.push(principal);
        }
        Ok(())
    }

    /// Removes one principal from an identity's mapping. Returns true if the
    /// identity had that mapping.
    pub fn unregister(
        &mut self,
        provider: Provider,
        external_id: &str,
        principal: &PrincipalId,
    ) -> bool {
        let key = (provider, external_id.to_owned());
        match self.entries.get_mut(&key) {
            None => false,
            Some(principals) => {
                let before = principals.len();
                principals.retain(|p| p != principal);
                let removed = principals.len() != before;
                if principals.is_empty() {
                    self.entries.remove(&key);
                }
                removed
            }
        }
    }

    /// Resolves an external identity. Fail closed on anything but an exact,
    /// unambiguous mapping.
    pub fn resolve(&self, provider: Provider, external_id: &str) -> PrincipalResolution {
        match self.entries.get(&(provider, external_id.to_owned())) {
            None => PrincipalResolution::Unknown,
            Some(principals) if principals.len() == 1 => {
                PrincipalResolution::Mapped(principals[0].clone())
            }
            Some(_) => PrincipalResolution::Ambiguous,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MappingError {
    #[error("external id must be non-empty and at most 512 bytes")]
    InvalidExternalId,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(subject: &str) -> PrincipalId {
        PrincipalId::new("bct", subject).unwrap()
    }

    #[test]
    fn exact_mapping_resolves() {
        let mut registry = PrincipalMappingRegistry::new();
        let alice = principal("alice");
        registry
            .register(Provider::Courier, "ed25519:abc", alice.clone())
            .unwrap();
        assert_eq!(
            registry.resolve(Provider::Courier, "ed25519:abc"),
            PrincipalResolution::Mapped(alice)
        );
    }

    #[test]
    fn unknown_identity_fails_closed() {
        let registry = PrincipalMappingRegistry::new();
        let resolution = registry.resolve(Provider::Discord, "user-1");
        assert_eq!(resolution, PrincipalResolution::Unknown);
        assert_eq!(resolution.verification(), SenderVerification::Unknown);
        assert_eq!(resolution.principal(), None);
    }

    #[test]
    fn conflicting_mappings_are_ambiguous_not_first_wins() {
        let mut registry = PrincipalMappingRegistry::new();
        let a = principal("alice");
        let b = principal("bob");
        registry.register(Provider::Discord, "user-1", a).unwrap();
        registry.register(Provider::Discord, "user-1", b).unwrap();
        let resolution = registry.resolve(Provider::Discord, "user-1");
        assert_eq!(resolution, PrincipalResolution::Ambiguous);
        assert_eq!(resolution.verification(), SenderVerification::Ambiguous);
        assert_eq!(resolution.principal(), None);
    }

    #[test]
    fn unregister_resolves_ambiguity() {
        let mut registry = PrincipalMappingRegistry::new();
        let a = principal("alice");
        let b = principal("bob");
        registry
            .register(Provider::Discord, "user-1", a.clone())
            .unwrap();
        registry
            .register(Provider::Discord, "user-1", b.clone())
            .unwrap();
        assert!(registry.unregister(Provider::Discord, "user-1", &b));
        assert_eq!(
            registry.resolve(Provider::Discord, "user-1"),
            PrincipalResolution::Mapped(a)
        );
    }

    #[test]
    fn provider_scopes_identities() {
        let mut registry = PrincipalMappingRegistry::new();
        registry
            .register(Provider::Courier, "x", principal("alice"))
            .unwrap();
        assert_eq!(
            registry.resolve(Provider::Discord, "x"),
            PrincipalResolution::Unknown
        );
    }

    #[test]
    fn idempotent_reregistration() {
        let mut registry = PrincipalMappingRegistry::new();
        let alice = principal("alice");
        registry
            .register(Provider::Courier, "x", alice.clone())
            .unwrap();
        registry
            .register(Provider::Courier, "x", alice.clone())
            .unwrap();
        assert_eq!(
            registry.resolve(Provider::Courier, "x"),
            PrincipalResolution::Mapped(alice)
        );
    }
}
