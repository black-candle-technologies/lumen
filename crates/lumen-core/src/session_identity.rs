//! Per-session ephemeral identity (Phase 4A).
//!
//! The kernel generates a fresh Ed25519 keypair when a session starts and
//! holds the private key in kernel-controlled memory for the session's
//! lifetime. The private key is **never** exposed to Pi, the model, or
//! sandbox guests: signing happens inside the vault through
//! [`SessionIdentityVault::sign`] and [`SessionIdentityVault::with_signing_key`],
//! which run caller closures without letting key bytes escape.
//!
//! The session's Courier address (`ed25519:<base64url>`) is derived from the
//! public key and published with session metadata. Ending the session
//! destroys the private key (zeroized on drop) and deactivates the session
//! in the kernel [`SessionRegistry`](crate::lease::SessionRegistry); the
//! audit record retains the public identity.
//!
//! Three signature domains keep the purposes distinct:
//! - session identity — attribution of actions, messages, and handoffs to
//!   one agent session,
//! - kernel host key — audit checkpoints (see [`crate::kernel_audit`]),
//! - human VHL key — exceptional authority (see [`crate::vhl`]).

use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::Serialize;
use thiserror::Error;

use crate::lease::{LeaseError, SessionRegistry};

/// Courier address prefix for Ed25519 identities, matching Courier's address
/// scheme (`ed25519:<base64url-no-pad>`).
pub const SESSION_ADDRESS_PREFIX: &str = "ed25519:";

/// Derive the Courier address for a session verifying key.
pub fn session_address(verifying_key: &VerifyingKey) -> String {
    format!(
        "{SESSION_ADDRESS_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(verifying_key.as_bytes())
    )
}

/// Parse a session Courier address back to its verifying key.
pub fn parse_session_address(address: &str) -> Result<VerifyingKey, SessionIdentityError> {
    let encoded = address
        .strip_prefix(SESSION_ADDRESS_PREFIX)
        .ok_or_else(|| SessionIdentityError::MalformedAddress(address.to_string()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| SessionIdentityError::MalformedAddress(address.to_string()))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SessionIdentityError::MalformedAddress(address.to_string()))?;
    VerifyingKey::from_bytes(&array)
        .map_err(|_| SessionIdentityError::MalformedAddress(address.to_string()))
}

/// Domain separation for session-identity signatures. A signature made for
/// one purpose can never verify as another.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureDomain {
    /// Attribution of an action or message to this session.
    SessionAttribution,
    /// Handoff artifacts passed between sessions.
    Handoff,
    /// Lease delegation statements.
    Delegation,
}

impl SignatureDomain {
    /// Domain separator bytes, NUL-terminated like Courier's domains.
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::SessionAttribution => b"lumen-session-attest-v1\x00",
            Self::Handoff => b"lumen-handoff-v1\x00",
            Self::Delegation => b"lumen-delegation-v1\x00",
        }
    }
}

/// One session's identity. Private to the vault.
///
/// Key destruction: [`ed25519_dalek::SigningKey`] zeroizes itself on drop
/// (its `ZeroizeOnDrop` impl, active via the `zeroize` feature), so removing
/// an identity from the vault destroys the key material. There is no manual
/// `Drop` here on purpose — the key type's own drop is the single place
/// that touches key bytes.
struct SessionIdentity {
    key: SigningKey,
    parent_subject: Option<String>,
}

/// Receipt for a started session. Carries only public material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionStartReceipt {
    pub subject: String,
    pub verifying_key_hex: String,
    pub parent_subject: Option<String>,
    pub created_at_ms: i64,
}

/// Receipt for an ended session. The private key is gone (zeroized); the
/// public identity is retained for the audit trail, and `affected_subjects`
/// lists every session whose authority died with this one so the supervisor
/// can revoke their leases.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionEndReceipt {
    pub subject: String,
    pub verifying_key_hex: String,
    pub parent_subject: Option<String>,
    pub affected_subjects: Vec<String>,
    pub ended_at_ms: i64,
}

#[derive(Debug, Error)]
pub enum SessionIdentityError {
    #[error("parent session is not active: {0}")]
    ParentNotActive(String),
    #[error("session subject collision on fresh keypair")]
    SubjectCollision,
    #[error("session unknown or already destroyed: {0}")]
    UnknownOrDestroyed(String),
    #[error("malformed session address: {0}")]
    MalformedAddress(String),
    #[error("session signature verification failed")]
    BadSignature,
    #[error(transparent)]
    Lease(#[from] LeaseError),
}

/// Kernel-controlled store for per-session signing keys.
///
/// The vault is the only holder of session private keys. It hands out
/// signatures, never keys: [`sign`](Self::sign) signs domain-separated
/// messages, and [`with_signing_key`](Self::with_signing_key) runs a caller
/// closure with temporary access for operations that need the raw
/// [`SigningKey`] (e.g. minting a child lease as the parent session) without
/// the key ever crossing the vault boundary.
#[derive(Default)]
pub struct SessionIdentityVault {
    identities: HashMap<String, SessionIdentity>,
    /// Parent subject -> child subjects, for the revocation view.
    children: HashMap<String, Vec<String>>,
}

impl SessionIdentityVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a session: generate the ephemeral keypair, derive the Courier
    /// address, and register the verifying key in the kernel session
    /// registry with its parent linkage.
    pub fn start_session(
        &mut self,
        registry: &mut SessionRegistry,
        parent_subject: Option<String>,
        now_ms: i64,
    ) -> Result<SessionStartReceipt, SessionIdentityError> {
        if let Some(parent) = &parent_subject {
            match registry.get(parent) {
                Some(record) if record.active => {}
                _ => return Err(SessionIdentityError::ParentNotActive(parent.clone())),
            }
        }
        let key = SigningKey::generate(&mut OsRng);
        let verifying = key.verifying_key();
        let subject = session_address(&verifying);
        if self.identities.contains_key(&subject) {
            // Astronomically unlikely; fail closed rather than overwrite.
            return Err(SessionIdentityError::SubjectCollision);
        }
        registry.register(subject.clone(), parent_subject.clone(), verifying);
        if let Some(parent) = &parent_subject {
            self.children
                .entry(parent.clone())
                .or_default()
                .push(subject.clone());
        }
        self.identities.insert(
            subject.clone(),
            SessionIdentity {
                key,
                parent_subject: parent_subject.clone(),
            },
        );
        Ok(SessionStartReceipt {
            subject,
            verifying_key_hex: hex::encode(verifying.as_bytes()),
            parent_subject,
            created_at_ms: now_ms,
        })
    }

    /// Sign `message` under `domain` as `subject`. The key never leaves the
    /// vault.
    pub fn sign(
        &self,
        subject: &str,
        domain: SignatureDomain,
        message: &[u8],
    ) -> Result<Signature, SessionIdentityError> {
        let identity = self
            .identities
            .get(subject)
            .ok_or_else(|| SessionIdentityError::UnknownOrDestroyed(subject.to_string()))?;
        let mut bytes = Vec::with_capacity(domain.as_bytes().len() + message.len());
        bytes.extend_from_slice(domain.as_bytes());
        bytes.extend_from_slice(message);
        Ok(identity.key.sign(&bytes))
    }

    /// Verify a domain-separated signature against a session address.
    pub fn verify(
        &self,
        subject: &str,
        domain: SignatureDomain,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SessionIdentityError> {
        use ed25519_dalek::Verifier as _;
        let identity = self
            .identities
            .get(subject)
            .ok_or_else(|| SessionIdentityError::UnknownOrDestroyed(subject.to_string()))?;
        let mut bytes = Vec::with_capacity(domain.as_bytes().len() + message.len());
        bytes.extend_from_slice(domain.as_bytes());
        bytes.extend_from_slice(message);
        identity
            .key
            .verifying_key()
            .verify(&bytes, signature)
            .map_err(|_| SessionIdentityError::BadSignature)
    }

    /// Run `f` with the session's signing key. The key is borrowed for the
    /// duration of the call and never escapes the vault; lease-engine
    /// failures surface as [`LeaseError`].
    pub fn with_signing_key<R>(
        &self,
        subject: &str,
        f: impl FnOnce(&SigningKey) -> Result<R, LeaseError>,
    ) -> Result<R, SessionIdentityError> {
        let identity = self
            .identities
            .get(subject)
            .ok_or_else(|| SessionIdentityError::UnknownOrDestroyed(subject.to_string()))?;
        f(&identity.key).map_err(SessionIdentityError::from)
    }

    /// The session's verifying key, if the session is live in this vault.
    pub fn verifying_key(&self, subject: &str) -> Option<VerifyingKey> {
        self.identities
            .get(subject)
            .map(|identity| identity.key.verifying_key())
    }

    /// True while the vault still holds this session's private key.
    pub fn is_live(&self, subject: &str) -> bool {
        self.identities.contains_key(subject)
    }

    pub fn session_count(&self) -> usize {
        self.identities.len()
    }

    /// End a session: destroy the private key (zeroized on drop) of the
    /// session and every vault-known descendant, deactivate them in the
    /// registry, and return the termination receipt.
    ///
    /// TODO(PHASE3): the session supervisor must call this when a session
    /// ends and then revoke every lease held by the returned
    /// `affected_subjects` through the kernel `RevocationIndex`, so
    /// in-flight actions lose authority and pending commits are denied.
    pub fn end_session(
        &mut self,
        registry: &mut SessionRegistry,
        subject: &str,
        now_ms: i64,
    ) -> Result<SessionEndReceipt, SessionIdentityError> {
        let identity = self
            .identities
            .remove(subject)
            .ok_or_else(|| SessionIdentityError::UnknownOrDestroyed(subject.to_string()))?;
        let verifying_hex = hex::encode(identity.key.verifying_key().as_bytes());
        let parent_subject = identity.parent_subject.clone();
        // Key material is zeroized by SigningKey::drop as `identity` goes
        // out of scope at the end of this function.
        let affected = self.affected_subjects(registry, subject);
        for descendant in &affected {
            registry.deactivate(descendant);
            // Destroy descendant keys too: ending a parent must leave no
            // usable signing key anywhere in its subtree.
            if descendant != subject {
                self.identities.remove(descendant);
            }
        }
        Ok(SessionEndReceipt {
            subject: subject.to_string(),
            verifying_key_hex: verifying_hex,
            parent_subject,
            affected_subjects: affected,
            ended_at_ms: now_ms,
        })
    }

    /// The revocation view: `subject` plus every vault-known descendant,
    /// restricted to sessions still active in the registry. Used to show
    /// what a session-end revocation affects.
    pub fn affected_subjects(&self, registry: &SessionRegistry, subject: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![subject.to_string()];
        let mut seen = std::collections::HashSet::new();
        while let Some(current) = stack.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            let active = registry.get(&current).is_some_and(|record| record.active);
            if active {
                out.push(current.clone());
            }
            if let Some(kids) = self.children.get(&current) {
                stack.extend(kids.iter().cloned());
            }
        }
        out.sort();
        out
    }
}
