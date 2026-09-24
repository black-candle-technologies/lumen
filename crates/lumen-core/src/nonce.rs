//! Nonce replay protection (Phase 1B).
//!
//! Every [`lumen_protocol::ActionEnvelope`] carries a fresh random nonce, and
//! every lease carries a `lease_nonce`. The kernel records each nonce it has
//! honored; a second presentation of the same nonce is rejected. Nonces expire
//! with the object they protect so the store stays bounded.
//!
//! The durable replay record for single-use leases lives in the
//! `kernel_one_shot_uses` table; this in-memory store is the hot path for
//! envelope nonces within a kernel process.

use std::{collections::HashMap, sync::Mutex};

use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NonceError {
    #[error("nonce replay detected: {0}")]
    Replay(String),
    #[error("invalid nonce: must be 1-256 printable ASCII characters")]
    Invalid,
}

fn valid_nonce(nonce: &str) -> bool {
    !nonce.is_empty() && nonce.len() <= 256 && nonce.bytes().all(|b| b.is_ascii_graphic())
}

struct NonceRecord {
    expires_at_ms: i64,
}

/// Thread-safe nonce store with expiry-bounded memory.
pub struct NonceStore {
    inner: Mutex<HashMap<String, NonceRecord>>,
}

impl NonceStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Record `nonce`, or reject it as a replay. A nonce seen before whose
    /// record has expired is treated as fresh (its protected object is dead).
    pub fn check_and_insert(
        &self,
        nonce: &str,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<(), NonceError> {
        if !valid_nonce(nonce) {
            return Err(NonceError::Invalid);
        }
        let mut inner = self.inner.lock().expect("nonce mutex poisoned");
        if let Some(record) = inner.get(nonce)
            && now_ms < record.expires_at_ms
        {
            return Err(NonceError::Replay(nonce.to_string()));
        }
        // Opportunistic purge keeps the map bounded.
        if inner.len().is_multiple_of(1024) {
            inner.retain(|_, r| now_ms < r.expires_at_ms);
        }
        inner.insert(
            nonce.to_string(),
            NonceRecord {
                expires_at_ms: now_ms.saturating_add(ttl_ms),
            },
        );
        Ok(())
    }

    /// Explicitly forget a nonce (used only in tests / controlled reset).
    #[cfg(test)]
    pub fn forget(&self, nonce: &str) {
        self.inner
            .lock()
            .expect("nonce mutex poisoned")
            .remove(nonce);
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("nonce mutex poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn purge_expired(&self, now_ms: i64) -> usize {
        let mut inner = self.inner.lock().expect("nonce mutex poisoned");
        let before = inner.len();
        inner.retain(|_, r| now_ms < r.expires_at_ms);
        before - inner.len()
    }
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_ok_second_is_replay() {
        let store = NonceStore::new();
        store.check_and_insert("abc123", 1000, 60_000).unwrap();
        assert!(matches!(
            store.check_and_insert("abc123", 2000, 60_000),
            Err(NonceError::Replay(_))
        ));
    }

    #[test]
    fn expired_nonce_is_fresh() {
        let store = NonceStore::new();
        store.check_and_insert("abc123", 1000, 500).unwrap();
        store.check_and_insert("abc123", 2000, 500).unwrap();
    }

    #[test]
    fn invalid_nonces_rejected() {
        let store = NonceStore::new();
        assert!(matches!(
            store.check_and_insert("", 0, 1),
            Err(NonceError::Invalid)
        ));
        assert!(matches!(
            store.check_and_insert("has space", 0, 1),
            Err(NonceError::Invalid)
        ));
    }

    #[test]
    fn purge_bounds_memory() {
        let store = NonceStore::new();
        store.check_and_insert("a", 0, 10).unwrap();
        store.check_and_insert("b", 0, 10_000).unwrap();
        assert_eq!(store.purge_expired(100), 1);
        assert_eq!(store.len(), 1);
    }
}
