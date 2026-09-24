//! Deduplication: every inbound event is checked here *before* it may enter
//! a Pi session. Duplicate delivery, retries, and replays collapse to a
//! single envelope.

use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use thiserror::Error;

use crate::envelope::DedupeKey;

/// Outcome of a dedupe check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DedupeOutcome {
    /// First time this key was seen.
    New,
    /// Seen before; the envelope must NOT be processed again.
    Duplicate { first_seen_millis: i64 },
}

/// Fail-closed dedupe contract. Implementations must be deterministic:
/// the same key always yields the same outcome for the retention window.
pub trait DedupeStore: Send + Sync {
    /// Atomically checks the key and records it if new.
    fn check_and_insert(&self, key: &DedupeKey) -> Result<DedupeOutcome, DedupeError>;

    /// Removes entries older than the retention window. Best-effort.
    fn evict_expired(&self);
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DedupeError {
    #[error("dedupe store unavailable")]
    Unavailable,
}

/// In-memory dedupe store with a retention window.
///
/// Uncertainty policy: if the store itself is unavailable (poisoned lock),
/// callers must treat the outcome as [`DedupeError::Unavailable`] and fail
/// closed — a duplicate whose state is uncertain must not enter the session
/// twice.
pub struct MemoryDedupeStore {
    retention_millis: i64,
    inner: Mutex<MemoryDedupeInner>,
}

struct MemoryDedupeInner {
    seen: HashMap<String, i64>,
    order: VecDeque<(String, i64)>,
}

impl MemoryDedupeStore {
    /// `retention_millis` bounds how long a key suppresses duplicates.
    pub fn new(retention_millis: u64) -> Self {
        Self {
            // Clamp unrepresentable values instead of wrapping: a wrapped
            // negative retention would make every redelivery look new and
            // silently turn dedupe off.
            retention_millis: i64::try_from(retention_millis).unwrap_or(i64::MAX),
            inner: Mutex::new(MemoryDedupeInner {
                seen: HashMap::new(),
                order: VecDeque::new(),
            }),
        }
    }

    fn now_millis() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

impl DedupeStore for MemoryDedupeStore {
    fn check_and_insert(&self, key: &DedupeKey) -> Result<DedupeOutcome, DedupeError> {
        let mut inner = self.inner.lock().map_err(|_| DedupeError::Unavailable)?;
        let now = Self::now_millis();
        if let Some(first_seen) = inner.seen.get(key.as_str())
            && now - first_seen <= self.retention_millis
        {
            return Ok(DedupeOutcome::Duplicate {
                first_seen_millis: *first_seen,
            });
        }
        // Expired: fall through and re-record as new.
        inner.seen.insert(key.as_str().to_owned(), now);
        inner.order.push_back((key.as_str().to_owned(), now));
        Ok(DedupeOutcome::New)
    }

    fn evict_expired(&self) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let now = Self::now_millis();
        while let Some((key, seen)) = inner.order.front().map(|(k, s)| (k.clone(), *s)) {
            if now - seen <= self.retention_millis {
                break;
            }
            inner.order.pop_front();
            // Only remove from `seen` if the timestamp still matches the
            // evicted entry (a re-recorded key must survive).
            if inner.seen.get(&key) == Some(&seen) {
                inner.seen.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{ConnectionId, Provider, ProviderMessageId};

    fn key(provider: Provider, message: &str) -> DedupeKey {
        DedupeKey::compute(
            provider,
            &ConnectionId::new("conn").unwrap(),
            &ProviderMessageId::new(message).unwrap(),
        )
    }

    #[test]
    fn duplicate_delivery_collapses() {
        let store = MemoryDedupeStore::new(60_000);
        let k = key(Provider::Courier, "m1");
        assert_eq!(store.check_and_insert(&k), Ok(DedupeOutcome::New));
        match store.check_and_insert(&k).unwrap() {
            DedupeOutcome::Duplicate { .. } => {}
            DedupeOutcome::New => panic!("second insert must be a duplicate"),
        }
    }

    #[test]
    fn distinct_messages_are_new() {
        let store = MemoryDedupeStore::new(60_000);
        assert_eq!(
            store.check_and_insert(&key(Provider::Courier, "m1")),
            Ok(DedupeOutcome::New)
        );
        assert_eq!(
            store.check_and_insert(&key(Provider::Courier, "m2")),
            Ok(DedupeOutcome::New)
        );
    }

    #[test]
    fn provider_scopes_keys() {
        let store = MemoryDedupeStore::new(60_000);
        assert_eq!(
            store.check_and_insert(&key(Provider::Courier, "m1")),
            Ok(DedupeOutcome::New)
        );
        assert_eq!(
            store.check_and_insert(&key(Provider::Discord, "m1")),
            Ok(DedupeOutcome::New)
        );
    }

    #[test]
    fn expired_keys_become_new_again() {
        let store = MemoryDedupeStore::new(1);
        let k = key(Provider::Courier, "m1");
        assert_eq!(store.check_and_insert(&k), Ok(DedupeOutcome::New));
        std::thread::sleep(std::time::Duration::from_millis(5));
        store.evict_expired();
        assert_eq!(store.check_and_insert(&k), Ok(DedupeOutcome::New));
    }

    #[test]
    fn huge_retention_clamps_instead_of_wrapping() {
        // u64::MAX `as i64` wraps to -1, which would make every redelivery
        // look new and silently disable dedupe. The constructor clamps to
        // i64::MAX so "never expire" keeps suppressing duplicates.
        let store = MemoryDedupeStore::new(u64::MAX);
        let k = key(Provider::Courier, "m1");
        assert_eq!(store.check_and_insert(&k), Ok(DedupeOutcome::New));
        match store.check_and_insert(&k).unwrap() {
            DedupeOutcome::Duplicate { .. } => {}
            DedupeOutcome::New => panic!("second insert must still be a duplicate"),
        }
    }
}
