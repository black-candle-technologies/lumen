//! authd integration (3D).
//!
//! Users authenticate through authd and are mapped to one stable account
//! ID. Account authentication is deliberately separate from session
//! authority: the account ID identifies *who* owns a session (for audit,
//! UI, and ownership checks), while *what the session may do* flows only
//! through the session's ephemeral subject identity and kernel leases.
//! An authenticated account confers no authority by itself.

use std::{future::Future, pin::Pin, sync::Mutex};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A stable authd account identifier. Opaque to the host; the only
/// guarantee is stability across sessions for the same user.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountId(pub String);

impl AccountId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The authenticated identity of a user, as resolved by authd.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountIdentity {
    pub account_id: AccountId,
    /// When authd last verified this identity (RFC 3339).
    pub verified_at: String,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid or unknown bearer token")]
    InvalidToken,
    #[error("token expired")]
    Expired,
    #[error("authd unavailable: {0}")]
    Unavailable(String),
}

/// Boxed future for [`AuthdClient`] (object-safe seam).
pub type AuthFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AuthError>> + Send + 'a>>;

/// authd client seam. The real implementation calls authd's token
/// verification endpoint over the local authenticated channel; the mock
/// maps fixed test tokens to stable account IDs.
pub trait AuthdClient: Send + Sync {
    fn authenticate<'a>(&'a self, bearer_token: &'a str) -> AuthFuture<'a, AccountIdentity>;
}

/// Binds a Pi session to its owning account for audit and ownership
/// checks. Carries no authority: session power still comes from the
/// ephemeral subject identity plus kernel leases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionBinding {
    pub session_id: String,
    pub account_id: AccountId,
    pub session_subject: String,
}

impl SessionBinding {
    /// The account owns the session only when the binding's account
    /// matches; authority checks never consult this.
    pub fn owner_is(&self, account: &AccountId) -> bool {
        &self.account_id == account
    }
}

/// Mock authd: fixed token -> stable account ID mapping.
#[derive(Debug, Default)]
pub struct MockAuthdClient {
    tokens: Mutex<Vec<(String, AccountIdentity)>>,
    down: Mutex<bool>,
}

impl MockAuthdClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_token(self, token: impl Into<String>, account_id: impl Into<String>) -> Self {
        self.tokens.lock().unwrap().push((
            token.into(),
            AccountIdentity {
                account_id: AccountId(account_id.into()),
                verified_at: crate::kernel_client::now_rfc3339(),
            },
        ));
        self
    }

    pub fn set_down(&self, down: bool) {
        *self.down.lock().unwrap() = down;
    }
}

impl AuthdClient for MockAuthdClient {
    fn authenticate<'a>(&'a self, bearer_token: &'a str) -> AuthFuture<'a, AccountIdentity> {
        Box::pin(async move {
            if *self.down.lock().unwrap() {
                return Err(AuthError::Unavailable("mock authd down".to_string()));
            }
            if bearer_token.is_empty() {
                return Err(AuthError::InvalidToken);
            }
            self.tokens
                .lock()
                .unwrap()
                .iter()
                .find(|(token, _)| token == bearer_token)
                .map(|(_, identity)| identity.clone())
                .ok_or(AuthError::InvalidToken)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn same_token_maps_to_stable_account_id() {
        let authd = MockAuthdClient::new().with_token("tok-1", "acct-42");
        let first = authd.authenticate("tok-1").await.unwrap();
        let second = authd.authenticate("tok-1").await.unwrap();
        assert_eq!(first.account_id, second.account_id);
        assert_eq!(first.account_id.as_str(), "acct-42");
    }

    #[tokio::test]
    async fn unknown_and_empty_tokens_rejected() {
        let authd = MockAuthdClient::new().with_token("tok-1", "acct-42");
        assert!(matches!(
            authd.authenticate("tok-9").await,
            Err(AuthError::InvalidToken)
        ));
        assert!(matches!(
            authd.authenticate("").await,
            Err(AuthError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn authd_outage_is_an_error_not_anonymous_access() {
        let authd = MockAuthdClient::new().with_token("tok-1", "acct-42");
        authd.set_down(true);
        assert!(matches!(
            authd.authenticate("tok-1").await,
            Err(AuthError::Unavailable(_))
        ));
    }

    #[test]
    fn session_binding_checks_ownership_not_authority() {
        let binding = SessionBinding {
            session_id: "sess-1".to_string(),
            account_id: AccountId("acct-42".to_string()),
            session_subject: "ed25519:subj".to_string(),
        };
        assert!(binding.owner_is(&AccountId("acct-42".to_string())));
        assert!(!binding.owner_is(&AccountId("acct-7".to_string())));
    }
}
