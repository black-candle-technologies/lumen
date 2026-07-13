use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};

use thiserror::Error;
use tokio::sync::Mutex;

pub type SecretStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, SecretStoreError>> + Send + 'a>>;

pub trait SecretStore: Send + Sync {
    fn put<'a>(&'a self, account: &'a str, value: Vec<u8>) -> SecretStoreFuture<'a, ()>;
    fn resolve<'a>(&'a self, account: &'a str) -> SecretStoreFuture<'a, Vec<u8>>;
    fn delete<'a>(&'a self, account: &'a str) -> SecretStoreFuture<'a, ()>;
}

#[derive(Clone, Debug)]
pub struct OsKeyringSecretStore {
    service: String,
}

impl OsKeyringSecretStore {
    pub fn new(service: impl Into<String>) -> Result<Self, SecretStoreError> {
        let service = service.into();
        validate_identifier("service", &service, 128)?;
        Ok(Self { service })
    }
}

impl SecretStore for OsKeyringSecretStore {
    fn put<'a>(&'a self, account: &'a str, value: Vec<u8>) -> SecretStoreFuture<'a, ()> {
        let validated = validate_identifier("account", account, 512);
        let service = self.service.clone();
        let account = account.to_owned();
        Box::pin(async move {
            validated?;
            tokio::task::spawn_blocking(move || {
                let entry =
                    keyring::Entry::new(&service, &account).map_err(SecretStoreError::backend)?;
                entry.set_secret(&value).map_err(SecretStoreError::backend)
            })
            .await
            .map_err(|error| SecretStoreError::Unavailable(error.to_string()))?
        })
    }

    fn resolve<'a>(&'a self, account: &'a str) -> SecretStoreFuture<'a, Vec<u8>> {
        let validated = validate_identifier("account", account, 512);
        let service = self.service.clone();
        let account = account.to_owned();
        Box::pin(async move {
            validated?;
            tokio::task::spawn_blocking(move || {
                let entry =
                    keyring::Entry::new(&service, &account).map_err(SecretStoreError::backend)?;
                entry.get_secret().map_err(SecretStoreError::backend)
            })
            .await
            .map_err(|error| SecretStoreError::Unavailable(error.to_string()))?
        })
    }

    fn delete<'a>(&'a self, account: &'a str) -> SecretStoreFuture<'a, ()> {
        let validated = validate_identifier("account", account, 512);
        let service = self.service.clone();
        let account = account.to_owned();
        Box::pin(async move {
            validated?;
            tokio::task::spawn_blocking(move || {
                let entry =
                    keyring::Entry::new(&service, &account).map_err(SecretStoreError::backend)?;
                entry.delete_credential().map_err(SecretStoreError::backend)
            })
            .await
            .map_err(|error| SecretStoreError::Unavailable(error.to_string()))?
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct InMemorySecretStore {
    values: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    unavailable: Option<String>,
}

impl InMemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            values: Arc::default(),
            unavailable: Some(reason.into()),
        }
    }

    fn availability(&self) -> Result<(), SecretStoreError> {
        match &self.unavailable {
            Some(reason) => Err(SecretStoreError::Unavailable(reason.clone())),
            None => Ok(()),
        }
    }
}

impl SecretStore for InMemorySecretStore {
    fn put<'a>(&'a self, account: &'a str, value: Vec<u8>) -> SecretStoreFuture<'a, ()> {
        Box::pin(async move {
            self.availability()?;
            validate_identifier("account", account, 512)?;
            self.values.lock().await.insert(account.to_owned(), value);
            Ok(())
        })
    }

    fn resolve<'a>(&'a self, account: &'a str) -> SecretStoreFuture<'a, Vec<u8>> {
        Box::pin(async move {
            self.availability()?;
            validate_identifier("account", account, 512)?;
            self.values
                .lock()
                .await
                .get(account)
                .cloned()
                .ok_or(SecretStoreError::NotFound)
        })
    }

    fn delete<'a>(&'a self, account: &'a str) -> SecretStoreFuture<'a, ()> {
        Box::pin(async move {
            self.availability()?;
            validate_identifier("account", account, 512)?;
            self.values
                .lock()
                .await
                .remove(account)
                .map(|_| ())
                .ok_or(SecretStoreError::NotFound)
        })
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SecretStoreError {
    #[error("secret store {0} is invalid")]
    InvalidIdentifier(&'static str),
    #[error("secret store is unavailable: {0}")]
    Unavailable(String),
    #[error("secret was not found")]
    NotFound,
    #[error("secret store operation failed: {0}")]
    Backend(String),
}

impl SecretStoreError {
    fn backend(error: impl std::fmt::Display) -> Self {
        Self::Backend(error.to_string())
    }
}

fn validate_identifier(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), SecretStoreError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(SecretStoreError::InvalidIdentifier(field));
    }
    Ok(())
}
