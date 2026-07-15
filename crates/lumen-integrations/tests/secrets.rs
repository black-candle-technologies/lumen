#[cfg(feature = "native-secrets")]
use lumen_integrations::secrets::OsKeyringSecretStore;
use lumen_integrations::secrets::{InMemorySecretStore, SecretStore};

#[tokio::test]
async fn in_memory_secret_store_contract_covers_put_resolve_and_delete() {
    let store = InMemorySecretStore::new();

    store
        .put("workspace/ref", b"top-secret".to_vec())
        .await
        .expect("secret stored");
    assert_eq!(
        store.resolve("workspace/ref").await.expect("secret read"),
        b"top-secret"
    );
    store.delete("workspace/ref").await.expect("secret deleted");
    assert!(store.resolve("workspace/ref").await.is_err());
}

#[tokio::test]
async fn unavailable_secret_store_fails_closed_for_every_operation() {
    let store = InMemorySecretStore::unavailable("credential service is locked");

    assert!(store.put("ref", b"value".to_vec()).await.is_err());
    assert!(store.resolve("ref").await.is_err());
    assert!(store.delete("ref").await.is_err());
}

#[test]
#[cfg(feature = "native-secrets")]
fn os_keyring_adapter_rejects_invalid_service_names() {
    assert!(OsKeyringSecretStore::new("").is_err());
    assert!(OsKeyringSecretStore::new(" dev.lumen.runtime ").is_err());
    assert!(OsKeyringSecretStore::new("dev.lumen.runtime").is_ok());
}
