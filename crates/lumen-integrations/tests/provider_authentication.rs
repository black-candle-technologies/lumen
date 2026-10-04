#![cfg(feature = "model-client")]

mod common;
use common::{Reply, TlsServer};
use lumen_core::{
    egress::ProviderId,
    model::{ModelInput, ModelMessage, ModelRole},
    provider::{
        ModelCapabilities, ModelCapability, ModelProfile, ModelProfileId, ModelTrustZone,
        ProviderAdapter, ProviderConfig, ProviderKind,
    },
    secret::SecretRefId,
};
use lumen_integrations::providers::{
    ProviderCredential, ProviderHttpOptions, openai_compatible::OpenAiCompatibleAdapter,
};
use serde_json::json;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
fn config(endpoint: &str) -> ProviderConfig {
    ProviderConfig::remote(
        ProviderId::parse("compatible").unwrap(),
        1,
        ProviderKind::OpenAiCompatible,
        endpoint,
        true,
        SecretRefId::new(),
    )
    .unwrap()
}
fn profile(p: &ProviderConfig) -> ModelProfile {
    ModelProfile::new(
        ModelProfileId::parse("text").unwrap(),
        1,
        p.id().clone(),
        1,
        "model",
        true,
        ModelCapabilities::new([ModelCapability::Text]),
        4096,
        ModelTrustZone::RemoteUntrusted,
        1,
        0,
    )
    .unwrap()
}
fn key() -> ProviderCredential {
    ProviderCredential::from_keyring(Zeroizing::new(b"sentinel-auth-key".to_vec())).unwrap()
}
fn input() -> ModelInput {
    ModelInput::new(vec![ModelMessage::new(ModelRole::User, "hello".into())])
}
#[tokio::test]
async fn remote_compatible_authenticates_and_omits_empty_tools() {
    let server = TlsServer::new().await;
    let p = config(&server.endpoint);
    let m = profile(&p);
    let adapter =
        OpenAiCompatibleAdapter::new_with_options(p, Some(key()), ProviderHttpOptions::default())
            .unwrap()
            .with_http_client(server.client.clone());
    adapter
        .generate(&m, input(), CancellationToken::new())
        .await
        .unwrap();
    let requests = server.requests.lock().await;
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("POST /gateway/v1/chat/completions "));
    assert!(requests[0].contains("authorization: Bearer sentinel-auth-key"));
    let body: serde_json::Value =
        serde_json::from_str(requests[0].split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert!(body.get("tools").is_none());
    assert!(body.get("parallel_tool_calls").is_none());
    assert!(!body.to_string().contains("sentinel-auth-key"));
}
#[tokio::test]
async fn redirects_bounded_bodies_errors_and_invalid_json_are_safe() {
    let server = TlsServer::new().await;
    let p = config(&server.endpoint);
    let m = profile(&p);
    let adapter = OpenAiCompatibleAdapter::new_with_options(
        p,
        Some(key()),
        ProviderHttpOptions {
            timeout: Duration::from_secs(2),
            max_response_bytes: 256,
        },
    )
    .unwrap()
    .with_http_client(server.client.clone());
    for reply in [
        Reply {
            status: 302,
            location: Some(server.endpoint.clone()),
            body: "sentinel-auth-key".into(),
            delay: Duration::ZERO,
        },
        Reply {
            status: 401,
            location: None,
            body: "sentinel-auth-key".into(),
            delay: Duration::ZERO,
        },
        Reply {
            status: 200,
            location: None,
            body: "x".repeat(257),
            delay: Duration::ZERO,
        },
        Reply {
            status: 200,
            location: None,
            body: "sentinel-auth-key malformed JSON".into(),
            delay: Duration::ZERO,
        },
    ] {
        server.replies.lock().await.push_back(reply);
        let error = adapter
            .generate(&m, input(), CancellationToken::new())
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("sentinel-auth-key"));
    }
    assert_eq!(
        server.requests.lock().await.len(),
        4,
        "redirect must not be followed"
    );
}
#[tokio::test]
async fn cancellation_and_timeout_cover_body_reading() {
    let server = TlsServer::new().await;
    let p = config(&server.endpoint);
    let m = profile(&p);
    let adapter = OpenAiCompatibleAdapter::new_with_options(
        p,
        Some(key()),
        ProviderHttpOptions {
            timeout: Duration::from_millis(100),
            max_response_bytes: 1024,
        },
    )
    .unwrap()
    .with_http_client(server.client.clone());
    let mut reply =
        Reply::json(json!({"choices":[{"message":{"content":"hello"},"finish_reason":"stop"}]}));
    reply.delay = Duration::from_secs(2);
    server.replies.lock().await.push_back(reply.clone());
    let started = std::time::Instant::now();
    assert!(
        adapter
            .generate(&m, input(), CancellationToken::new())
            .await
            .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    server.replies.lock().await.push_back(reply);
    let token = CancellationToken::new();
    let cancel = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel.cancel();
    });
    assert!(adapter.generate(&m, input(), token).await.is_err());
    let token = CancellationToken::new();
    token.cancel();
    let seen = server.requests.lock().await.len();
    assert!(adapter.generate(&m, input(), token).await.is_err());
    assert_eq!(server.requests.lock().await.len(), seen);
}
#[tokio::test]
async fn untrusted_tls_certificate_is_rejected_before_authentication() {
    let server = TlsServer::new().await;
    let p = config(&server.endpoint);
    let m = profile(&p);
    let port = p.endpoint().port().unwrap();
    let client = reqwest::Client::builder()
        .resolve(
            "provider.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        )
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let adapter =
        OpenAiCompatibleAdapter::new_with_options(p, Some(key()), ProviderHttpOptions::default())
            .unwrap()
            .with_http_client(client);
    assert!(
        adapter
            .generate(&m, input(), CancellationToken::new())
            .await
            .is_err()
    );
    assert!(server.requests.lock().await.is_empty());
}
