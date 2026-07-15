#![cfg(feature = "model-client")]

use std::time::Duration;

use lumen_core::{
    action::CanonicalValue,
    model::{ModelInput, ModelMessage, ModelOutput, ModelPort, ModelRole},
};
use lumen_integrations::openai_compatible::{
    EndpointClass, EndpointPolicy, OpenAiCompatibleClient, OpenAiCompatibleConfig,
};
use serde_json::json;
use tokio_util::sync::CancellationToken;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path},
};

fn input() -> ModelInput {
    ModelInput::new(vec![ModelMessage::new(
        ModelRole::User,
        CanonicalValue::from("hello"),
    )])
}

fn config(server: &MockServer) -> OpenAiCompatibleConfig {
    OpenAiCompatibleConfig::new(
        format!("{}/v1/", server.uri()),
        "local-model",
        EndpointPolicy::LoopbackOnly,
    )
    .expect("loopback config")
}

#[tokio::test]
async fn sends_openai_request_and_parses_text_completion() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_json(json!({
            "model": "local-model",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "model": "resolved-model",
            "choices": [{"message": {"content": "hello back"}}]
        })))
        .mount(&server)
        .await;
    let client = OpenAiCompatibleClient::new(config(&server)).expect("client builds");

    let output = client.generate(input()).await.expect("completion succeeds");

    assert_eq!(output, ModelOutput::FinalText("hello back".into()));
    assert_eq!(client.identity().configured_model(), "local-model");
    assert_eq!(client.identity().endpoint_class(), EndpointClass::Local);
}

#[tokio::test]
async fn parses_structured_tool_call_as_untrusted_action_proposal() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{
                "message": {
                    "content": null,
                    "tool_calls": [{
                        "function": {
                            "name": "filesystem.read",
                            "arguments": "{\"path\":\"notes/today.md\"}"
                        }
                    }]
                }
            }]
        })))
        .mount(&server)
        .await;
    let client = OpenAiCompatibleClient::new(config(&server)).expect("client builds");

    let output = client.generate(input()).await.expect("completion succeeds");

    match output {
        ModelOutput::Action(proposal) => {
            assert_eq!(proposal.kind(), "filesystem.read");
            assert_eq!(
                proposal.into_arguments(),
                CanonicalValue::object([("path", CanonicalValue::from("notes/today.md"))])
            );
        }
        other => panic!("expected action proposal, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_malformed_tool_arguments() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{
                "message": {
                    "tool_calls": [{
                        "function": {
                            "name": "filesystem.read",
                            "arguments": "not-json"
                        }
                    }]
                }
            }]
        })))
        .mount(&server)
        .await;
    let client = OpenAiCompatibleClient::new(config(&server)).expect("client builds");

    let error = client
        .generate(input())
        .await
        .expect_err("malformed arguments fail");

    assert!(error.message().contains("tool arguments"));
}

#[tokio::test]
async fn consumes_sse_stream_and_aggregates_text() {
    let server = MockServer::start().await;
    let body = concat!(
        "data: {\"choices\":[{\"delta\":{\"content\":\"hel\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(body_json(json!({
            "model": "local-model",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": true
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_raw(body, "text/event-stream"),
        )
        .mount(&server)
        .await;
    let client =
        OpenAiCompatibleClient::new(config(&server).with_streaming(true)).expect("client builds");

    let output = client.generate(input()).await.expect("stream succeeds");

    assert_eq!(output, ModelOutput::FinalText("hello".into()));
}

#[tokio::test]
async fn cancellation_stops_an_in_flight_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(2))
                .set_body_json(json!({"choices": []})),
        )
        .mount(&server)
        .await;
    let client = OpenAiCompatibleClient::new(config(&server).with_timeout(Duration::from_secs(5)))
        .expect("client builds");
    let cancellation = CancellationToken::new();
    let cancel = cancellation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel.cancel();
    });

    let error = client
        .generate_cancellable(input(), cancellation)
        .await
        .expect_err("request is cancelled");

    assert_eq!(error.message(), "model request cancelled");
}

#[tokio::test]
async fn request_timeout_is_reported_without_fallback() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(1))
                .set_body_json(json!({"choices": []})),
        )
        .mount(&server)
        .await;
    let client =
        OpenAiCompatibleClient::new(config(&server).with_timeout(Duration::from_millis(20)))
            .expect("client builds");

    let error = client
        .generate(input())
        .await
        .expect_err("request times out");

    assert!(error.message().contains("timed out"));
}

#[tokio::test]
async fn response_body_is_rejected_when_it_exceeds_the_configured_limit() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "x".repeat(1024)}}]
        })))
        .mount(&server)
        .await;
    let client = OpenAiCompatibleClient::new(config(&server).with_max_response_bytes(128))
        .expect("client builds");

    let error = client
        .generate(input())
        .await
        .expect_err("oversized response is rejected");

    assert!(error.message().contains("response byte limit"));
}

#[test]
fn non_loopback_endpoint_requires_explicit_remote_policy() {
    let rejected = OpenAiCompatibleConfig::new(
        "https://models.example.com/v1/",
        "remote-model",
        EndpointPolicy::LoopbackOnly,
    );
    assert!(rejected.is_err());

    let allowed = OpenAiCompatibleConfig::new(
        "https://models.example.com/v1/",
        "remote-model",
        EndpointPolicy::AllowRemote,
    )
    .expect("remote endpoint explicitly allowed");
    assert_eq!(allowed.endpoint_class(), EndpointClass::Remote);
}
