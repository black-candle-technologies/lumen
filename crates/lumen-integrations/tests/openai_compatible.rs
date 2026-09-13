#![cfg(feature = "model-client")]

use std::time::Duration;

use lumen_core::{
    action::CanonicalValue,
    model::{
        ModelInput, ModelMessage, ModelOutput, ModelPort, ModelRole, ModelTool, ModelToolCall,
    },
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

fn read_tool() -> ModelTool {
    ModelTool::new(
        "filesystem_read",
        "Read a workspace file.",
        "filesystem.read",
        CanonicalValue::object([
            ("type", CanonicalValue::from("object")),
            (
                "properties",
                CanonicalValue::object([(
                    "path",
                    CanonicalValue::object([("type", CanonicalValue::from("string"))]),
                )]),
            ),
            (
                "required",
                CanonicalValue::Array(vec![CanonicalValue::from("path")]),
            ),
            ("additionalProperties", CanonicalValue::from(false)),
        ]),
    )
}

fn tool_input() -> ModelInput {
    input().with_tools(vec![read_tool()])
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
async fn sends_runtime_tool_schema_and_correlated_follow_up_messages() {
    let server = MockServer::start().await;
    let call = ModelToolCall::new(
        "call-1",
        "filesystem_read",
        CanonicalValue::object([("path", CanonicalValue::from("nonce.txt"))]),
    );
    let input = ModelInput::new(vec![
        ModelMessage::new(ModelRole::User, CanonicalValue::from("read nonce.txt")),
        ModelMessage::assistant_tool_call(call),
        ModelMessage::tool_result(
            "call-1",
            CanonicalValue::object([("contents", CanonicalValue::from("random-nonce"))]),
        ),
    ])
    .with_tools(vec![read_tool()]);
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_json(json!({
            "model": "local-model",
            "messages": [
                {"role": "user", "content": "read nonce.txt"},
                {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "filesystem_read",
                            "arguments": "{\"path\":\"nonce.txt\"}"
                        }
                    }]
                },
                {
                    "role": "tool",
                    "content": "{\"contents\":\"random-nonce\"}",
                    "tool_call_id": "call-1"
                }
            ],
            "stream": false,
            "tools": [{
                "type": "function",
                "function": {
                    "name": "filesystem_read",
                    "description": "Read a workspace file.",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                        "additionalProperties": false
                    }
                }
            }]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "random-nonce"}}]
        })))
        .mount(&server)
        .await;
    let client = OpenAiCompatibleClient::new(config(&server)).expect("client builds");

    let output = client.generate(input).await.expect("completion succeeds");

    assert_eq!(output, ModelOutput::FinalText("random-nonce".into()));
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
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "filesystem_read",
                            "arguments": "{\"path\":\"notes/today.md\"}"
                        }
                    }]
                }
            }]
        })))
        .mount(&server)
        .await;
    let client = OpenAiCompatibleClient::new(config(&server)).expect("client builds");

    let output = client
        .generate(tool_input())
        .await
        .expect("completion succeeds");

    match output {
        ModelOutput::Action(proposal) => {
            assert_eq!(proposal.kind(), "filesystem.read");
            let call = proposal.tool_call().expect("tool call identity");
            assert_eq!(call.id(), "call-1");
            assert_eq!(call.name(), "filesystem_read");
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
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "filesystem_read",
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
        .generate(tool_input())
        .await
        .expect_err("malformed arguments fail");

    assert!(error.message().contains("tool arguments"));
}

#[tokio::test]
async fn rejects_unknown_or_multiple_tool_calls() {
    let unknown_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"tool_calls": [{
                "id": "call-1",
                "type": "function",
                "function": {"name": "unknown_tool", "arguments": "{}"}
            }]}}]
        })))
        .mount(&unknown_server)
        .await;
    let client = OpenAiCompatibleClient::new(config(&unknown_server)).expect("client builds");
    let error = client
        .generate(tool_input())
        .await
        .expect_err("unknown tool fails");
    assert!(error.message().contains("unknown tool"));

    let multiple_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"tool_calls": [
                {
                    "id": "call-1",
                    "type": "function",
                    "function": {"name": "filesystem_read", "arguments": "{\"path\":\"a\"}"}
                },
                {
                    "id": "call-2",
                    "type": "function",
                    "function": {"name": "filesystem_read", "arguments": "{\"path\":\"b\"}"}
                }
            ]}}]
        })))
        .mount(&multiple_server)
        .await;
    let client = OpenAiCompatibleClient::new(config(&multiple_server)).expect("client builds");
    let error = client
        .generate(tool_input())
        .await
        .expect_err("multiple calls fail");
    assert!(error.message().contains("multiple tool calls"));
}

#[tokio::test]
async fn streams_one_tool_call_without_losing_its_identity() {
    let server = MockServer::start().await;
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call-1\",\"type\":\"function\",\"function\":{\"name\":\"filesystem_\",\"arguments\":\"{\\\"path\\\":\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"read\",\"arguments\":\"\\\"nonce.txt\\\"}\"}}]}}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_raw(body, "text/event-stream"),
        )
        .mount(&server)
        .await;
    let client =
        OpenAiCompatibleClient::new(config(&server).with_streaming(true)).expect("client builds");

    let output = client
        .generate(tool_input())
        .await
        .expect("streamed tool call succeeds");

    let ModelOutput::Action(proposal) = output else {
        panic!("expected action proposal")
    };
    assert_eq!(proposal.kind(), "filesystem.read");
    assert_eq!(proposal.tool_call().expect("call identity").id(), "call-1");
}

#[tokio::test]
async fn consumes_sse_stream_and_aggregates_text() {
    let server = MockServer::start().await;
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\"}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"}}]}\n\n",
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
async fn unreachable_endpoint_is_reported_without_fallback() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    let endpoint = format!(
        "http://{}/v1/",
        listener.local_addr().expect("loopback address")
    );
    drop(listener);
    let config = OpenAiCompatibleConfig::new(endpoint, "local-model", EndpointPolicy::LoopbackOnly)
        .expect("loopback config")
        .with_timeout(Duration::from_secs(1));
    let client = OpenAiCompatibleClient::new(config).expect("client builds");

    let error = client
        .generate(input())
        .await
        .expect_err("endpoint is unreachable");

    assert!(
        error.message().contains("model request failed")
            || error.message() == "model request timed out",
        "unexpected error: {}",
        error.message()
    );
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
