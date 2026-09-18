#![cfg(feature = "model-client")]

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use lumen_core::{
    action::CanonicalValue,
    model::{
        ModelInput, ModelMessage, ModelOutput, ModelPort, ModelRole, ModelTool, ModelToolCall,
    },
};
use lumen_integrations::openai_compatible::{
    EndpointClass, EndpointPolicy, OllamaGpuPolicy, OpenAiCompatibleClient, OpenAiCompatibleConfig,
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

fn gpu_config(server: &MockServer, policy: OllamaGpuPolicy) -> OpenAiCompatibleConfig {
    config(server)
        .with_ollama_gpu_policy(policy)
        .expect("local Ollama GPU policy")
}

fn loaded_model(size: u64, size_vram: u64) -> serde_json::Value {
    json!({"models": [{"name": "local-model", "size": size, "size_vram": size_vram}]})
}

fn completion() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "choices": [{"finish_reason":"stop", "message": {"content": "guarded answer"}}]
    }))
}

#[tokio::test]
async fn require_full_rejects_non_gpu_and_unknown_residency_before_user_content() {
    for (label, response, expected) in [
        (
            "mixed",
            ResponseTemplate::new(200).set_body_json(loaded_model(100, 60)),
            "mixed",
        ),
        (
            "cpu",
            ResponseTemplate::new(200).set_body_json(loaded_model(100, 0)),
            "CPU-only",
        ),
        ("unavailable", ResponseTemplate::new(503), "unavailable"),
        (
            "unknown",
            ResponseTemplate::new(200).set_body_json(json!({"models": [{"name": "local-model"}]})),
            "unknown",
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/ps"))
            .respond_with(response)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(completion())
            .mount(&server)
            .await;
        let client = OpenAiCompatibleClient::new(gpu_config(&server, OllamaGpuPolicy::RequireFull))
            .expect("client");

        let error = client.generate(input()).await.expect_err(label);
        assert!(error.message().contains(expected), "{label}: {error}");
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1, "{label}: must not send user content");
        assert_eq!(requests[0].url.path(), "/api/ps");
    }
}

#[tokio::test]
async fn require_full_accepts_full_residency_and_checks_after_completion() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/ps"))
        .respond_with(ResponseTemplate::new(200).set_body_json(loaded_model(100, 100)))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(completion())
        .mount(&server)
        .await;
    let client = OpenAiCompatibleClient::new(gpu_config(&server, OllamaGpuPolicy::RequireFull))
        .expect("client");

    assert_eq!(
        client.generate(input()).await.expect("full GPU"),
        ModelOutput::FinalText("guarded answer".into())
    );
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(
        requests
            .iter()
            .map(|request| request.url.path())
            .collect::<Vec<_>>(),
        ["/api/ps", "/v1/chat/completions", "/api/ps"]
    );
}

#[tokio::test]
async fn allow_mixed_accepts_partial_offload_but_not_cpu_only() {
    for (size_vram, allowed) in [(60, true), (0, false)] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/ps"))
            .respond_with(ResponseTemplate::new(200).set_body_json(loaded_model(100, size_vram)))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(completion())
            .mount(&server)
            .await;
        let client = OpenAiCompatibleClient::new(gpu_config(&server, OllamaGpuPolicy::AllowMixed))
            .expect("client");
        let result = client.generate(input()).await;
        assert_eq!(result.is_ok(), allowed);
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.url.path() == "/v1/chat/completions")
                .count(),
            usize::from(allowed)
        );
    }
}

#[tokio::test]
async fn absent_model_is_preloaded_without_user_content_then_checked() {
    let server = MockServer::start().await;
    let probes = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&probes);
    Mock::given(method("GET"))
        .and(path("/api/ps"))
        .respond_with(move |_: &wiremock::Request| {
            let models = if count.fetch_add(1, Ordering::SeqCst) == 0 {
                json!({"models": []})
            } else {
                loaded_model(100, 100)
            };
            ResponseTemplate::new(200).set_body_json(models)
        })
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/generate"))
        .and(body_json(
            json!({"model": "local-model", "prompt": "", "stream": false}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"done": true})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(completion())
        .mount(&server)
        .await;
    let client = OpenAiCompatibleClient::new(gpu_config(&server, OllamaGpuPolicy::RequireFull))
        .expect("client");

    assert!(client.generate(input()).await.is_ok());
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(
        requests
            .iter()
            .map(|request| request.url.path())
            .collect::<Vec<_>>(),
        [
            "/api/ps",
            "/api/generate",
            "/api/ps",
            "/v1/chat/completions",
            "/api/ps"
        ]
    );
}

#[tokio::test]
async fn failed_ollama_preload_never_sends_user_content() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/ps"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/generate"))
        .and(body_json(
            json!({"model": "local-model", "prompt": "", "stream": false}),
        ))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(completion())
        .mount(&server)
        .await;
    let client = OpenAiCompatibleClient::new(gpu_config(&server, OllamaGpuPolicy::RequireFull))
        .expect("client");

    let error = client
        .generate(input())
        .await
        .expect_err("backend unavailable");
    assert!(error.message().contains("preload unavailable: HTTP 503"));
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(
        requests
            .iter()
            .map(|request| request.url.path())
            .collect::<Vec<_>>(),
        ["/api/ps", "/api/generate"]
    );
}

#[tokio::test]
async fn post_request_downgrade_withholds_model_output() {
    let server = MockServer::start().await;
    let probes = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&probes);
    Mock::given(method("GET"))
        .and(path("/api/ps"))
        .respond_with(move |_: &wiremock::Request| {
            let vram = if count.fetch_add(1, Ordering::SeqCst) == 0 {
                100
            } else {
                0
            };
            ResponseTemplate::new(200).set_body_json(loaded_model(100, vram))
        })
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(completion())
        .mount(&server)
        .await;
    let client = OpenAiCompatibleClient::new(gpu_config(&server, OllamaGpuPolicy::RequireFull))
        .expect("client");

    let error = client.generate(input()).await.expect_err("CPU downgrade");
    assert!(error.message().contains("CPU-only"));
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(
        requests
            .iter()
            .map(|request| request.url.path())
            .collect::<Vec<_>>(),
        ["/api/ps", "/v1/chat/completions", "/api/ps"]
    );
}

#[test]
fn gpu_policy_is_limited_to_loopback_ollama_v1_endpoint() {
    let normalized = OpenAiCompatibleConfig::new(
        "http://127.0.0.1:11434/v1",
        "model",
        EndpointPolicy::LoopbackOnly,
    )
    .expect("local endpoint without trailing slash");
    assert!(
        normalized
            .with_ollama_gpu_policy(OllamaGpuPolicy::RequireFull)
            .is_ok()
    );
    let remote = OpenAiCompatibleConfig::new(
        "https://models.example.com/v1/",
        "model",
        EndpointPolicy::AllowRemote,
    )
    .expect("remote opt-in config");
    assert!(
        remote
            .with_ollama_gpu_policy(OllamaGpuPolicy::RequireFull)
            .is_err()
    );
    let other_local = OpenAiCompatibleConfig::new(
        "http://127.0.0.1:11434/other/",
        "model",
        EndpointPolicy::LoopbackOnly,
    )
    .expect("local config");
    assert!(
        other_local
            .with_ollama_gpu_policy(OllamaGpuPolicy::RequireFull)
            .is_err()
    );
}

#[tokio::test]
async fn opt_in_local_catalog_probe_distinguishes_listed_missing_and_unavailable_models() {
    let listed = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list", "data": [{"id": "local-model", "object": "model"}]
        })))
        .mount(&listed)
        .await;
    let client = OpenAiCompatibleClient::new(config(&listed)).expect("listed client");
    assert!(client.probe_local_model().await.expect("listed catalog"));

    let missing = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list", "data": [{"id": "other-model", "object": "model"}]
        })))
        .mount(&missing)
        .await;
    let client = OpenAiCompatibleClient::new(config(&missing)).expect("missing client");
    assert!(!client.probe_local_model().await.expect("missing catalog"));

    let unavailable = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&unavailable)
        .await;
    let client = OpenAiCompatibleClient::new(config(&unavailable)).expect("unavailable client");
    assert!(client.probe_local_model().await.is_err());
}

#[tokio::test]
async fn catalog_probe_refuses_remote_egress_without_a_model_policy_decision() {
    let config = OpenAiCompatibleConfig::new(
        "http://example.invalid/v1/",
        "remote-model",
        EndpointPolicy::AllowRemote,
    )
    .expect("remote config");
    let client = OpenAiCompatibleClient::new(config).expect("remote client");
    let error = client
        .probe_local_model()
        .await
        .expect_err("remote probe denied");
    assert!(
        error
            .to_string()
            .contains("remote model catalog probe is not allowed")
    );
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
            "choices": [{"finish_reason":"stop", "message": {"content": "hello back"}}]
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
            "choices": [{"finish_reason":"stop", "message": {"content": "random-nonce"}}]
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
                "finish_reason": "tool_calls",
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
                "finish_reason": "tool_calls",
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
            "choices": [{"finish_reason":"tool_calls", "message": {"tool_calls": [{
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
            "choices": [{"finish_reason":"tool_calls", "message": {"tool_calls": [
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
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
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
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
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
async fn refuses_streamed_tool_call_without_transport_and_finish_finality() {
    for (body, expected) in [
        (
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call-1\",\"type\":\"function\",\"function\":{\"name\":\"filesystem_read\",\"arguments\":\"{\\\"path\\\":\\\"nonce.txt\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "before [DONE]",
        ),
        (
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"looks complete\"}}]}\n\ndata: [DONE]\n\n",
            "terminal finish reason",
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_raw(body, "text/event-stream"),
            )
            .mount(&server)
            .await;
        let client =
            OpenAiCompatibleClient::new(config(&server).with_streaming(true)).expect("client");
        let error = client
            .generate(tool_input())
            .await
            .expect_err("incomplete stream refused");
        assert!(error.message().contains(expected), "{error}");
    }
}

#[tokio::test]
async fn refuses_nonstream_length_and_finish_content_mismatch() {
    for (finish, content, expected) in [
        ("length", "partial", "length"),
        ("tool_calls", "plain text", "tool_calls"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "choices": [{"finish_reason": finish, "message": {"content": content}}]
            })))
            .mount(&server)
            .await;
        let client = OpenAiCompatibleClient::new(config(&server)).expect("client");
        let error = client
            .generate(input())
            .await
            .expect_err("invalid finish refused");
        assert!(error.message().contains(expected), "{error}");
    }
}

#[tokio::test]
async fn refuses_stream_finish_failures_and_malformed_sse() {
    for (body, expected) in [
        (
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"},\"finish_reason\":\"length\"}]}\n\ndata: [DONE]\n\n",
            "length",
        ),
        (
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"filtered\"},\"finish_reason\":\"content_filter\"}]}\n\ndata: [DONE]\n\n",
            "content_filter",
        ),
        ("data: not-json\n\n", "invalid model stream JSON"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_raw(body, "text/event-stream"),
            )
            .mount(&server)
            .await;
        let client =
            OpenAiCompatibleClient::new(config(&server).with_streaming(true)).expect("client");
        let error = client
            .generate(input())
            .await
            .expect_err("invalid stream refused");
        assert!(error.message().contains(expected), "{error}");
    }
}

#[tokio::test]
async fn refuses_conflicting_streamed_tool_id_and_multiple_indices() {
    let first = json!({"choices":[{"index":0,"delta":{"tool_calls":[{
        "index":0,"id":"call-one","type":"function",
        "function":{"name":"filesystem_read","arguments":"{\"path\":\"nonce.txt\"}"}
    }]}}]});
    for (second, expected) in [
        (
            json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call-two","function":{}}]},"finish_reason":"tool_calls"}]}),
            "conflicting streamed tool call ID",
        ),
        (
            json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call-two","function":{}}]},"finish_reason":"tool_calls"}]}),
            "multiple tool calls",
        ),
    ] {
        let server = MockServer::start().await;
        let body = format!("data: {first}\n\ndata: {second}\n\ndata: [DONE]\n\n");
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_raw(body, "text/event-stream"),
            )
            .mount(&server)
            .await;
        let client =
            OpenAiCompatibleClient::new(config(&server).with_streaming(true)).expect("client");
        let error = client
            .generate(tool_input())
            .await
            .expect_err("conflicting tool refused");
        assert!(error.message().contains(expected), "{error}");
    }
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
