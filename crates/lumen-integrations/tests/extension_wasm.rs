use std::sync::Arc;

use lumen_core::{
    action::{ActionKind, CanonicalValue},
    extension::{
        ExtensionFailure, ExtensionFailureClass, ExtensionInvocationLimits, ExtensionResponse,
        Sha256Digest,
    },
};
use lumen_extension_sdk::{
    Failure as WireFailure, FailureClass as WireFailureClass, InvocationRequest,
    InvocationResponse, Response as WireResponse,
};
use lumen_integrations::extension_wasm::{WasmComponentHost, WasmHostError};
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

fn request(id: &str) -> InvocationRequest {
    InvocationRequest::new(
        id,
        "echo",
        serde_json::json!({"message": "hello"}),
        serde_json::Value::Null,
        2_000,
    )
    .unwrap()
}

fn limits() -> ExtensionInvocationLimits {
    ExtensionInvocationLimits::new(2_000, 16 * 1024, 10_000_000, 2 * 1024 * 1024).unwrap()
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(format!("{:x}", Sha256::digest(bytes))).unwrap()
}

fn response_component(response: &InvocationResponse) -> Vec<u8> {
    let encoded = serde_json::to_string(response).unwrap();
    let data = encoded
        .as_bytes()
        .iter()
        .map(|byte| format!("\\{byte:02x}"))
        .collect::<String>();
    let wat = format!(
        r#"(component
            (core module $guest
                (memory (export "memory") 1)
                (data (i32.const 1024) "{data}")
                (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
                    i32.const 4096)
                (func (export "invoke") (param i32 i32) (result i32)
                    i32.const 512
                    i32.const 1024
                    i32.store
                    i32.const 512
                    i32.const {length}
                    i32.store offset=4
                    i32.const 512))
            (core instance $guest-instance (instantiate $guest))
            (alias core export $guest-instance "memory" (core memory $memory))
            (alias core export $guest-instance "cabi_realloc" (core func $realloc))
            (alias core export $guest-instance "invoke" (core func $core-invoke))
            (type $invoke-type (func (param "request" string) (result string)))
            (func $invoke (type $invoke-type)
                (canon lift (core func $core-invoke)
                    (memory $memory)
                    (realloc $realloc)))
            (export "invoke" (func $invoke)))"#,
        length = encoded.len()
    );
    wat::parse_str(wat).unwrap()
}

fn stateful_component(first: &InvocationResponse, later: &InvocationResponse) -> Vec<u8> {
    let first = first.encode().unwrap();
    let later = later.encode().unwrap();
    assert_eq!(first.len(), later.len());
    let encode_data = |value: &str| {
        value
            .as_bytes()
            .iter()
            .map(|byte| format!("\\{byte:02x}"))
            .collect::<String>()
    };
    wat::parse_str(format!(
        r#"(component
            (core module $guest
                (memory (export "memory") 1)
                (global $called (mut i32) (i32.const 0))
                (data (i32.const 1024) "{first}")
                (data (i32.const 2048) "{later}")
                (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
                    i32.const 4096)
                (func (export "invoke") (param i32 i32) (result i32)
                    (local $response i32)
                    global.get $called
                    if (result i32)
                        i32.const 2048
                    else
                        i32.const 1
                        global.set $called
                        i32.const 1024
                    end
                    local.set $response
                    i32.const 512
                    local.get $response
                    i32.store
                    i32.const 512
                    i32.const {length}
                    i32.store offset=4
                    i32.const 512))
            (core instance $guest-instance (instantiate $guest))
            (alias core export $guest-instance "memory" (core memory $memory))
            (alias core export $guest-instance "cabi_realloc" (core func $realloc))
            (alias core export $guest-instance "invoke" (core func $core-invoke))
            (type $invoke-type (func (param "request" string) (result string)))
            (func $invoke (type $invoke-type)
                (canon lift (core func $core-invoke) (memory $memory) (realloc $realloc)))
            (export "invoke" (func $invoke)))"#,
        first = encode_data(&first),
        later = encode_data(&later),
        length = first.len(),
    ))
    .unwrap()
}

fn looping_component() -> Vec<u8> {
    wat::parse_str(
        r#"(component
            (core module $guest
                (memory (export "memory") 1)
                (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
                    i32.const 4096)
                (func (export "invoke") (param i32 i32) (result i32)
                    (loop $forever (br $forever))
                    unreachable))
            (core instance $guest-instance (instantiate $guest))
            (alias core export $guest-instance "memory" (core memory $memory))
            (alias core export $guest-instance "cabi_realloc" (core func $realloc))
            (alias core export $guest-instance "invoke" (core func $core-invoke))
            (type $invoke-type (func (param "request" string) (result string)))
            (func $invoke (type $invoke-type)
                (canon lift (core func $core-invoke)
                    (memory $memory)
                    (realloc $realloc)))
            (export "invoke" (func $invoke)))"#,
    )
    .unwrap()
}

async fn invoke(
    bytes: Vec<u8>,
    request: InvocationRequest,
) -> Result<ExtensionResponse, WasmHostError> {
    WasmComponentHost::default()
        .invoke(
            digest(&bytes),
            Arc::from(bytes),
            request,
            limits(),
            CancellationToken::new(),
        )
        .await
}

#[tokio::test]
async fn executes_structured_results_proposals_and_typed_failures() {
    let cases = [
        (
            WireResponse::result(serde_json::json!("done")),
            ExtensionResponse::result(CanonicalValue::from("done")),
        ),
        (
            WireResponse::proposal("filesystem.read", serde_json::json!({"path": "README.md"})),
            ExtensionResponse::proposal(
                ActionKind::new("filesystem.read").unwrap(),
                CanonicalValue::object([("path", CanonicalValue::from("README.md"))]),
            ),
        ),
        (
            WireResponse::failure(
                WireFailure::new(WireFailureClass::PluginFault, "fixture failure").unwrap(),
            ),
            ExtensionResponse::failure(
                ExtensionFailure::new(ExtensionFailureClass::PluginFault, "fixture failure")
                    .unwrap(),
            ),
        ),
    ];
    for (index, (wire_response, expected)) in cases.into_iter().enumerate() {
        let request = request(&format!("request-{index}"));
        let response = InvocationResponse::new(request.request_id(), wire_response).unwrap();
        assert_eq!(
            invoke(response_component(&response), request)
                .await
                .unwrap(),
            expected
        );
    }
}

#[tokio::test]
async fn rejects_protocol_request_and_result_bound_mismatches() {
    let valid_request = request("expected");
    let wrong_id =
        InvocationResponse::new("different", WireResponse::result(serde_json::Value::Null))
            .unwrap();
    assert_eq!(
        invoke(response_component(&wrong_id), valid_request)
            .await
            .unwrap_err(),
        WasmHostError::RequestMismatch
    );

    let request = request("oversized");
    let response = InvocationResponse::new(
        request.request_id(),
        WireResponse::result(serde_json::json!("x".repeat(32 * 1024))),
    )
    .unwrap();
    assert_eq!(
        invoke(response_component(&response), request)
            .await
            .unwrap_err(),
        WasmHostError::ResponseTooLarge
    );
}

#[tokio::test]
async fn refuses_unknown_ambient_imports() {
    let bytes = wat::parse_str(
        r#"(component
            (import "wasi:cli/environment@0.2.0" (instance
                (export "get-environment" (func (result (list (tuple string string)))))))
            (type $invoke-type (func (param "request" string) (result string)))
            (core module $guest
                (memory (export "memory") 1)
                (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) i32.const 0)
                (func (export "invoke") (param i32 i32) (result i32) i32.const 0))
            (core instance $guest-instance (instantiate $guest))
            (alias core export $guest-instance "memory" (core memory $memory))
            (alias core export $guest-instance "cabi_realloc" (core func $realloc))
            (alias core export $guest-instance "invoke" (core func $core-invoke))
            (func $invoke (type $invoke-type)
                (canon lift (core func $core-invoke)
                    (memory $memory)
                    (realloc $realloc)))
            (export "invoke" (func $invoke)))"#,
    )
    .unwrap();
    assert!(matches!(
        invoke(bytes, request("imports")).await,
        Err(WasmHostError::InvalidComponent(_))
    ));
}

#[tokio::test]
async fn fresh_store_state_is_used_for_every_invocation() {
    let seed_request = request("fresh-state");
    let response = InvocationResponse::new(
        seed_request.request_id(),
        WireResponse::result(serde_json::json!("fresh")),
    )
    .unwrap();
    let stale = InvocationResponse::new(
        seed_request.request_id(),
        WireResponse::result(serde_json::json!("stale")),
    )
    .unwrap();
    let bytes = stateful_component(&response, &stale);
    let host = WasmComponentHost::default();
    let artifact_digest = digest(&bytes);
    for _ in 0..2 {
        assert_eq!(
            host.invoke(
                artifact_digest.clone(),
                Arc::from(bytes.clone()),
                request("fresh-state"),
                limits(),
                CancellationToken::new(),
            )
            .await
            .unwrap(),
            ExtensionResponse::result(CanonicalValue::from("fresh"))
        );
    }
    assert_eq!(host.compilation_metadata().len(), 1);
}

#[tokio::test]
async fn rejects_components_over_the_memory_limit_and_guest_traps() {
    let oversized_memory = wat::parse_str(
        r#"(component
            (core module $guest
                (memory (export "memory") 64)
                (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) i32.const 0)
                (func (export "invoke") (param i32 i32) (result i32) i32.const 0))
            (core instance $guest-instance (instantiate $guest))
            (alias core export $guest-instance "memory" (core memory $memory))
            (alias core export $guest-instance "cabi_realloc" (core func $realloc))
            (alias core export $guest-instance "invoke" (core func $core-invoke))
            (type $invoke-type (func (param "request" string) (result string)))
            (func $invoke (type $invoke-type)
                (canon lift (core func $core-invoke) (memory $memory) (realloc $realloc)))
            (export "invoke" (func $invoke)))"#,
    )
    .unwrap();
    assert_eq!(
        invoke(oversized_memory, request("memory"))
            .await
            .unwrap_err(),
        WasmHostError::ResourceExhaustion
    );

    let oversized_table = wat::parse_str(
        r#"(component
            (core module $guest
                (memory (export "memory") 1)
                (table 100001 funcref)
                (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) i32.const 0)
                (func (export "invoke") (param i32 i32) (result i32) i32.const 0))
            (core instance $guest-instance (instantiate $guest))
            (alias core export $guest-instance "memory" (core memory $memory))
            (alias core export $guest-instance "cabi_realloc" (core func $realloc))
            (alias core export $guest-instance "invoke" (core func $core-invoke))
            (type $invoke-type (func (param "request" string) (result string)))
            (func $invoke (type $invoke-type)
                (canon lift (core func $core-invoke) (memory $memory) (realloc $realloc)))
            (export "invoke" (func $invoke)))"#,
    )
    .unwrap();
    assert_eq!(
        invoke(oversized_table, request("table")).await.unwrap_err(),
        WasmHostError::ResourceExhaustion
    );

    let empty_instances = (0..65)
        .map(|index| format!("(core instance $empty-{index} (instantiate $empty))"))
        .collect::<String>();
    let excessive_instances = wat::parse_str(format!(
        r#"(component
            (core module $empty)
            {empty_instances}
            (core module $guest
                (memory (export "memory") 1)
                (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) i32.const 0)
                (func (export "invoke") (param i32 i32) (result i32) i32.const 0))
            (core instance $guest-instance (instantiate $guest))
            (alias core export $guest-instance "memory" (core memory $memory))
            (alias core export $guest-instance "cabi_realloc" (core func $realloc))
            (alias core export $guest-instance "invoke" (core func $core-invoke))
            (type $invoke-type (func (param "request" string) (result string)))
            (func $invoke (type $invoke-type)
                (canon lift (core func $core-invoke) (memory $memory) (realloc $realloc)))
            (export "invoke" (func $invoke)))"#,
    ))
    .unwrap();
    assert_eq!(
        invoke(excessive_instances, request("instances"))
            .await
            .unwrap_err(),
        WasmHostError::ResourceExhaustion
    );

    let trap = wat::parse_str(
        r#"(component
            (core module $guest
                (memory (export "memory") 1)
                (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) i32.const 0)
                (func (export "invoke") (param i32 i32) (result i32) unreachable))
            (core instance $guest-instance (instantiate $guest))
            (alias core export $guest-instance "memory" (core memory $memory))
            (alias core export $guest-instance "cabi_realloc" (core func $realloc))
            (alias core export $guest-instance "invoke" (core func $core-invoke))
            (type $invoke-type (func (param "request" string) (result string)))
            (func $invoke (type $invoke-type)
                (canon lift (core func $core-invoke) (memory $memory) (realloc $realloc)))
            (export "invoke" (func $invoke)))"#,
    )
    .unwrap();
    assert!(matches!(
        invoke(trap, request("trap")).await,
        Err(WasmHostError::Trap(_))
    ));
}

#[tokio::test]
async fn fuel_deadline_and_cancellation_interrupt_guest_code() {
    let bytes = looping_component();
    assert_eq!(
        invoke(bytes.clone(), request("fuel")).await.unwrap_err(),
        WasmHostError::ResourceExhaustion
    );

    let result = WasmComponentHost::default()
        .invoke(
            digest(&bytes),
            Arc::from(bytes.clone()),
            request("deadline"),
            ExtensionInvocationLimits::new(20, 16 * 1024, 1_000_000_000_000, 2 * 1024 * 1024)
                .unwrap(),
            CancellationToken::new(),
        )
        .await;
    assert_eq!(result.unwrap_err(), WasmHostError::DeadlineExceeded);

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let result = WasmComponentHost::default()
        .invoke(
            digest(&bytes),
            Arc::from(bytes),
            request("cancel"),
            ExtensionInvocationLimits::new(50, 16 * 1024, 1_000_000_000_000, 2 * 1024 * 1024)
                .unwrap(),
            cancellation,
        )
        .await;
    assert_eq!(result.unwrap_err(), WasmHostError::Cancelled);

    let cancellation = CancellationToken::new();
    let active_cancellation = cancellation.clone();
    let host = WasmComponentHost::default();
    let active_bytes = looping_component();
    let task = tokio::spawn(async move {
        host.invoke(
            digest(&active_bytes),
            Arc::from(active_bytes),
            request("active-cancel"),
            ExtensionInvocationLimits::new(2_000, 16 * 1024, 1_000_000_000_000, 2 * 1024 * 1024)
                .unwrap(),
            active_cancellation,
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    cancellation.cancel();
    assert_eq!(task.await.unwrap().unwrap_err(), WasmHostError::Cancelled);
}

#[tokio::test]
async fn validates_digest_and_component_shape_without_execution() {
    let request = request("digest");
    let response = InvocationResponse::new(
        request.request_id(),
        WireResponse::result(serde_json::Value::Null),
    )
    .unwrap();
    let bytes = response_component(&response);
    let wrong = Sha256Digest::parse("0".repeat(64)).unwrap();
    assert_eq!(
        WasmComponentHost::default()
            .invoke(
                wrong,
                Arc::from(bytes),
                request,
                limits(),
                CancellationToken::new(),
            )
            .await
            .unwrap_err(),
        WasmHostError::ArtifactDigestMismatch
    );
}
