use lumen_server::pi_tool_bridge::{
    BridgeError, MAX_BRIDGE_METADATA_BYTES, MAX_BRIDGE_READ_BYTES, MAX_BRIDGE_REPLY_BYTES,
    MAX_BRIDGE_REQUEST_BYTES, PiReadRequest, PiToolReply,
};
use lumen_server::{AuditRef, ResourceUsage, ToolOutcome};
use serde_json::{Value, json};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../lumen-protocol/fixtures/pibridge_read_request.v2.json"
    ))
    .unwrap()
}

#[test]
fn versioned_read_intent_fixture_decodes() {
    let request = PiReadRequest::decode(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
    assert_eq!(request.version, 2);
    assert_eq!(request.tool, "bct.read_file");
}

#[test]
fn pi_cannot_supply_authority_or_expand_the_tool_catalog() {
    for field in [
        "session_id",
        "lease_chain",
        "resources",
        "effects",
        "nonce",
        "expires_at",
        "credential",
    ] {
        let mut value = fixture();
        value[field] = json!("forged");
        assert!(
            PiReadRequest::decode(&serde_json::to_vec(&value).unwrap()).is_err(),
            "{field}"
        );
    }
    for version in [0, 1, 3, u32::MAX] {
        let mut value = fixture();
        value["version"] = json!(version);
        assert!(PiReadRequest::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    for tool in [
        "bash",
        "bct.shell.run",
        "bct.fs.write",
        "bct.read_file.extra",
    ] {
        let mut value = fixture();
        value["tool"] = json!(tool);
        assert!(PiReadRequest::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}

#[test]
fn malformed_and_oversized_requests_fail_closed() {
    for arguments in [
        json!({"path":"/a","max_bytes":0}),
        json!({"path":"/a","max_bytes":1.5}),
        json!({"path":"relative","max_bytes":1}),
        json!({"path":"/a","max_bytes":1048577}),
        json!({"path":"/a","max_bytes":1,"shell":"id"}),
        json!({"path":"/a\u{0}","max_bytes":1}),
    ] {
        let mut value = fixture();
        value["arguments"] = arguments;
        assert!(PiReadRequest::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    assert!(PiReadRequest::decode(&vec![b' '; MAX_BRIDGE_REQUEST_BYTES + 1]).is_err());
    let mut duplicate = serde_json::to_string(&fixture()).unwrap();
    duplicate.insert_str(1, "\"version\":2,");
    assert!(PiReadRequest::decode(duplicate.as_bytes()).is_err());
}

fn completed(output: String) -> PiToolReply {
    PiToolReply {
        version: 2,
        tool_call_id: "c".repeat(128),
        action_digest: "a".repeat(64),
        outcome: ToolOutcome::Completed {
            result: json!({"exit_code": 0, "output_tail": output}),
            usage: ResourceUsage {
                cpu_ms: 1234,
                memory_bytes_max: 268_435_456,
                egress_bytes: 0,
            },
            audit_ref: AuditRef {
                event_id: "018f6c6e-7f4a-7000-8000-0123456789ab".into(),
                chain_hash: "b".repeat(64),
            },
        },
    }
}

#[test]
fn rust_limits_match_the_shared_pibridge_v2_wire_budget() {
    let budget: Value = serde_json::from_str(include_str!(
        "../../lumen-protocol/fixtures/pibridge_reply_budget.v2.json"
    ))
    .unwrap();
    assert_eq!(MAX_BRIDGE_READ_BYTES, budget["max_decoded_bytes"]);
    assert_eq!(MAX_BRIDGE_METADATA_BYTES, budget["max_metadata_bytes"]);
    assert_eq!(MAX_BRIDGE_REPLY_BYTES, budget["max_wire_bytes"]);
    assert_eq!(
        MAX_BRIDGE_REPLY_BYTES,
        budget["max_json_escape_bytes_per_decoded_byte"]
            .as_u64()
            .unwrap() as usize
            * MAX_BRIDGE_READ_BYTES as usize
            + MAX_BRIDGE_METADATA_BYTES
    );
    let mut request = fixture();
    request["arguments"]["max_bytes"] = json!(MAX_BRIDGE_READ_BYTES);
    assert!(PiReadRequest::decode(&serde_json::to_vec(&request).unwrap()).is_ok());
    request["arguments"]["max_bytes"] = json!(MAX_BRIDGE_READ_BYTES + 1);
    assert!(PiReadRequest::decode(&serde_json::to_vec(&request).unwrap()).is_err());
}

#[test]
fn escaped_and_multibyte_results_round_trip_at_cap_and_reject_floods() {
    let cap = MAX_BRIDGE_READ_BYTES as usize;
    for unit in ["\n", "\"", "\\", "\u{1}", "é日😀a"] {
        let text = unit.repeat(cap / unit.len()) + &"x".repeat(cap % unit.len());
        assert_eq!(text.len(), cap);
        let mut reply = completed(text.clone());
        let wire = reply.encode(MAX_BRIDGE_READ_BYTES).unwrap();
        assert!(wire.len() <= MAX_BRIDGE_REPLY_BYTES);
        let decoded: PiToolReply = serde_json::from_slice(&wire).unwrap();
        assert_eq!(decoded.tool_call_id, reply.tool_call_id);
        assert_eq!(decoded.action_digest, reply.action_digest);
        assert_eq!(decoded.outcome, reply.outcome);

        if let ToolOutcome::Completed { result, .. } = &mut reply.outcome {
            result["output_tail"] = json!(text + "x");
        }
        assert!(serde_json::to_vec(&reply).unwrap().len() < MAX_BRIDGE_REPLY_BYTES);
        assert!(matches!(
            reply.encode(MAX_BRIDGE_READ_BYTES),
            Err(BridgeError::ReplyLimit)
        ));
        assert!(matches!(
            reply.encode(MAX_BRIDGE_READ_BYTES + 1),
            Err(BridgeError::ReplyLimit)
        ));

        let flood = completed(unit.repeat(MAX_BRIDGE_REPLY_BYTES / unit.len() + 1));
        assert!(serde_json::to_vec(&flood).unwrap().len() > MAX_BRIDGE_REPLY_BYTES);
        assert!(matches!(
            flood.encode(MAX_BRIDGE_READ_BYTES),
            Err(BridgeError::ReplyLimit)
        ));
    }
}

#[test]
fn worst_case_payload_and_metadata_fit_exactly_and_metadata_floods_fail() {
    let mut metadata = completed(String::new());
    if let ToolOutcome::Completed { audit_ref, .. } = &mut metadata.outcome {
        audit_ref.event_id.push_str(&"\u{1}".repeat(100));
    }
    let padding = MAX_BRIDGE_METADATA_BYTES - serde_json::to_vec(&metadata).unwrap().len();
    if let ToolOutcome::Completed { audit_ref, .. } = &mut metadata.outcome {
        audit_ref.event_id.push_str(&"x".repeat(padding));
    }
    assert_eq!(
        metadata.encode(MAX_BRIDGE_READ_BYTES).unwrap().len(),
        MAX_BRIDGE_METADATA_BYTES
    );
    let mut reply = metadata.clone();
    if let ToolOutcome::Completed { result, .. } = &mut reply.outcome {
        result["output_tail"] = json!("\u{1}".repeat(MAX_BRIDGE_READ_BYTES as usize));
    }
    let wire = reply.encode(MAX_BRIDGE_READ_BYTES).unwrap();
    assert_eq!(wire.len(), MAX_BRIDGE_REPLY_BYTES);
    let decoded: PiToolReply = serde_json::from_slice(&wire).unwrap();
    assert_eq!(decoded.outcome, reply.outcome);

    if let ToolOutcome::Completed { audit_ref, .. } = &mut metadata.outcome {
        audit_ref.event_id.push('x');
    }
    assert!(serde_json::to_vec(&metadata).unwrap().len() < MAX_BRIDGE_REPLY_BYTES);
    assert!(matches!(
        metadata.encode(MAX_BRIDGE_READ_BYTES),
        Err(BridgeError::ReplyLimit)
    ));
}
