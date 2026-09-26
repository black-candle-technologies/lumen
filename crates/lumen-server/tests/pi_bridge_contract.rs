use lumen_server::pi_tool_bridge::{MAX_BRIDGE_REQUEST_BYTES, PiReadRequest};
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
