//! The host must reject ambiguous JSON before converting it to kernel types.
use lumen_server::{
    ACTION_ENVELOPE_VERSION, ActionEnvelope, LeaseDocument, POLICY_DECISION_VERSION, PolicyDecision,
};
use serde_json::{Value, json};

#[test]
fn host_fixture_is_bound_and_transport_namespaces_cannot_be_confused() {
    use lumen_core::pi_boundary::KernelWireRequest;
    use lumen_server::ChannelRequest;
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/host_action.v2.json")).unwrap();
    let request: ChannelRequest = serde_json::from_value(fixture["request"].clone()).unwrap();
    let policy: PolicyDecision = serde_json::from_value(fixture["host_policy"].clone()).unwrap();
    policy.bind(&request.envelope).unwrap();
    assert_eq!(
        request.envelope.digest().unwrap(),
        fixture["host_action_digest"]
    );
    assert!(serde_json::from_value::<KernelWireRequest>(fixture["request"].clone()).is_err());
    let core: Value = serde_json::from_str(include_str!(
        "../../lumen-core/tests/fixtures/kernel_wire_request.v2.json"
    ))
    .unwrap();
    assert!(serde_json::from_value::<ChannelRequest>(core).is_err());
}

fn action() -> Value {
    json!({"protocol_version":ACTION_ENVELOPE_VERSION,"action_id":"11111111-1111-4111-8111-111111111111",
        "session_id":"fixture-session","tool":{"name":"bct.fs.read","version":"1.0.0"},
        "arguments":{"path":"/workspace/file"},"input_hashes":[],
        "resources":{"paths":["/workspace/file"],"hosts":[],"secret_refs":[]},"lease_chain":[],
        "nonce":"fixture-nonce","expires_at":"2099-01-01T00:00:00Z","expected_effects":["read"]})
}

#[test]
fn host_actions_reject_duplicate_arguments_and_legacy_versions() {
    serde_json::from_value::<ActionEnvelope>(action())
        .unwrap()
        .validate()
        .unwrap();
    for version in [0, 1, 3, u32::MAX] {
        let mut value = action();
        value["protocol_version"] = json!(version);
        assert!(serde_json::from_value::<ActionEnvelope>(value).is_err());
    }
    let mut value = action();
    value["arguments"] = json!("MARKER");
    for raw in [
        r#"{"path":"a","path":"b"}"#,
        r#"{"nested":[{"cap":1,"cap":100}]}"#,
        r#"{"n":1.0}"#,
        "[]",
        "null",
    ] {
        let wire = value.to_string().replace("\"MARKER\"", raw);
        assert!(serde_json::from_str::<ActionEnvelope>(&wire).is_err());
    }
}

#[test]
fn host_lease_values_do_not_erase_duplicate_scope_or_budget_keys() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../lumen-core/tests/fixtures/lease.v3.json"
    ))
    .unwrap();
    let value = &fixture["document"];
    serde_json::from_value::<LeaseDocument>(value.clone()).unwrap();
    for pointer in ["/scope", "/limits/budget"] {
        let mut modified = value.clone();
        *modified.pointer_mut(pointer).unwrap() = json!("MARKER");
        let wire = modified
            .to_string()
            .replace("\"MARKER\"", r#"{"tokens":1,"tokens":100}"#);
        assert!(serde_json::from_str::<LeaseDocument>(&wire).is_err());
    }
    let mut legacy = value.clone();
    legacy["protocol_version"] = json!(2);
    assert!(serde_json::from_value::<LeaseDocument>(legacy).is_err());
}

#[test]
fn host_policy_rejects_unknown_fields_and_old_versions() {
    let value = json!({"protocol_version":POLICY_DECISION_VERSION,"action_digest":"a".repeat(64),
        "decided_at":"2026-01-01T00:00:00Z","decision":{"kind":"allow","lease_id":"fixture-lease",
        "obligations":[{"kind":"require_sandbox","params":{"profile":"strict"}}]}});
    serde_json::from_value::<PolicyDecision>(value.clone()).unwrap();
    for pointer in ["", "/decision", "/decision/obligations/0"] {
        let mut changed = value.clone();
        changed
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("future_authority".into(), json!(true));
        assert!(serde_json::from_value::<PolicyDecision>(changed).is_err());
    }
    for version in [0, 1, 2, 4, u32::MAX] {
        let mut changed = value.clone();
        changed["protocol_version"] = json!(version);
        assert!(serde_json::from_value::<PolicyDecision>(changed).is_err());
    }
}
