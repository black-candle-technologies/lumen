//! Fixture tests for the `lumen-protocol` facade: every frozen Phase-0
//! contract fixture under `fixtures/` must deserialize through the
//! re-exported types. This proves the facade exposes exactly the frozen
//! contract shapes (a fork would fail to parse the fixtures).

use lumen_protocol::{
    ActionEnvelope, AuditEvent, BridgeCancellation, BridgeEvent, BridgeToolRequest,
    KernelWireRequest, KernelWireResponse, PolicyDecision, SandboxProfile, SandboxSpec,
};
use serde_json::Value;
use std::fs;

fn fixture(name: &str) -> Value {
    let path = format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let bytes = fs::read(&path).unwrap_or_else(|_| panic!("missing fixture {path}"));
    serde_json::from_slice(&bytes).expect("fixture must be valid JSON")
}

#[test]
fn facade_action_envelope_fixture() {
    let mut value = fixture("action_envelope.v1.json");
    let recorded = value
        .get("_digest")
        .and_then(Value::as_str)
        .expect("fixture records its digest")
        .to_string();
    value.as_object_mut().unwrap().remove("_digest");
    let envelope: ActionEnvelope = serde_json::from_value(value).unwrap();
    envelope.validate().expect("fixture envelope validates");
    assert_eq!(envelope.digest().expect("digest"), recorded);
}

#[test]
fn facade_policy_decision_fixtures() {
    for (name, expected) in [
        ("policy_decision_allow.v1.json", "allow"),
        ("policy_decision_deny.v1.json", "deny"),
        ("policy_decision_pending.v1.json", "pending"),
    ] {
        let value = fixture(name);
        let decision: PolicyDecision = serde_json::from_value(value.clone())
            .unwrap_or_else(|e| panic!("fixture {name} must parse via facade: {e}"));
        assert_eq!(decision.summary(), expected);
        // Exact-shape check: deserialization ignores unknown fields, so
        // re-serializing and comparing against the fixture proves the
        // documented frozen shape — obligations and denial details included.
        let round_tripped = serde_json::to_value(&decision).expect("decision serializes");
        assert_eq!(
            round_tripped, value,
            "fixture {name} must round-trip exactly (frozen shape)"
        );
    }
}

#[test]
fn facade_pibridge_fixtures() {
    let request: BridgeToolRequest =
        serde_json::from_value(fixture("pibridge_tool_request.v1.json")).unwrap();
    assert_eq!(request.tool_name, "bct.read_file");

    let settled: BridgeEvent =
        serde_json::from_value(fixture("pibridge_agent_settled.v1.json")).unwrap();
    assert!(matches!(settled, BridgeEvent::AgentSettled { .. }));

    let _: BridgeCancellation =
        serde_json::from_value(fixture("pibridge_cancellation.v1.json")).unwrap();
}

#[test]
fn facade_audit_event_fixture() {
    let event: AuditEvent = serde_json::from_value(fixture("audit_event.v1.json")).unwrap();
    let recomputed = event.compute_hash(&event.prev_hash).expect("hash");
    assert_eq!(recomputed, event.hash, "audit chain link is valid");
}

#[test]
fn facade_sandbox_driver_fixture() {
    let spec: SandboxSpec = serde_json::from_value(fixture("sandbox_driver_spec.v1.json")).unwrap();
    assert_eq!(spec.profile, SandboxProfile::Strict);
    assert!(spec.egress_allowlist.is_empty(), "default-deny egress");
}

#[test]
fn facade_kernel_wire_fixtures() {
    let request: KernelWireRequest =
        serde_json::from_value(fixture("kernel_wire_request.v1.json")).unwrap();
    request
        .envelope
        .validate()
        .expect("wire envelope validates");

    let response: KernelWireResponse =
        serde_json::from_value(fixture("kernel_wire_response.v1.json")).unwrap();
    assert!(response.error.is_none());
    assert!(response.decision.expect("decision").is_allow());
    // The response must bind to the request it answers: an allow for a
    // different action must never satisfy this fixture contract.
    assert_eq!(
        response.action_digest.as_deref(),
        Some(request.envelope.digest().expect("request digest").as_str()),
        "wire response must carry the requesting envelope's action digest"
    );
}
