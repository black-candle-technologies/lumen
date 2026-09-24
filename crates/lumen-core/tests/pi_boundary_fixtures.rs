//! Protocol fixture tests: every frozen Phase-0 contract has a checked-in
//! JSON fixture under `tests/fixtures/`. These tests prove the fixtures
//! deserialize into the v1 types, are byte-stable under canonical
//! re-serialization, and carry valid digests / chain links.

use lumen_core::pi_boundary::*;
use serde_json::Value;
use std::fs;

fn fixture(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let bytes = fs::read(&path).unwrap_or_else(|_| panic!("missing fixture {path}"));
    serde_json::from_slice(&bytes).expect("fixture must be valid JSON")
}

/// Deserialize → canonical re-serialize must be byte-stable.
fn assert_round_trip_stable<T>(name: &str, value: &Value, expected_version: u32)
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let typed: T = serde_json::from_value(value.clone())
        .unwrap_or_else(|e| panic!("fixture {name} must deserialize: {e}"));
    let reserialized = serde_json::to_value(&typed).expect("serialize");
    let first = canonical_json(value).expect("canonical");
    let second = canonical_json(&reserialized).expect("canonical");
    assert_eq!(
        first, second,
        "fixture {name} is not stable under canonical re-serialization"
    );
    let version = value
        .get("version")
        .and_then(Value::as_u64)
        .expect("fixture must carry a version");
    assert_eq!(version, expected_version as u64, "fixture {name} version");
}

#[test]
fn action_envelope_fixture() {
    let value = fixture("action_envelope.v1.json");
    // `_digest` is fixture metadata, not part of the contract: strip it for
    // the round-trip check, then verify it independently.
    let recorded = value
        .get("_digest")
        .and_then(Value::as_str)
        .expect("fixture records its digest")
        .to_string();
    let mut contract = value.clone();
    contract.as_object_mut().unwrap().remove("_digest");
    assert_round_trip_stable::<ActionEnvelope>("action_envelope.v1.json", &contract, 1);
    let envelope: ActionEnvelope = serde_json::from_value(contract).unwrap();
    envelope.validate().expect("fixture envelope validates");
    let digest = envelope.digest().expect("digest");
    assert_eq!(digest, recorded, "envelope digest matches fixture");
    assert_eq!(digest.len(), 64);
}

#[test]
fn policy_decision_fixtures() {
    for name in [
        "policy_decision_allow.v1.json",
        "policy_decision_deny.v1.json",
        "policy_decision_pending.v1.json",
    ] {
        let value = fixture(name);
        assert_round_trip_stable::<PolicyDecision>(name, &value, 1);
    }
    let allow: PolicyDecision =
        serde_json::from_value(fixture("policy_decision_allow.v1.json")).unwrap();
    assert!(allow.is_allow());
    let deny: PolicyDecision =
        serde_json::from_value(fixture("policy_decision_deny.v1.json")).unwrap();
    assert!(!deny.is_allow());
    assert_eq!(deny.summary(), "deny");
    let pending: PolicyDecision =
        serde_json::from_value(fixture("policy_decision_pending.v1.json")).unwrap();
    assert_eq!(pending.summary(), "pending");
}

#[test]
fn pibridge_fixtures() {
    let request = fixture("pibridge_tool_request.v1.json");
    assert_round_trip_stable::<BridgeToolRequest>("pibridge_tool_request.v1.json", &request, 1);
    let request: BridgeToolRequest = serde_json::from_value(request).unwrap();
    assert_eq!(request.tool_name, "bct.read_file");
    request
        .envelope
        .validate()
        .expect("embedded envelope validates");

    let settled = fixture("pibridge_agent_settled.v1.json");
    let settled: BridgeEvent = serde_json::from_value(settled).unwrap();
    assert!(matches!(settled, BridgeEvent::AgentSettled { .. }));

    let cancel = fixture("pibridge_cancellation.v1.json");
    assert_round_trip_stable::<BridgeCancellation>("pibridge_cancellation.v1.json", &cancel, 1);
}

#[test]
fn audit_event_fixture_verifies() {
    let value = fixture("audit_event.v1.json");
    assert_round_trip_stable::<AuditEvent>("audit_event.v1.json", &value, 1);
    let event: AuditEvent = serde_json::from_value(value).unwrap();
    // Recompute the chain link independently.
    let recomputed = event.compute_hash(&event.prev_hash).expect("hash");
    assert_eq!(recomputed, event.hash, "audit chain link is valid");
    assert_eq!(event.action_digest.len(), 64);
    // And the referenced action digest matches the envelope fixture.
    let envelope_digest = fixture("action_envelope.v1.json")
        .get("_digest")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();
    assert_eq!(event.action_digest, envelope_digest);
}

#[test]
fn sandbox_driver_fixture() {
    let value = fixture("sandbox_driver_spec.v1.json");
    assert_round_trip_stable::<SandboxSpec>("sandbox_driver_spec.v1.json", &value, 1);
    let spec: SandboxSpec = serde_json::from_value(value).unwrap();
    assert_eq!(spec.profile, SandboxProfile::Strict);
    assert!(spec.egress_allowlist.is_empty(), "default-deny egress");
}

#[test]
fn kernel_wire_fixtures() {
    let request = fixture("kernel_wire_request.v1.json");
    let request: KernelWireRequest = serde_json::from_value(request).unwrap();
    assert_eq!(request.protocol, KERNEL_WIRE_PROTOCOL);
    request
        .envelope
        .validate()
        .expect("wire envelope validates");

    let response = fixture("kernel_wire_response.v1.json");
    let response: KernelWireResponse = serde_json::from_value(response).unwrap();
    assert_eq!(response.protocol, KERNEL_WIRE_PROTOCOL);
    assert!(response.error.is_none());
    assert!(response.decision.expect("decision").is_allow());
}
