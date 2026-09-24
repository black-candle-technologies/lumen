//! Seam D proof: the phase-4 Courier-VHL backend constructs the payloads,
//! the phase-5 Courier adapter carries them, and the adapter verifies
//! received carriages against the backend — with no transport changes.
//!
//! - [`VhlCourierMessage`] (built by `lumen_core::vhl`) round-trips through
//!   the adapter's [`encode_vhl_message`] / [`decode_vhl_message`] byte for
//!   byte; foreign bodies and type-tampered envelopes decode to `None`.
//! - [`VhlCourierCarriage::from_vhl_request`] builds the thin carriage from
//!   the real backend request; [`VhlCourierCarriage::verify_against`]
//!   accepts it and rejects wrong id/digest/nonce and expired approvals.
//! - [`outbound::VhlApprovalCarriage::from_vhl_request`] builds the outbound
//!   approval reference from the same real request.

use std::collections::BTreeMap;

use lumen_core::{
    canonical::RealFsResolver,
    lease::CanonicalAction,
    pi_boundary::{
        ACTION_ENVELOPE_VERSION, ActionEnvelope, EffectClasses, InputRef, PathResource, PathRights,
        ResourceSet, ToolRef,
    },
    vhl::{ApprovalKind, VhlApprovalRequest, VhlCourierMessage},
};
use lumen_messaging::{
    adapters::courier::{VhlCourierCarriage, decode_vhl_message, encode_vhl_message},
    outbound,
};
use uuid::Uuid;

const NOW_MS: i64 = 1_780_000_000_000;

fn envelope() -> ActionEnvelope {
    ActionEnvelope {
        version: ACTION_ENVELOPE_VERSION,
        action_id: Uuid::new_v4(),
        session_id: "sess-seam-d".to_string(),
        tool: ToolRef {
            name: "bct.read_file".to_string(),
            version: "1.0.0".to_string(),
        },
        arguments: BTreeMap::from([("path".to_string(), serde_json::json!(0))]),
        inputs: vec![InputRef {
            content_hash: "a".repeat(64),
            snapshot_id: None,
        }],
        resources: ResourceSet {
            paths: vec![PathResource {
                path: "/tmp".to_string(),
                rights: PathRights::Read,
            }],
            network: vec![],
            secrets: vec![],
        },
        expected_effects: EffectClasses {
            file_read: true,
            file_write: false,
            network_egress: false,
            network_ingress: false,
            process_spawn: false,
        },
        lease_chain: vec![],
        nonce: format!("seam-d-{}", Uuid::new_v4()),
        expires_at_ms: NOW_MS + 600_000,
    }
}

fn real_request() -> VhlApprovalRequest {
    // Built the way production builds it: envelope -> canonical action ->
    // approval request.
    let env = envelope();
    let action =
        CanonicalAction::from_envelope(&env, &RealFsResolver, false).expect("valid action");
    VhlApprovalRequest::new(
        ApprovalKind::OneShot,
        &action,
        &env,
        1,
        // Relative TTL, not an absolute timestamp: the constructor adds it
        // to `now_ms` to compute expiry.
        300_000,
        NOW_MS,
    )
    .expect("request builds")
}

#[test]
fn vhl_courier_message_round_trips_through_adapter() {
    let request = real_request();
    let msg = VhlCourierMessage::ApprovalRequest {
        request: request.clone(),
    };
    assert_eq!(msg.message_type(), "lumen.vhl.approval-request.v1");

    // The phase-4 backend's canonical bytes survive the adapter carriage.
    let body = encode_vhl_message(&msg).expect("encode");
    let back = decode_vhl_message(&body).expect("decode");
    assert_eq!(back, msg);

    // The adapter's encode is byte-identical to the backend's own encode
    // wrapped in the type envelope (no transport mutation).
    let backend_bytes = msg.encode().expect("backend encode");
    let backend_value: serde_json::Value = serde_json::from_slice(&backend_bytes).unwrap();
    let body_value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        body_value["lumen_vhl_type"],
        "lumen.vhl.approval-request.v1"
    );
    assert_eq!(body_value["lumen_vhl_payload"], backend_value);

    // Foreign bodies and type-tampered envelopes do not decode.
    assert!(decode_vhl_message("hello, world").is_none());
    assert!(decode_vhl_message("{\"lumen_vhl_type\":\"x\"}").is_none());
    let mut tampered: serde_json::Value = serde_json::from_str(&body).unwrap();
    tampered["lumen_vhl_type"] = serde_json::json!("lumen.vhl.attestation.v1");
    assert!(decode_vhl_message(&tampered.to_string()).is_none());
}

#[test]
fn carriage_built_from_real_request_verifies_and_tampering_fails() {
    let request = real_request();

    let carriage = VhlCourierCarriage::from_vhl_request(&request);
    assert_eq!(carriage.approval_id, request.request_id);
    assert_eq!(carriage.action_digest, request.action_digest);
    assert_eq!(carriage.nonce, request.nonce);
    assert_eq!(carriage.expires_at_millis, request.expires_at_ms);

    // The adapter verifies the carriage against the phase-4 backend request.
    carriage
        .verify_against(&request, NOW_MS)
        .expect("fresh carriage verifies");

    // Wrong id / digest / nonce are rejected.
    let mut bad = carriage.clone();
    bad.action_digest = "0".repeat(64);
    assert!(bad.verify_against(&request, NOW_MS).is_err());
    let mut bad = carriage.clone();
    bad.nonce = "wrong".to_string();
    assert!(bad.verify_against(&request, NOW_MS).is_err());
    let mut bad = carriage.clone();
    bad.approval_id = "wrong".to_string();
    assert!(bad.verify_against(&request, NOW_MS).is_err());

    // Expired approvals are rejected.
    assert!(
        carriage
            .verify_against(&request, request.expires_at_ms)
            .is_err(),
        "approval at expiry must not verify"
    );

    // The old body codec still round-trips (transport unchanged).
    let (parsed, text) = VhlCourierCarriage::decode_body(&carriage.encode_body("please approve"));
    assert_eq!(parsed, Some(carriage));
    assert_eq!(text, "please approve");
}

#[test]
fn outbound_carriage_built_from_real_request() {
    let request = real_request();
    let carriage = outbound::VhlApprovalCarriage::from_vhl_request(&request).expect("builds");
    assert_eq!(carriage.approval_id, request.request_id);
    assert_eq!(carriage.action_digest, request.action_digest);
    assert_eq!(carriage.nonce, request.nonce);
    assert_eq!(carriage.expires_at_millis, request.expires_at_ms);
}
