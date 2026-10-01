//! Live v2 authority must never discard wire content before digest review.
use lumen_core::pi_boundary::{
    ActionEnvelope, KernelWireRequest, KernelWireResponse, canonical_digest,
};
use proptest::prelude::*;
use serde_json::{Value, json};

fn fixture() -> Value {
    let mut value: Value =
        serde_json::from_str(include_str!("fixtures/action_envelope.v2.json")).unwrap();
    value.as_object_mut().unwrap().remove("_digest");
    value
}
fn with_arguments(raw: &str) -> String {
    let mut value = fixture();
    value["arguments"] = json!("ARGUMENT_PLACEHOLDER");
    serde_json::to_string(&value)
        .unwrap()
        .replace("\"ARGUMENT_PLACEHOLDER\"", raw)
}

#[test]
fn unknown_fields_are_rejected_at_every_authority_object() {
    let mut value = fixture();
    value["resources"]["network"] = json!([{"scheme":"https","host":"example.com","port":443}]);
    value["resources"]["secrets"] = json!([{"id":"vault:fixture","purpose":"fixture"}]);
    serde_json::from_value::<ActionEnvelope>(value.clone()).unwrap();
    for pointer in [
        "",
        "/tool",
        "/inputs/0",
        "/resources",
        "/resources/paths/0",
        "/resources/network/0",
        "/resources/secrets/0",
        "/expected_effects",
    ] {
        let mut changed = value.clone();
        changed
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("future_authority".into(), json!(true));
        assert!(
            serde_json::from_value::<ActionEnvelope>(changed).is_err(),
            "accepted {pointer}"
        );
    }
}

#[test]
fn raw_argument_duplicates_and_non_integer_numbers_are_rejected() {
    for raw in [
        r#"{"path":"a","path":"b"}"#,
        r#"{"path":"a","p\u0061th":"b"}"#,
        r#"{"nested":{"budget":1,"budget":999}}"#,
        r#"{"nested":[{"budget":1,"budget":999}]}"#,
        r#"{"budget":1.0}"#,
        r#"{"budget":1e0}"#,
        r#"{"budget":18446744073709551616}"#,
        r#"{"budget":-9223372036854775809}"#,
        "[]",
        "null",
    ] {
        assert!(
            serde_json::from_str::<ActionEnvelope>(&with_arguments(raw)).is_err(),
            "accepted {raw}"
        );
    }
    let valid = with_arguments(
        r#"{"minimum":-9223372036854775808,"maximum":18446744073709551615,"nested":[null,true,"value"]}"#,
    );
    let action: ActionEnvelope = serde_json::from_str(&valid).unwrap();
    assert_eq!(action.arguments["maximum"].as_u64(), Some(u64::MAX));
    assert_eq!(action.arguments["minimum"].as_i64(), Some(i64::MIN));
}

#[test]
fn old_versions_invalid_hashes_and_floating_tool_pins_are_rejected() {
    for version in [0, 1, 3, u32::MAX] {
        let mut value = fixture();
        value["version"] = json!(version);
        assert!(serde_json::from_value::<ActionEnvelope>(value).is_err());
    }
    for hash in [
        String::new(),
        "f".repeat(63),
        "A".repeat(64),
        format!("sha256:{}", "a".repeat(64)),
    ] {
        let mut value = fixture();
        value["inputs"][0]["content_hash"] = json!(hash);
        assert!(serde_json::from_value::<ActionEnvelope>(value).is_err());
    }
    for pin in ["*", "latest", "^1.0.0", "1"] {
        let mut value = fixture();
        value["tool"]["version"] = json!(pin);
        assert!(serde_json::from_value::<ActionEnvelope>(value).is_err());
    }
}

#[test]
fn transport_protocol_and_fields_are_strict() {
    let request: Value =
        serde_json::from_str(include_str!("fixtures/kernel_wire_request.v2.json")).unwrap();
    let response: Value =
        serde_json::from_str(include_str!("fixtures/kernel_wire_response.v2.json")).unwrap();
    for protocol in ["lumen-kernel/1", "lumen-kernel/3", ""] {
        let mut req = request.clone();
        req["protocol"] = json!(protocol);
        let mut res = response.clone();
        res["protocol"] = json!(protocol);
        assert!(serde_json::from_value::<KernelWireRequest>(req).is_err());
        assert!(serde_json::from_value::<KernelWireResponse>(res).is_err());
    }
    let mut req = request;
    req["ambient_lease"] = json!("forbidden");
    let mut res = response;
    res["extra_authority"] = json!(true);
    assert!(serde_json::from_value::<KernelWireRequest>(req).is_err());
    assert!(serde_json::from_value::<KernelWireResponse>(res).is_err());
}

#[test]
fn policy_versions_unknown_obligations_and_ambiguous_responses_fail_closed() {
    use lumen_core::pi_boundary::PolicyDecision;
    let allow: Value =
        serde_json::from_str(include_str!("fixtures/policy_decision_allow.v3.json")).unwrap();
    let deny: Value =
        serde_json::from_str(include_str!("fixtures/policy_decision_deny.v3.json")).unwrap();
    for version in [0, 1, 2, 4, u32::MAX] {
        let mut value = allow.clone();
        value["version"] = json!(version);
        assert!(serde_json::from_value::<PolicyDecision>(value).is_err());
    }
    for (mut value, pointer) in [
        (allow.clone(), ""),
        (allow, "/obligations/0"),
        (deny, "/reason"),
    ] {
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("future_authority".into(), json!(true));
        assert!(serde_json::from_value::<PolicyDecision>(value).is_err());
    }
    for raw in [
        r#"{"version":3,"decision":"allow","obligations":[{"type":"truncate_output","max_bytes":1,"max_bytes":100}]}"#,
        r#"{"version":3,"decision":"allow","decision":"deny","obligations":[]}"#,
        r#"{"version":3,"decision":"allow","decision":"allow","obligations":[]}"#,
        r#"{"version":3,"version":3,"decision":"allow","obligations":[]}"#,
    ] {
        assert!(serde_json::from_str::<PolicyDecision>(raw).is_err());
    }
    let response: Value =
        serde_json::from_str(include_str!("fixtures/kernel_wire_response.v2.json")).unwrap();
    for field in ["decision", "audit_sequence", "action_digest"] {
        let mut value = response.clone();
        value.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<KernelWireResponse>(value).is_err());
    }
    let mut mixed = response;
    mixed["error"] = json!({"code":"denied","detail":"fixture"});
    assert!(serde_json::from_value::<KernelWireResponse>(mixed).is_err());
}

proptest! {
    #[test]
    fn generated_duplicate_keys_cannot_collapse_to_an_approved_value(key in "[a-z]{1,20}", a in any::<u64>(), b in any::<u64>()) {
        let key=serde_json::to_string(&key).unwrap();
        let raw=format!("{{{key}:{a},{key}:{b}}}");
        prop_assert!(serde_json::from_str::<ActionEnvelope>(&with_arguments(&raw)).is_err());
    }
}

#[test]
fn valid_legacy_approval_cannot_mint_v2_authority_or_burn_its_nonce() {
    use lumen_core::{
        budget::BudgetLedger,
        canonical::PathResolver,
        lease::{CanonicalAction, KernelKeys, OneShotGrant, SessionRegistry, mint_one_shot_lease},
        nonce::NonceStore,
    };
    struct Identity;
    impl PathResolver for Identity {
        fn resolve(&self, p: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
            Ok(p.to_owned())
        }
    }
    let value = fixture();
    let envelope: ActionEnvelope = serde_json::from_value(value.clone()).unwrap();
    let action = CanonicalAction::from_envelope(&envelope, &Identity, false).unwrap();
    // Identical content, only the authority version differs.
    let mut legacy = value;
    legacy["version"] = json!(1);
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let keys = KernelKeys::generate();
    let ledger = BudgetLedger::new();
    let nonces = NonceStore::new();
    let mut sessions = SessionRegistry::new();
    sessions.register(envelope.session_id.clone(), None, key.verifying_key(), 0);
    let mut grant = OneShotGrant {
        approval_id: "old-approval".into(),
        action_digest: canonical_digest(&legacy).unwrap(),
        session_subject: envelope.session_id,
        signer_key_id: "fixture-human".into(),
        nonce: "binding-nonce".into(),
        created_at_ms: 1,
        expires_at_ms: 1000,
        signature: String::new(),
    };
    grant.sign(&key);
    grant.verify(&key.verifying_key()).unwrap();
    assert!(
        mint_one_shot_lease(
            &grant,
            &key.verifying_key(),
            &action,
            &keys,
            &sessions,
            &ledger,
            &nonces,
            10
        )
        .is_err()
    );
    // A separately signed new decision can mint once. The failed binding
    // must not have consumed this nonce or changed the budget ledger.
    grant.action_digest = action.digest.clone();
    grant.sign(&key);
    let lease = mint_one_shot_lease(
        &grant,
        &key.verifying_key(),
        &action,
        &keys,
        &sessions,
        &ledger,
        &nonces,
        10,
    )
    .unwrap();
    assert_eq!(
        lease.approved_action_digest.as_deref(),
        Some(action.digest.as_str())
    );
    assert!(
        mint_one_shot_lease(
            &grant,
            &key.verifying_key(),
            &action,
            &keys,
            &sessions,
            &ledger,
            &nonces,
            10
        )
        .is_err()
    );
}

#[tokio::test]
async fn raw_socket_rejections_are_audited_without_reflecting_untrusted_content() {
    use lumen_core::pi_boundary::{
        AuditEventKind, KernelListener, LocalKernel, LocalKernelConfig, PeerPolicy,
    };
    use std::{sync::Arc, time::Duration};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let path = std::path::PathBuf::from(format!("/tmp/lumen-action-{}.sock", uuid::Uuid::new_v4()));
    let kernel = Arc::new(LocalKernel::new(LocalKernelConfig::default()));
    let listener = KernelListener::bind(kernel.clone(), path.clone(), PeerPolicy::current_user())
        .await
        .unwrap();
    let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    let mut raw: Value =
        serde_json::from_str(include_str!("fixtures/kernel_wire_request.v2.json")).unwrap();
    raw["credential"] = json!(listener.endpoint().nonce);
    let marker = "SECRET_SENTINEL_NOT_A_REAL_SECRET";
    raw["envelope"]["tool"][marker] = json!(marker);
    writer
        .write_all(format!("{raw}\n").as_bytes())
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!response.contains(marker));
    let response: KernelWireResponse = serde_json::from_str(&response).unwrap();
    assert_eq!(response.error.unwrap().code, "malformed_request");
    assert!(response.decision.is_none());
    let events = kernel.audit_log().events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, AuditEventKind::TransportRejected);
    assert!(!serde_json::to_string(&events).unwrap().contains(marker));
    kernel.audit_log().verify().unwrap();
    drop(writer);
    drop(lines);
    listener.shutdown().await.unwrap();
    assert!(!path.exists());
}
