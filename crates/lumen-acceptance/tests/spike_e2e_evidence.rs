//! Phase-0 spike end-to-end evidence.
//!
//! On 2026-09-24 a real pinned Pi session (commit
//! `b45597504eeaba1f11a9920a1d1048c361ed4b8e`, v0.87.1) drove the real
//! `bct.read_file` tool through the real kernel wire (Unix socket,
//! `SO_PEERCRED` + per-session nonce) for three marked prompts. The run's
//! transcript and the kernel's hash-chained audit log are frozen in
//! `crates/lumen-core/tests/fixtures/spike-e2e-evidence.json`.
//!
//! This test re-verifies that frozen evidence: allow returned the file,
//! deny refused with the kernel's reason and exposed nothing, pending
//! requested human approval and executed nothing. It does not re-run Pi;
//! the harness that produced the run (scripted deterministic model,
//! example kernel, node driver) was scaffolding and is not committed.

use serde_json::Value;
use std::fs;

fn evidence() -> Value {
    let path = format!(
        "{}/../lumen-core/tests/fixtures/spike-e2e-evidence.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = fs::read(&path).unwrap_or_else(|_| panic!("missing fixture {path}"));
    serde_json::from_slice(&bytes).expect("evidence must be valid JSON")
}

fn tool_text(evidence: &Value, marker: &str) -> (bool, String) {
    let events = evidence["cases"][marker]
        .as_array()
        .unwrap_or_else(|| panic!("missing case {marker}"));
    assert_eq!(
        events.len(),
        1,
        "case {marker} must have exactly one tool event"
    );
    let event = &events[0];
    assert_eq!(
        event["toolName"].as_str(),
        Some("bct.read_file"),
        "case {marker} must be the mediated tool"
    );
    let is_error = event["isError"].as_bool().unwrap_or(false);
    let text = event["result"]["content"]
        .as_array()
        .and_then(|c| c.iter().find_map(|b| b["text"].as_str()))
        .unwrap_or("")
        .to_string();
    (is_error, text)
}

#[test]
fn spike_e2e_allow_returned_file_content() {
    let ev = evidence();
    assert_eq!(
        ev["expected"]["allowed_content"].as_str(),
        Some("LUMEN-SPIKE-EXPECTED-CONTENT\n")
    );
    let (is_error, text) = tool_text(&ev, "SPIKE_ALLOW");
    assert!(!is_error, "allow must not be an error");
    assert_eq!(text, "LUMEN-SPIKE-EXPECTED-CONTENT\n");
}

#[test]
fn spike_e2e_deny_exposed_nothing() {
    let ev = evidence();
    let (is_error, text) = tool_text(&ev, "SPIKE_DENY");
    assert!(is_error, "deny must surface as a tool error");
    assert!(
        text.contains("scope_exceeded"),
        "deny must carry the kernel reason code, got: {text}"
    );
    assert!(
        !text.contains("root:"),
        "deny must not leak file content, got: {text}"
    );
}

#[test]
fn spike_e2e_pending_executed_nothing() {
    let ev = evidence();
    let (is_error, text) = tool_text(&ev, "SPIKE_PENDING");
    assert!(
        is_error,
        "pending must surface as a tool error (no execution)"
    );
    assert!(
        text.contains("requires human approval"),
        "pending must name the approval gate, got: {text}"
    );
    assert!(
        text.contains("apr-"),
        "pending must carry the approval id, got: {text}"
    );
    assert!(
        !text.contains("needs a human"),
        "pending must NOT return the file content, got: {text}"
    );
}

#[test]
fn spike_e2e_audit_pairs_every_verdict() {
    let ev = evidence();
    let audit = ev["audit"]
        .as_array()
        .expect("evidence must carry the kernel audit log");
    assert_eq!(audit.len(), 6, "three actions, each proposed then decided");
    let kinds: Vec<&str> = audit
        .iter()
        .map(|a| a["kind"].as_str().unwrap_or("?"))
        .collect();
    assert_eq!(
        kinds,
        [
            "action_proposed",
            "policy_allowed",
            "action_proposed",
            "policy_denied",
            "action_proposed",
            "approval_requested",
        ],
        "audit must pair each proposal with its verdict in run order"
    );
    // The hash chain must link: every event commits to its predecessor.
    let mut prev = "0000000000000000000000000000000000000000000000000000000000000000";
    for a in audit {
        assert_eq!(
            a["prev_hash"].as_str(),
            Some(prev),
            "audit chain link broken at {}",
            a["event_id"].as_str().unwrap_or("?")
        );
        prev = a["hash"].as_str().expect("audit event must carry its hash");
    }
}

#[test]
fn spike_e2e_pinned_pi_provenance() {
    let ev = evidence();
    assert_eq!(
        ev["pi"]["commit"].as_str(),
        Some("b45597504eeaba1f11a9920a1d1048c361ed4b8e")
    );
    assert_eq!(ev["pi"]["version"].as_str(), Some("0.87.1"));
    assert_eq!(
        ev["pi"]["artifact_sha256"].as_str(),
        Some("e79626f2dd6f94aa45d30f3fa63cd84319a6eefcd150b353cfaf274366926774")
    );
}
