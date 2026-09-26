//! Supervisor boundary tests against a fake JSONL child.
//!
//! The fake child is a small Python script (mode selected by
//! `LUMEN_FAKE_CHILD_MODE`) so tests exercise the real subprocess,
//! byte-framing, and restart machinery — not mocks.

use crate::pi_supervisor::{PiSupervisor, PiSupervisorConfig, RestartPolicy, SupervisorEvent};
use serde_json::json;
use std::path::PathBuf;
use std::time::Duration;

const FAKE_CHILD: &str = r#"
import sys, json, os
mode = os.environ.get("LUMEN_FAKE_CHILD_MODE", "echo")

def emit(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()

def respond_to_stdin():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            cmd = json.loads(line)
        except Exception:
            continue
        emit({"type": "response", "id": cmd.get("id"),
              "command": cmd.get("type"), "success": True, "data": {}})

if mode == "echo":
    respond_to_stdin()
elif mode == "malformed_first":
    sys.stdout.write("this is not json\n")
    sys.stdout.flush()
    respond_to_stdin()
elif mode == "flood":
    sys.stdout.write("x" * (4 * 1024 * 1024) + "\n")
    sys.stdout.flush()
elif mode == "die":
    sys.exit(3)
elif mode == "settled":
    emit({"type": "agent_settled"})
    for _ in sys.stdin:
        pass
elif mode == "unicode":
    # Raw U+2028 (via escape) inside a JSON string value: the supervisor must
    # NOT treat it as a record boundary.
    emit({"type": "response", "id": "u1", "command": "get_state",
          "success": True, "data": {"t": "a b"}})
    for _ in sys.stdin:
        pass
"#;

fn config_with_mode(mode: &str) -> (PiSupervisorConfig, PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let script = dir.path().join("fake_child.py");
    std::fs::write(&script, FAKE_CHILD).expect("write fake child");
    let base = PiSupervisorConfig::default();
    let mut args = vec![script.to_string_lossy().to_string()];
    args.extend(base.args.clone());
    let mut env = base.env.clone();
    env.push(("LUMEN_FAKE_CHILD_MODE".to_string(), mode.to_string()));
    let config = PiSupervisorConfig {
        pi_binary: PathBuf::from("/usr/bin/python3"),
        args,
        env,
        restart: RestartPolicy {
            max_restarts: 1,
            base_backoff: Duration::from_millis(10),
        },
        ..base
    };
    (config, script, dir)
}

async fn next_non_response(sup: &mut PiSupervisor) -> SupervisorEvent {
    loop {
        match sup
            .next_event()
            .await
            .expect("supervisor must produce an event")
        {
            SupervisorEvent::Response(_) => continue,
            other => return other,
        }
    }
}

#[tokio::test]
async fn prompt_round_trip_correlates_by_id() {
    let (config, _script, _dir) = config_with_mode("echo");
    let mut sup = PiSupervisor::spawn_fixture(config).await.expect("spawn");
    let response = sup
        .prompt(json!({"text": "hello"}), Duration::from_secs(5))
        .await
        .expect("round trip");
    assert!(response.success);
    assert_eq!(response.command, "prompt");
    assert!(response.id.is_some());
    sup.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn malformed_line_is_reported_and_stream_recovers() {
    let (config, _script, _dir) = config_with_mode("malformed_first");
    let mut sup = PiSupervisor::spawn_fixture(config).await.expect("spawn");
    let event = next_non_response(&mut sup).await;
    assert!(
        matches!(event, SupervisorEvent::MalformedLine { .. }),
        "expected MalformedLine, got {event:?}"
    );
    // The stream still works afterwards.
    let response = sup
        .prompt(json!({"text": "after garbage"}), Duration::from_secs(5))
        .await
        .expect("round trip after malformed line");
    assert!(response.success);
    sup.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn output_flood_kills_child_and_restarts_observably() {
    let (mut config, _script, _dir) = config_with_mode("flood");
    config.max_line_bytes = 1024;
    let mut sup = PiSupervisor::spawn_fixture(config).await.expect("spawn");
    let event = sup.next_event().await.expect("event");
    assert!(
        matches!(event, SupervisorEvent::LineTooLong { .. }),
        "expected LineTooLong, got {event:?}"
    );
    // The restart verdict is queued as the next event so both are observable.
    let verdict = sup.next_event().await.expect("verdict");
    assert!(
        matches!(verdict, SupervisorEvent::Restarting { attempt: 1, .. }),
        "expected Restarting, got {verdict:?}"
    );
    sup.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn restart_policy_is_bounded() {
    let (mut config, _script, _dir) = config_with_mode("die");
    config.restart = RestartPolicy {
        max_restarts: 0,
        base_backoff: Duration::from_millis(10),
    };
    let mut sup = PiSupervisor::spawn_fixture(config).await.expect("spawn");
    // The child exits immediately; with max_restarts=0 there is no restart.
    let mut saw_exit = false;
    for _ in 0..10 {
        match sup.next_event().await {
            Some(SupervisorEvent::Exited {
                restarted: false, ..
            }) => {
                saw_exit = true;
                break;
            }
            Some(SupervisorEvent::Restarting { .. }) => {
                panic!("must not restart when max_restarts=0")
            }
            Some(_) => continue,
            None => break,
        }
    }
    assert!(saw_exit, "expected bounded Exited event");
}

#[tokio::test]
async fn agent_settled_is_observed() {
    let (config, _script, _dir) = config_with_mode("settled");
    let mut sup = PiSupervisor::spawn_fixture(config).await.expect("spawn");
    sup.wait_settled(Duration::from_secs(5))
        .await
        .expect("agent_settled must arrive");
    sup.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn unicode_line_separator_is_not_a_record_boundary() {
    // The fake child emits one JSON record containing a raw U+2028 inside a
    // string. The supervisor must deliver exactly one Response, proving it
    // splits on LF only.
    let (config, _script, _dir) = config_with_mode("unicode");
    let mut sup = PiSupervisor::spawn_fixture(config).await.expect("spawn");
    let event = tokio::time::timeout(Duration::from_secs(5), sup.next_event())
        .await
        .expect("event in time")
        .expect("event");
    match event {
        SupervisorEvent::Response(response) => {
            assert_eq!(response.id.as_deref(), Some("u1"));
            let text = response
                .data
                .as_ref()
                .and_then(|d| d.get("t"))
                .and_then(|t| t.as_str())
                .unwrap_or("");
            assert!(
                text.contains('\u{2028}'),
                "U+2028 must survive intact, got {text:?}"
            );
        }
        other => panic!("expected a single Response, got {other:?}"),
    }
    sup.shutdown().await.expect("shutdown");
}
