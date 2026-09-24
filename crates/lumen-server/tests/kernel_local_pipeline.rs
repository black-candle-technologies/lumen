//! Seam A proof: [`ToolPipeline`] drives the REAL Phase-1 kernel.
//!
//! This test wires `ToolPipeline` with [`LocalKernelClient`] (backed by a
//! real [`lumen_core::pi_boundary::LocalKernel`]) and a mock sandbox. It
//! proves the pipeline calls the real decision/lease/audit functions:
//!
//! - allow iff a real kernel lease covers the action;
//! - deny with no lease, deny for out-of-scope paths, deny after
//!   `revoke_session` (real `revoke_lease` in the kernel registry);
//! - the kernel's hash-chained audit log verifies and contains both the
//!   kernel's own decision events and the host's staged/committed events;
//! - the sandbox still stages before audit and commits after (ordering
//!   preserved with the real kernel in the loop).

use std::sync::Arc;

use lumen_core::pi_boundary::{LocalKernel, LocalKernelConfig};
use lumen_server::{
    Catalog, CatalogError, EffectClass, KernelClient, LocalKernelClient, MockSandboxRunner,
    PiToolRequest, ProjectionKind, ToolDef, ToolOutcome, ToolPipeline, now_ms,
};

fn read_file_catalog() -> Result<Catalog, CatalogError> {
    let mut catalog = Catalog::new();
    catalog.register(ToolDef {
        name: "bct.read_file".to_string(),
        version: "1.0.0".to_string(),
        description: "Phase-0 canonical read (test double for the real kernel policy).".to_string(),
        parameters_schema: serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["path"],
            "properties": {
                "path": {"type": "string", "minLength": 1, "maxLength": 4096}
            }
        }),
        effects: vec![EffectClass::Read],
        projection: ProjectionKind::FsRead,
    })?;
    Ok(catalog)
}

fn read_request(path: &str) -> PiToolRequest {
    PiToolRequest {
        id: "call-1".to_string(),
        tool: "bct.read_file".to_string(),
        arguments: serde_json::json!({ "path": path }),
    }
}

struct Fixture {
    pipeline: ToolPipeline<LocalKernelClient, MockSandboxRunner>,
    kernel: Arc<LocalKernelClient>,
    sandbox: Arc<MockSandboxRunner>,
}

fn fixture() -> Fixture {
    let kernel = Arc::new(LocalKernelClient::new(Arc::new(LocalKernel::new(
        LocalKernelConfig::default(),
    ))));
    let sandbox = Arc::new(MockSandboxRunner::new());
    let pipeline = ToolPipeline::new(
        Arc::new(read_file_catalog().unwrap()),
        kernel.clone(),
        sandbox.clone(),
    );
    Fixture {
        pipeline,
        kernel,
        sandbox,
    }
}

#[tokio::test]
async fn pipeline_allows_with_real_lease_and_audits() {
    let f = fixture();
    let subject = "sess-pipe-1";
    let lease = f
        .kernel
        .issue_session_lease(
            subject,
            vec!["/leased".into()],
            vec!["read".into()],
            now_ms() + 3_600_000,
        )
        .expect("issue real lease");

    let outcome = f
        .pipeline
        .handle(
            &read_request("/leased/a.txt"),
            subject,
            &[lease.to_string()],
        )
        .await;
    let audit_ref = match outcome {
        ToolOutcome::Completed { audit_ref, .. } => audit_ref,
        other => panic!("expected Completed from real kernel allow, got {other:?}"),
    };

    // The full pipeline ran against the real kernel: staged, audit-before-
    // commit, committed.
    assert_eq!(f.sandbox.staged_count(), 1);
    assert_eq!(f.sandbox.committed_count(), 1);

    // The completion audit ref points into the REAL kernel audit chain.
    let log = f.kernel.audit_log();
    log.verify().expect("kernel audit chain must verify");
    let stored: Vec<_> = log
        .events()
        .into_iter()
        .filter(|e| e.session_id == subject)
        .collect();
    assert!(
        stored.iter().any(|e| e.kind.as_str() == "policy_allowed"),
        "kernel's own allow event must be present"
    );
    assert!(
        stored
            .iter()
            .any(|e| e.detail.contains("host_kind=tool_staged")),
        "host staged event must be in the kernel chain"
    );
    assert!(
        stored
            .iter()
            .any(|e| e.detail.contains("host_kind=tool_committed")),
        "host committed event must be in the kernel chain"
    );
    assert!(
        stored
            .iter()
            .any(|e| e.event_id.to_string() == audit_ref.event_id),
        "returned audit ref must resolve in the kernel log"
    );
}

#[tokio::test]
async fn pipeline_denies_without_lease_and_after_revoke() {
    let f = fixture();
    let subject = "sess-pipe-2";

    // No lease chain: the real kernel denies (no default allow).
    let outcome = f
        .pipeline
        .handle(&read_request("/leased/a.txt"), subject, &[])
        .await;
    assert!(
        matches!(outcome, ToolOutcome::Denied { .. }),
        "expected Denied, got {outcome:?}"
    );
    assert_eq!(f.sandbox.staged_count(), 0, "denied actions never stage");

    // Real lease: allow.
    let lease = f
        .kernel
        .issue_session_lease(
            subject,
            vec!["/leased".into()],
            vec!["read".into()],
            now_ms() + 3_600_000,
        )
        .expect("issue real lease");
    let outcome = f
        .pipeline
        .handle(
            &read_request("/leased/a.txt"),
            subject,
            &[lease.to_string()],
        )
        .await;
    assert!(
        matches!(outcome, ToolOutcome::Completed { .. }),
        "expected Completed, got {outcome:?}"
    );

    // Revoke the session's leases kernel-side: the same action now denies.
    f.kernel.revoke_session(subject).await.expect("revoke");
    let outcome = f
        .pipeline
        .handle(
            &read_request("/leased/a.txt"),
            subject,
            &[lease.to_string()],
        )
        .await;
    let denied_revoked = matches!(
        &outcome,
        ToolOutcome::Denied { reason } if reason.contains("revoked")
    );
    assert!(denied_revoked, "expected revoked Denied, got {outcome:?}");
    f.kernel.audit_log().verify().expect("chain must verify");
}

#[tokio::test]
async fn pipeline_denies_out_of_scope_path() {
    let f = fixture();
    let subject = "sess-pipe-3";
    let lease = f
        .kernel
        .issue_session_lease(
            subject,
            vec!["/leased".into()],
            vec!["read".into()],
            now_ms() + 3_600_000,
        )
        .expect("issue real lease");
    let outcome = f
        .pipeline
        .handle(
            &read_request("/elsewhere/a.txt"),
            subject,
            &[lease.to_string()],
        )
        .await;
    assert!(
        matches!(outcome, ToolOutcome::Denied { .. }),
        "expected Denied for out-of-scope path, got {outcome:?}"
    );
    assert_eq!(f.sandbox.staged_count(), 0);
}
