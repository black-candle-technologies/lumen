//! Light matrix for the lease-persistence key-custody control plane
//! (worker C scope): operator-gated rotation, kill, and purge on
//! [`AuthorityKernelClient`], plus the continuity guarantee that a root
//! lease minted before rotation still verifies afterwards (D5).
//!
//! The full cross-restart matrix (acceptance criteria §8) belongs to
//! worker D; these tests pin the operator gating and the retired-
//! generation verification path.

use std::sync::Arc;

use lumen_core::budget::{Budget, BudgetDimension};
use lumen_core::canonical::ResourceScope;
use lumen_core::identity::PrincipalId;
use lumen_core::lease::{LeaseLimits, RootLeaseParams};
use lumen_core::operator::{AuthorityFuture, AuthorityRequest, OperatorAuthorityPort};
use lumen_server::{
    AuthorityDb, AuthorityKernelClient, AuthorityKernelConfig, KernelClient, KernelError,
    LeaseDocument, SessionIdentityAuthority, now_ms,
};

/// Stub operator authority: allows or denies every `KeyManagement`
/// request. `None` in the config means no authority is configured at all.
struct StubAuthority {
    allow: bool,
}

impl OperatorAuthorityPort for StubAuthority {
    fn authorize<'a>(&'a self, _r: &'a AuthorityRequest) -> AuthorityFuture<'a> {
        let allow = self.allow;
        Box::pin(async move { Ok(allow) })
    }
}

fn config_with_authority(allow: Option<bool>) -> AuthorityKernelConfig {
    let mut config = AuthorityKernelConfig::test_config();
    config.db = AuthorityDb::Memory;
    config.operator_authority =
        allow.map(|a| Arc::new(StubAuthority { allow: a }) as Arc<dyn OperatorAuthorityPort>);
    config
}

fn actor() -> PrincipalId {
    PrincipalId::new("test", "operator").expect("principal")
}

/// Start a fresh session identity and mint a root lease under the
/// kernel's current issuer generation.
async fn mint_root_lease(kernel: &AuthorityKernelClient, tag: &str) -> LeaseDocument {
    let info = kernel
        .start_session_identity(None)
        .await
        .expect("start session identity");
    let now = now_ms();
    kernel
        .issue_root_lease(RootLeaseParams {
            lease_id: format!("lease-{tag}"),
            subject: info.subject.clone(),
            scope: ResourceScope::default(),
            limits: LeaseLimits {
                not_before_ms: now,
                expires_at_ms: now + 3_600_000,
                budget: Budget::new().set(BudgetDimension::Executions, 100),
                max_executions: None,
                single_use: false,
            },
            depth_limit: 4,
            lease_nonce: format!("nonce-{tag}"),
            issued_at_ms: now,
        })
        .await
        .expect("issue root lease")
}

#[tokio::test]
async fn rotate_without_operator_authority_is_denied() {
    let kernel = AuthorityKernelClient::open(config_with_authority(None))
        .await
        .expect("open");
    let err = kernel
        .rotate_issuer_keys("test", &actor())
        .await
        .expect_err("rotate must be denied");
    assert!(
        matches!(err, KernelError::OperatorDenied(_)),
        "expected OperatorDenied, got {err:?}"
    );
}

#[tokio::test]
async fn rotate_with_denying_authority_is_denied() {
    let kernel = AuthorityKernelClient::open(config_with_authority(Some(false)))
        .await
        .expect("open");
    let err = kernel
        .rotate_issuer_keys("test", &actor())
        .await
        .expect_err("rotate must be denied");
    assert!(
        matches!(err, KernelError::OperatorDenied(_)),
        "expected OperatorDenied, got {err:?}"
    );
}

#[tokio::test]
async fn rotate_kill_purge_happy_path() {
    let kernel = AuthorityKernelClient::open(config_with_authority(Some(true)))
        .await
        .expect("open");

    // Mint under the boot generation, then rotate: the ids must change.
    let lease = mint_root_lease(&kernel, "pre-rotation").await;
    let report = kernel
        .rotate_issuer_keys("test rotation", &actor())
        .await
        .expect("rotate");
    assert_ne!(report.old_issuer_key_id, report.new_issuer_key_id);
    assert_ne!(report.old_host_key_id, report.new_host_key_id);
    assert!(!report.old_issuer_key_id.is_empty());
    // The lease was minted under the now-retired generation.
    assert_eq!(lease.issuer_key_id, report.old_issuer_key_id);

    // D5: the pre-rotation lease still verifies via the retired
    // generation's recorded verifying key.
    let verified = kernel
        .verify_lease(&lease)
        .await
        .expect("pre-rotation lease must still verify after rotation");
    assert_eq!(verified.lease_id, lease.lease_id);
    assert!(!verified.revoked);

    // Killing the current generation is refused (rotate first).
    let err = kernel
        .kill_key_generation(&report.new_issuer_key_id, "issuer", "test", &actor())
        .await
        .expect_err("killing the current generation must fail");
    assert!(
        matches!(err, KernelError::Unavailable(_)),
        "expected Unavailable, got {err:?}"
    );

    // An invalid role is refused.
    let err = kernel
        .kill_key_generation(&report.old_issuer_key_id, "bogus", "test", &actor())
        .await
        .expect_err("invalid role must fail");
    assert!(matches!(err, KernelError::Unavailable(_)));

    // Killing the retired generation succeeds; its lease then fails
    // closed at verification.
    let killed = kernel
        .kill_key_generation(&report.old_issuer_key_id, "issuer", "compromise", &actor())
        .await
        .expect("kill");
    assert!(killed);
    let err = kernel
        .verify_lease(&lease)
        .await
        .expect_err("lease from a killed generation must fail");
    assert!(
        matches!(err, KernelError::VerificationFailed(_)),
        "expected VerificationFailed, got {err:?}"
    );
}

/// Killing a host generation fails closed at audit verification: the
/// boot checkpoints were signed by the pre-rotation host key, so once
/// that generation is killed the chain must no longer verify.
#[tokio::test]
async fn killed_host_generation_fails_audit_verification() {
    let kernel = AuthorityKernelClient::open(config_with_authority(Some(true)))
        .await
        .expect("open");

    // Sanity: the audit chain verifies before the kill.
    kernel
        .verify_kernel_audit()
        .await
        .expect("audit verifies pre-kill");

    let report = kernel
        .rotate_issuer_keys("test rotation", &actor())
        .await
        .expect("rotate");

    let killed = kernel
        .kill_key_generation(&report.old_host_key_id, "host", "compromise", &actor())
        .await
        .expect("kill old host generation");
    assert!(killed);

    let err = kernel
        .verify_kernel_audit()
        .await
        .expect_err("checkpoints from a killed host generation must not verify");
    assert!(
        format!("{err:?}").contains("unknown key generation"),
        "expected unknown-key-generation failure, got {err:?}"
    );
}

#[tokio::test]
async fn purge_retains_generation_with_live_lease_refs() {
    let kernel = AuthorityKernelClient::open(config_with_authority(Some(true)))
        .await
        .expect("open");

    let lease = mint_root_lease(&kernel, "purge-live").await;
    let report = kernel
        .rotate_issuer_keys("test rotation", &actor())
        .await
        .expect("rotate");
    let old_issuer = report.old_issuer_key_id.clone();
    assert_eq!(lease.issuer_key_id, old_issuer);

    let purge = kernel.purge_key_generations(&actor()).await.expect("purge");
    // The retired generation still has a live lease: retained, not purged.
    assert!(
        purge.skipped_live.contains(&old_issuer),
        "expected {old_issuer} in skipped_live, got {purge:?}"
    );
    assert!(
        !purge.purged.contains(&old_issuer),
        "live generation must not be purged, got {purge:?}"
    );
    // Retention is real: the lease still verifies afterwards.
    kernel
        .verify_lease(&lease)
        .await
        .expect("live lease must still verify after purge");
}
