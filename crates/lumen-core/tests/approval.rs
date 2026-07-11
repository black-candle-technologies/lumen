use lumen_core::action::{ActionEnvelope, ActionId, ActionKind, CanonicalValue, RunId};
use lumen_core::approval::{
    ApprovalError, ApprovalId, ApprovalRequest, ApprovalState, DispatchAuthorization,
    DispatchError, TimestampMillis, authorize_dispatch,
};
use lumen_core::capability::{Capability, CapabilityName, ResourceScope, WorkspacePath};
use lumen_core::identity::{ComponentId, PrincipalId, WorkspaceId};
use lumen_core::policy::{DenialReason, PolicyDecision, PolicyVersion};
use uuid::Uuid;

const CREATED_AT: TimestampMillis = TimestampMillis::new(1_000);
const EXPIRES_AT: TimestampMillis = TimestampMillis::new(2_000);
const BEFORE_EXPIRY: TimestampMillis = TimestampMillis::new(1_500);

fn workspace_id() -> WorkspaceId {
    WorkspaceId::from_uuid(
        Uuid::parse_str("26db5a31-94f0-4e92-a9c9-4cdf19d71c31").expect("valid UUID"),
    )
}

fn action(path: &str) -> ActionEnvelope {
    ActionEnvelope::new(
        ActionId::from_uuid(
            Uuid::parse_str("63908e55-6719-48c4-b43b-95f52264703f").expect("valid UUID"),
        ),
        RunId::from_uuid(
            Uuid::parse_str("f553a2c1-ee86-4c66-af7f-8e913a08ff17").expect("valid UUID"),
        ),
        workspace_id(),
        PrincipalId::new("local", "riley").expect("valid principal"),
        ComponentId::new("builtin.filesystem").expect("valid component"),
        ActionKind::new("filesystem.write").expect("valid action kind"),
        CanonicalValue::object([("path", CanonicalValue::from(path))]),
        vec![Capability::new(
            CapabilityName::FsWrite,
            ResourceScope::path(
                workspace_id(),
                WorkspacePath::parse(path).expect("valid workspace path"),
            ),
        )],
    )
}

fn policy_version(value: &str) -> PolicyVersion {
    PolicyVersion::new(value).expect("valid policy version")
}

fn pending_approval(action: &ActionEnvelope) -> ApprovalRequest {
    ApprovalRequest::new(
        ApprovalId::from_uuid(
            Uuid::parse_str("8e4cf97d-228d-4f63-b644-b28f24f8cd78").expect("valid UUID"),
        ),
        action.fingerprint(),
        policy_version("policy-v1"),
        CREATED_AT,
        EXPIRES_AT,
    )
    .expect("valid approval request")
}

fn approver() -> PrincipalId {
    PrincipalId::new("local", "admin").expect("valid principal")
}

#[test]
fn one_shot_approval_authorizes_exactly_once() {
    let action = action("notes/today.md");
    let mut approval = pending_approval(&action);
    approval
        .grant(approver(), TimestampMillis::new(1_200))
        .expect("pending approval can be granted");

    let authorization = authorize_dispatch(
        &PolicyDecision::RequireApproval,
        &action,
        &policy_version("policy-v1"),
        Some(&mut approval),
        BEFORE_EXPIRY,
    )
    .expect("matching approval authorizes dispatch");

    assert_eq!(
        authorization,
        DispatchAuthorization::Approved {
            approval_id: approval.id()
        }
    );
    assert_eq!(approval.state(), ApprovalState::Consumed);

    assert_eq!(
        authorize_dispatch(
            &PolicyDecision::RequireApproval,
            &action,
            &policy_version("policy-v1"),
            Some(&mut approval),
            BEFORE_EXPIRY,
        ),
        Err(DispatchError::Approval(ApprovalError::AlreadyConsumed))
    );
}

#[test]
fn expired_approval_is_marked_expired_and_cannot_dispatch() {
    let action = action("notes/today.md");
    let mut approval = pending_approval(&action);
    approval
        .grant(approver(), TimestampMillis::new(1_200))
        .expect("pending approval can be granted");

    assert_eq!(
        authorize_dispatch(
            &PolicyDecision::RequireApproval,
            &action,
            &policy_version("policy-v1"),
            Some(&mut approval),
            EXPIRES_AT,
        ),
        Err(DispatchError::Approval(ApprovalError::Expired))
    );
    assert_eq!(approval.state(), ApprovalState::Expired);
}

#[test]
fn dispatch_cannot_be_recorded_before_the_grant_decision() {
    let action = action("notes/today.md");
    let mut approval = pending_approval(&action);
    approval
        .grant(approver(), TimestampMillis::new(1_200))
        .expect("pending approval can be granted");

    assert_eq!(
        authorize_dispatch(
            &PolicyDecision::RequireApproval,
            &action,
            &policy_version("policy-v1"),
            Some(&mut approval),
            TimestampMillis::new(1_100),
        ),
        Err(DispatchError::Approval(ApprovalError::InvalidDecisionTime))
    );
    assert_eq!(approval.state(), ApprovalState::Granted);
}

#[test]
fn changed_action_invalidates_approval() {
    let original = action("notes/today.md");
    let changed = action("notes/private.md");
    let mut approval = pending_approval(&original);
    approval
        .grant(approver(), TimestampMillis::new(1_200))
        .expect("pending approval can be granted");

    assert_eq!(
        authorize_dispatch(
            &PolicyDecision::RequireApproval,
            &changed,
            &policy_version("policy-v1"),
            Some(&mut approval),
            BEFORE_EXPIRY,
        ),
        Err(DispatchError::Approval(
            ApprovalError::ActionFingerprintMismatch
        ))
    );
    assert_eq!(approval.state(), ApprovalState::Invalidated);
}

#[test]
fn changed_policy_version_invalidates_approval() {
    let action = action("notes/today.md");
    let mut approval = pending_approval(&action);
    approval
        .grant(approver(), TimestampMillis::new(1_200))
        .expect("pending approval can be granted");

    assert_eq!(
        authorize_dispatch(
            &PolicyDecision::RequireApproval,
            &action,
            &policy_version("policy-v2"),
            Some(&mut approval),
            BEFORE_EXPIRY,
        ),
        Err(DispatchError::Approval(
            ApprovalError::PolicyVersionMismatch
        ))
    );
    assert_eq!(approval.state(), ApprovalState::Invalidated);
}

#[test]
fn rejected_approval_cannot_be_granted_or_used() {
    let action = action("notes/today.md");
    let mut approval = pending_approval(&action);
    approval
        .reject(approver(), TimestampMillis::new(1_200))
        .expect("pending approval can be rejected");

    assert_eq!(approval.state(), ApprovalState::Rejected);
    assert_eq!(
        approval.grant(approver(), TimestampMillis::new(1_300)),
        Err(ApprovalError::Rejected)
    );
    assert_eq!(
        authorize_dispatch(
            &PolicyDecision::RequireApproval,
            &action,
            &policy_version("policy-v1"),
            Some(&mut approval),
            BEFORE_EXPIRY,
        ),
        Err(DispatchError::Approval(ApprovalError::Rejected))
    );
}

#[test]
fn approval_is_required_only_when_the_current_policy_requires_it() {
    let action = action("notes/today.md");

    assert_eq!(
        authorize_dispatch(
            &PolicyDecision::Allow,
            &action,
            &policy_version("policy-v1"),
            None,
            BEFORE_EXPIRY,
        ),
        Ok(DispatchAuthorization::PolicyAllowed)
    );
    assert_eq!(
        authorize_dispatch(
            &PolicyDecision::RequireApproval,
            &action,
            &policy_version("policy-v1"),
            None,
            BEFORE_EXPIRY,
        ),
        Err(DispatchError::MissingApproval)
    );
}

#[test]
fn approval_cannot_override_a_current_policy_denial() {
    let action = action("notes/today.md");
    let mut approval = pending_approval(&action);
    approval
        .grant(approver(), TimestampMillis::new(1_200))
        .expect("pending approval can be granted");

    assert_eq!(
        authorize_dispatch(
            &PolicyDecision::Deny(DenialReason::NoCapabilitiesDeclared),
            &action,
            &policy_version("policy-v1"),
            Some(&mut approval),
            BEFORE_EXPIRY,
        ),
        Err(DispatchError::PolicyDenied(
            DenialReason::NoCapabilitiesDeclared
        ))
    );
    assert_eq!(approval.state(), ApprovalState::Granted);
}
