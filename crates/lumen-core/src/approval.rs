use std::fmt;

use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    action::{ActionEnvelope, ActionFingerprint},
    identity::PrincipalId,
    policy::{DenialReason, PolicyDecision, PolicyVersion},
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ApprovalId(Uuid);

impl ApprovalId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }
}

impl Default for ApprovalId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ApprovalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ExecutionAttemptId(Uuid);

impl ExecutionAttemptId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }
}

impl Default for ExecutionAttemptId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ExecutionAttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TimestampMillis(u64);

impl TimestampMillis {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Pending,
    Granted,
    Rejected,
    Expired,
    Consumed,
    Invalidated,
}

impl ApprovalState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Granted => "granted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Consumed => "consumed",
            Self::Invalidated => "invalidated",
        }
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct ApprovalRequest {
    id: ApprovalId,
    action_fingerprint: ActionFingerprint,
    policy_version: PolicyVersion,
    created_at: TimestampMillis,
    expires_at: TimestampMillis,
    state: ApprovalState,
    decided_by: Option<PrincipalId>,
    decided_at: Option<TimestampMillis>,
    consumed_at: Option<TimestampMillis>,
}

impl ApprovalRequest {
    pub fn new(
        id: ApprovalId,
        action_fingerprint: ActionFingerprint,
        policy_version: PolicyVersion,
        created_at: TimestampMillis,
        expires_at: TimestampMillis,
    ) -> Result<Self, ApprovalError> {
        if expires_at <= created_at {
            return Err(ApprovalError::InvalidTimeRange);
        }

        Ok(Self {
            id,
            action_fingerprint,
            policy_version,
            created_at,
            expires_at,
            state: ApprovalState::Pending,
            decided_by: None,
            decided_at: None,
            consumed_at: None,
        })
    }

    pub const fn id(&self) -> ApprovalId {
        self.id
    }

    pub const fn state(&self) -> ApprovalState {
        self.state
    }

    pub const fn action_fingerprint(&self) -> &ActionFingerprint {
        &self.action_fingerprint
    }

    pub const fn policy_version(&self) -> &PolicyVersion {
        &self.policy_version
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub const fn expires_at(&self) -> TimestampMillis {
        self.expires_at
    }

    pub const fn decided_by(&self) -> Option<&PrincipalId> {
        self.decided_by.as_ref()
    }

    pub const fn decided_at(&self) -> Option<TimestampMillis> {
        self.decided_at
    }

    pub const fn consumed_at(&self) -> Option<TimestampMillis> {
        self.consumed_at
    }

    pub fn grant(
        &mut self,
        approver: PrincipalId,
        now: TimestampMillis,
    ) -> Result<(), ApprovalError> {
        self.ensure_pending(now)?;
        self.state = ApprovalState::Granted;
        self.decided_by = Some(approver);
        self.decided_at = Some(now);
        Ok(())
    }

    pub fn reject(
        &mut self,
        approver: PrincipalId,
        now: TimestampMillis,
    ) -> Result<(), ApprovalError> {
        self.ensure_pending(now)?;
        self.state = ApprovalState::Rejected;
        self.decided_by = Some(approver);
        self.decided_at = Some(now);
        Ok(())
    }

    fn ensure_pending(&mut self, now: TimestampMillis) -> Result<(), ApprovalError> {
        if now < self.created_at {
            return Err(ApprovalError::InvalidDecisionTime);
        }
        if now >= self.expires_at {
            self.state = ApprovalState::Expired;
            return Err(ApprovalError::Expired);
        }

        match self.state {
            ApprovalState::Pending => Ok(()),
            ApprovalState::Granted => Err(ApprovalError::AlreadyGranted),
            ApprovalState::Rejected => Err(ApprovalError::Rejected),
            ApprovalState::Expired => Err(ApprovalError::Expired),
            ApprovalState::Consumed => Err(ApprovalError::AlreadyConsumed),
            ApprovalState::Invalidated => Err(ApprovalError::Invalidated),
        }
    }

    fn consume(
        &mut self,
        action: &ActionEnvelope,
        policy_version: &PolicyVersion,
        now: TimestampMillis,
    ) -> Result<ApprovalId, ApprovalError> {
        match self.state {
            ApprovalState::Pending => return Err(ApprovalError::NotGranted),
            ApprovalState::Rejected => return Err(ApprovalError::Rejected),
            ApprovalState::Expired => return Err(ApprovalError::Expired),
            ApprovalState::Consumed => return Err(ApprovalError::AlreadyConsumed),
            ApprovalState::Invalidated => return Err(ApprovalError::Invalidated),
            ApprovalState::Granted => {}
        }

        if now >= self.expires_at {
            self.state = ApprovalState::Expired;
            return Err(ApprovalError::Expired);
        }
        if self.decided_at.is_some_and(|decided_at| now < decided_at) {
            return Err(ApprovalError::InvalidDecisionTime);
        }
        if action.fingerprint() != self.action_fingerprint {
            self.state = ApprovalState::Invalidated;
            return Err(ApprovalError::ActionFingerprintMismatch);
        }
        if policy_version != &self.policy_version {
            self.state = ApprovalState::Invalidated;
            return Err(ApprovalError::PolicyVersionMismatch);
        }

        self.state = ApprovalState::Consumed;
        self.consumed_at = Some(now);
        Ok(self.id)
    }
}

pub fn authorize_dispatch(
    decision: &PolicyDecision,
    action: &ActionEnvelope,
    policy_version: &PolicyVersion,
    approval: Option<&mut ApprovalRequest>,
    now: TimestampMillis,
) -> Result<DispatchAuthorization, DispatchError> {
    match decision {
        PolicyDecision::Deny(reason) => Err(DispatchError::PolicyDenied(reason.clone())),
        PolicyDecision::Allow => Ok(DispatchAuthorization::PolicyAllowed),
        PolicyDecision::RequireApproval => {
            let approval = approval.ok_or(DispatchError::MissingApproval)?;
            let approval_id = approval.consume(action, policy_version, now)?;
            Ok(DispatchAuthorization::Approved { approval_id })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchAuthorization {
    PolicyAllowed,
    Approved { approval_id: ApprovalId },
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ApprovalError {
    #[error("approval expiry must be later than creation")]
    InvalidTimeRange,
    #[error("approval decision cannot predate creation")]
    InvalidDecisionTime,
    #[error("approval has already been granted")]
    AlreadyGranted,
    #[error("approval has not been granted")]
    NotGranted,
    #[error("approval was rejected")]
    Rejected,
    #[error("approval expired")]
    Expired,
    #[error("approval was already consumed")]
    AlreadyConsumed,
    #[error("approval was invalidated")]
    Invalidated,
    #[error("action fingerprint does not match approval")]
    ActionFingerprintMismatch,
    #[error("policy version does not match approval")]
    PolicyVersionMismatch,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DispatchError {
    #[error("current policy denied dispatch: {0:?}")]
    PolicyDenied(DenialReason),
    #[error("current policy requires an approval")]
    MissingApproval,
    #[error(transparent)]
    Approval(#[from] ApprovalError),
}
