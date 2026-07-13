use std::{fmt, str::FromStr};

use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{action::CanonicalValue, approval::TimestampMillis, identity::WorkspaceId};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AuditEventId(Uuid);

impl AuditEventId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }
}

impl Default for AuditEventId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AuditEventId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    AuthenticationAccepted,
    AuthenticationRejected,
    RunCreated,
    RunCompleted,
    RunCancelled,
    RunBudgetExhausted,
    ActionProposed,
    ActionNormalized,
    PolicyAllowed,
    PolicyDenied,
    ApprovalCreated,
    ApprovalGranted,
    ApprovalRejected,
    ApprovalConsumed,
    ExecutionStarted,
    ExecutionSucceeded,
    ExecutionFailed,
    ExecutionCancelled,
    ExecutionTimedOut,
    ExecutionUnknown,
}

impl AuditEventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticationAccepted => "authentication_accepted",
            Self::AuthenticationRejected => "authentication_rejected",
            Self::RunCreated => "run_created",
            Self::RunCompleted => "run_completed",
            Self::RunCancelled => "run_cancelled",
            Self::RunBudgetExhausted => "run_budget_exhausted",
            Self::ActionProposed => "action_proposed",
            Self::ActionNormalized => "action_normalized",
            Self::PolicyAllowed => "policy_allowed",
            Self::PolicyDenied => "policy_denied",
            Self::ApprovalCreated => "approval_created",
            Self::ApprovalGranted => "approval_granted",
            Self::ApprovalRejected => "approval_rejected",
            Self::ApprovalConsumed => "approval_consumed",
            Self::ExecutionStarted => "execution_started",
            Self::ExecutionSucceeded => "execution_succeeded",
            Self::ExecutionFailed => "execution_failed",
            Self::ExecutionCancelled => "execution_cancelled",
            Self::ExecutionTimedOut => "execution_timed_out",
            Self::ExecutionUnknown => "execution_unknown",
        }
    }
}

impl FromStr for AuditEventKind {
    type Err = AuditValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "authentication_accepted" => Ok(Self::AuthenticationAccepted),
            "authentication_rejected" => Ok(Self::AuthenticationRejected),
            "run_created" => Ok(Self::RunCreated),
            "run_completed" => Ok(Self::RunCompleted),
            "run_cancelled" => Ok(Self::RunCancelled),
            "run_budget_exhausted" => Ok(Self::RunBudgetExhausted),
            "action_proposed" => Ok(Self::ActionProposed),
            "action_normalized" => Ok(Self::ActionNormalized),
            "policy_allowed" => Ok(Self::PolicyAllowed),
            "policy_denied" => Ok(Self::PolicyDenied),
            "approval_created" => Ok(Self::ApprovalCreated),
            "approval_granted" => Ok(Self::ApprovalGranted),
            "approval_rejected" => Ok(Self::ApprovalRejected),
            "approval_consumed" => Ok(Self::ApprovalConsumed),
            "execution_started" => Ok(Self::ExecutionStarted),
            "execution_succeeded" => Ok(Self::ExecutionSucceeded),
            "execution_failed" => Ok(Self::ExecutionFailed),
            "execution_cancelled" => Ok(Self::ExecutionCancelled),
            "execution_timed_out" => Ok(Self::ExecutionTimedOut),
            "execution_unknown" => Ok(Self::ExecutionUnknown),
            _ => Err(AuditValueError::UnknownEventKind(value.to_owned())),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
    Pending,
    Unknown,
}

impl AuditOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
            Self::Pending => "pending",
            Self::Unknown => "unknown",
        }
    }
}

impl FromStr for AuditOutcome {
    type Err = AuditValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "success" => Ok(Self::Success),
            "failure" => Ok(Self::Failure),
            "denied" => Ok(Self::Denied),
            "pending" => Ok(Self::Pending),
            "unknown" => Ok(Self::Unknown),
            _ => Err(AuditValueError::UnknownOutcome(value.to_owned())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditEvent {
    id: AuditEventId,
    timestamp: TimestampMillis,
    kind: AuditEventKind,
    outcome: AuditOutcome,
    workspace_id: Option<WorkspaceId>,
    payload: CanonicalValue,
}

impl AuditEvent {
    pub const fn new(
        id: AuditEventId,
        timestamp: TimestampMillis,
        kind: AuditEventKind,
        outcome: AuditOutcome,
        workspace_id: Option<WorkspaceId>,
        payload: CanonicalValue,
    ) -> Self {
        Self {
            id,
            timestamp,
            kind,
            outcome,
            workspace_id,
            payload,
        }
    }

    pub const fn id(&self) -> AuditEventId {
        self.id
    }

    pub const fn timestamp(&self) -> TimestampMillis {
        self.timestamp
    }

    pub const fn kind(&self) -> AuditEventKind {
        self.kind
    }

    pub const fn outcome(&self) -> AuditOutcome {
        self.outcome
    }

    pub const fn workspace_id(&self) -> Option<WorkspaceId> {
        self.workspace_id
    }

    pub const fn payload(&self) -> &CanonicalValue {
        &self.payload
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AuditHash(String);

impl AuditHash {
    pub fn genesis() -> Self {
        Self("0".repeat(64))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, AuditValueError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AuditValueError::InvalidHash);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AuditHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRecord {
    sequence: i64,
    event: AuditEvent,
    previous_hash: AuditHash,
    hash: AuditHash,
}

impl AuditRecord {
    pub fn chain(sequence: i64, event: AuditEvent, previous_hash: AuditHash) -> Self {
        let hash = calculate_hash(sequence, &event, &previous_hash);
        Self {
            sequence,
            event,
            previous_hash,
            hash,
        }
    }

    pub fn from_stored(
        sequence: i64,
        event: AuditEvent,
        previous_hash: AuditHash,
        hash: AuditHash,
    ) -> Self {
        Self {
            sequence,
            event,
            previous_hash,
            hash,
        }
    }

    pub const fn sequence(&self) -> i64 {
        self.sequence
    }

    pub const fn event(&self) -> &AuditEvent {
        &self.event
    }

    pub const fn previous_hash(&self) -> &AuditHash {
        &self.previous_hash
    }

    pub const fn hash(&self) -> &AuditHash {
        &self.hash
    }

    pub fn verify(&self, expected_previous: &AuditHash) -> Result<(), AuditIntegrityError> {
        if &self.previous_hash != expected_previous {
            return Err(AuditIntegrityError::PreviousHashMismatch {
                sequence: self.sequence,
            });
        }
        if self.hash != calculate_hash(self.sequence, &self.event, &self.previous_hash) {
            return Err(AuditIntegrityError::HashMismatch {
                sequence: self.sequence,
            });
        }
        Ok(())
    }
}

fn calculate_hash(sequence: i64, event: &AuditEvent, previous_hash: &AuditHash) -> AuditHash {
    let encoded = serde_json::to_vec(&(sequence, event, previous_hash))
        .expect("audit record serialization cannot fail");
    AuditHash(format!("{:x}", Sha256::digest(encoded)))
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AuditIntegrityError {
    #[error("audit event {sequence} does not reference the expected previous hash")]
    PreviousHashMismatch { sequence: i64 },
    #[error("audit event {sequence} hash does not match its content")]
    HashMismatch { sequence: i64 },
    #[error("audit sequence expected {expected} but found {actual}")]
    SequenceGap { expected: i64, actual: i64 },
    #[error(transparent)]
    InvalidValue(#[from] AuditValueError),
    #[error("could not read audit storage: {0}")]
    Storage(String),
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AuditValueError {
    #[error("unknown audit event kind: {0}")]
    UnknownEventKind(String),
    #[error("unknown audit outcome: {0}")]
    UnknownOutcome(String),
    #[error("audit hash must contain 64 lowercase hexadecimal characters")]
    InvalidHash,
    #[error("invalid UUID in audit record")]
    InvalidUuid,
    #[error("invalid audit payload")]
    InvalidPayload,
}
