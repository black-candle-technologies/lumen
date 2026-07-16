use std::{fmt, time::Duration};

use semver::Version;
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    approval::TimestampMillis,
    identity::{IdentityError, PrincipalId},
};

macro_rules! uuid_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

uuid_id!(JobId);
uuid_id!(SkillId);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct JobRevision(u64);

impl JobRevision {
    pub const fn new(value: u64) -> Result<Self, AutomationError> {
        if value == 0 {
            return Err(AutomationError::InvalidRevision);
        }
        Ok(Self(value))
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SkillVersion(String);

impl SkillVersion {
    pub fn parse(value: impl Into<String>) -> Result<Self, AutomationError> {
        let value = value.into();
        let parsed = Version::parse(&value).map_err(|_| AutomationError::InvalidSkillVersion)?;
        if parsed.to_string() != value {
            return Err(AutomationError::InvalidSkillVersion);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct OccurrenceKey {
    job_id: JobId,
    revision: JobRevision,
    scheduled_for: TimestampMillis,
    value: String,
}

impl OccurrenceKey {
    pub fn new(job_id: JobId, revision: JobRevision, scheduled_for: TimestampMillis) -> Self {
        let value = format!("{job_id}:{}:{}", revision.as_u64(), scheduled_for.as_u64());
        Self {
            job_id,
            revision,
            scheduled_for,
            value,
        }
    }

    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    pub const fn revision(&self) -> JobRevision {
        self.revision
    }

    pub const fn scheduled_for(&self) -> TimestampMillis {
        self.scheduled_for
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JobOrigin {
    job_id: JobId,
    revision: JobRevision,
    scheduled_for: TimestampMillis,
    occurrence_key: OccurrenceKey,
}

impl JobOrigin {
    pub fn new(job_id: JobId, revision: JobRevision, scheduled_for: TimestampMillis) -> Self {
        let occurrence_key = OccurrenceKey::new(job_id, revision, scheduled_for);
        Self {
            job_id,
            revision,
            scheduled_for,
            occurrence_key,
        }
    }

    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    pub const fn revision(&self) -> JobRevision {
        self.revision
    }

    pub const fn scheduled_for(&self) -> TimestampMillis {
        self.scheduled_for
    }

    pub const fn occurrence_key(&self) -> &OccurrenceKey {
        &self.occurrence_key
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ScheduleSpec {
    Once {
        run_at: TimestampMillis,
    },
    Interval {
        start_at: TimestampMillis,
        interval_millis: u64,
    },
}

impl ScheduleSpec {
    pub const fn once(run_at: TimestampMillis) -> Self {
        Self::Once { run_at }
    }

    pub fn interval(
        start_at: TimestampMillis,
        interval: Duration,
    ) -> Result<Self, AutomationError> {
        let interval_millis =
            u64::try_from(interval.as_millis()).map_err(|_| AutomationError::InvalidInterval)?;
        if interval_millis == 0 {
            return Err(AutomationError::InvalidInterval);
        }
        Ok(Self::Interval {
            start_at,
            interval_millis,
        })
    }

    pub const fn next_after(
        self,
        timestamp: TimestampMillis,
        enabled: bool,
    ) -> Option<TimestampMillis> {
        if !enabled {
            return None;
        }
        match self {
            Self::Once { run_at } => {
                if timestamp.as_u64() < run_at.as_u64() {
                    Some(run_at)
                } else {
                    None
                }
            }
            Self::Interval {
                start_at,
                interval_millis,
            } => {
                if timestamp.as_u64() < start_at.as_u64() {
                    return Some(start_at);
                }
                let elapsed = timestamp.as_u64() - start_at.as_u64();
                let steps = elapsed / interval_millis + 1;
                let offset = match steps.checked_mul(interval_millis) {
                    Some(offset) => offset,
                    None => return None,
                };
                match start_at.as_u64().checked_add(offset) {
                    Some(next) => Some(TimestampMillis::new(next)),
                    None => None,
                }
            }
        }
    }
}

pub fn service_principal(subject: impl Into<String>) -> Result<PrincipalId, IdentityError> {
    PrincipalId::new("service", subject)
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AutomationError {
    #[error("job revision must be greater than zero")]
    InvalidRevision,
    #[error("skill version must be canonical semantic version")]
    InvalidSkillVersion,
    #[error("schedule interval must be positive and fit in milliseconds")]
    InvalidInterval,
}
