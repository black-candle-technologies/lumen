use std::str::FromStr;

use lumen_core::{
    action::CanonicalValue,
    approval::TimestampMillis,
    audit::{
        AuditEvent, AuditEventId, AuditEventKind, AuditHash, AuditIntegrityError, AuditOutcome,
        AuditRecord, AuditValueError,
    },
    identity::WorkspaceId,
};
use sqlx::Row;
use uuid::Uuid;

use crate::{Database, RepositoryError, timestamp_to_i64};

impl Database {
    pub async fn append_audit_event(
        &self,
        event: AuditEvent,
    ) -> Result<AuditRecord, RepositoryError> {
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let previous: Option<(i64, String)> = sqlx::query_as(
            "SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
        )
        .fetch_optional(&mut *transaction)
        .await?;
        let (sequence, previous_hash) = match previous {
            Some((sequence, hash)) => (
                sequence + 1,
                AuditHash::parse(hash).map_err(audit_value_error)?,
            ),
            None => (1, AuditHash::genesis()),
        };
        let record = AuditRecord::chain(sequence, event, previous_hash);

        sqlx::query(
            "INSERT INTO audit_events (
                sequence, event_id, timestamp, event_type, outcome, workspace_id,
                payload_json, previous_hash, event_hash
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(record.sequence())
        .bind(record.event().id().to_string())
        .bind(timestamp_to_i64(record.event().timestamp())?)
        .bind(record.event().kind().as_str())
        .bind(record.event().outcome().as_str())
        .bind(record.event().workspace_id().map(|id| id.to_string()))
        .bind(serde_json::to_string(record.event().payload())?)
        .bind(record.previous_hash().as_str())
        .bind(record.hash().as_str())
        .execute(&mut *transaction)
        .await?;

        transaction.commit().await?;
        Ok(record)
    }

    pub async fn verify_audit_chain(&self) -> Result<(), AuditIntegrityError> {
        let rows = sqlx::query(
            "SELECT sequence, event_id, timestamp, event_type, outcome, workspace_id,
                    payload_json, previous_hash, event_hash
             FROM audit_events ORDER BY sequence",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;

        let mut expected_previous = AuditHash::genesis();
        for (expected_sequence, row) in (1_i64..).zip(rows) {
            let sequence: i64 = row.try_get("sequence").map_err(storage_error)?;
            if sequence != expected_sequence {
                return Err(AuditIntegrityError::SequenceGap {
                    expected: expected_sequence,
                    actual: sequence,
                });
            }

            let event_id = Uuid::parse_str(
                row.try_get::<String, _>("event_id")
                    .map_err(storage_error)?
                    .as_str(),
            )
            .map_err(|_| AuditValueError::InvalidUuid)?;
            let timestamp =
                u64::try_from(row.try_get::<i64, _>("timestamp").map_err(storage_error)?)
                    .map_err(|_| AuditValueError::InvalidPayload)?;
            let kind = AuditEventKind::from_str(
                row.try_get::<String, _>("event_type")
                    .map_err(storage_error)?
                    .as_str(),
            )?;
            let outcome = AuditOutcome::from_str(
                row.try_get::<String, _>("outcome")
                    .map_err(storage_error)?
                    .as_str(),
            )?;
            let workspace_id = row
                .try_get::<Option<String>, _>("workspace_id")
                .map_err(storage_error)?
                .map(|value| {
                    Uuid::parse_str(&value)
                        .map(WorkspaceId::from_uuid)
                        .map_err(|_| AuditValueError::InvalidUuid)
                })
                .transpose()?;
            let payload = serde_json::from_str::<CanonicalValue>(
                row.try_get::<String, _>("payload_json")
                    .map_err(storage_error)?
                    .as_str(),
            )
            .map_err(|_| AuditValueError::InvalidPayload)?;
            let previous_hash = AuditHash::parse(
                row.try_get::<String, _>("previous_hash")
                    .map_err(storage_error)?,
            )?;
            let hash = AuditHash::parse(
                row.try_get::<String, _>("event_hash")
                    .map_err(storage_error)?,
            )?;
            let event = AuditEvent::new(
                AuditEventId::from_uuid(event_id),
                TimestampMillis::new(timestamp),
                kind,
                outcome,
                workspace_id,
                payload,
            );
            let record = AuditRecord::from_stored(sequence, event, previous_hash, hash);
            record.verify(&expected_previous)?;
            expected_previous = record.hash().clone();
        }

        Ok(())
    }
}

fn audit_value_error(error: AuditValueError) -> RepositoryError {
    RepositoryError::Sqlx(sqlx::Error::Protocol(error.to_string()))
}

fn storage_error(error: sqlx::Error) -> AuditIntegrityError {
    AuditIntegrityError::Storage(error.to_string())
}
