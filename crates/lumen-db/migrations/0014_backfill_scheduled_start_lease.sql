-- Databases that applied 0012 before start_lease_id was populated for an
-- already-running occurrence need a conservative backfill.  Never fabricate
-- a lease: rows without their matching durable lease remain for explicit
-- reconciliation.
UPDATE scheduled_job_runs
SET start_lease_id = (
    SELECT lease_id
    FROM scheduled_job_leases
    WHERE scheduled_job_leases.occurrence_key = scheduled_job_runs.occurrence_key
)
WHERE state = 'running'
  AND start_lease_id IS NULL
  AND EXISTS (
      SELECT 1
      FROM scheduled_job_leases
      WHERE scheduled_job_leases.occurrence_key = scheduled_job_runs.occurrence_key
  );
