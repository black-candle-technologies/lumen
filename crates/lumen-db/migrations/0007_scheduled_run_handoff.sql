CREATE UNIQUE INDEX scheduled_job_runs_run_idx
    ON scheduled_job_runs(run_id)
    WHERE run_id IS NOT NULL;
