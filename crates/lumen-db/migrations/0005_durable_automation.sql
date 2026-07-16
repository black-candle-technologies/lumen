CREATE TABLE service_identities (
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    owner_provider TEXT NOT NULL,
    owner_subject TEXT NOT NULL,
    label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 128),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    PRIMARY KEY (provider, subject),
    FOREIGN KEY (provider, subject)
        REFERENCES identities(provider, subject) ON DELETE RESTRICT,
    FOREIGN KEY (owner_provider, owner_subject)
        REFERENCES identities(provider, subject) ON DELETE RESTRICT,
    CHECK (provider = 'service')
) STRICT;

CREATE TABLE service_identity_grants (
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    capability_name TEXT NOT NULL,
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('workspace', 'path', 'exact')),
    scope_workspace_id TEXT NOT NULL,
    scope_path TEXT NOT NULL,
    scope_resource_type TEXT NOT NULL,
    scope_resource_value TEXT NOT NULL,
    PRIMARY KEY (
        provider, subject, workspace_id, capability_name, scope_kind,
        scope_workspace_id, scope_path, scope_resource_type, scope_resource_value
    ),
    FOREIGN KEY (provider, subject)
        REFERENCES service_identities(provider, subject) ON DELETE CASCADE
) STRICT;

CREATE TABLE scheduled_jobs (
    job_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    service_provider TEXT NOT NULL,
    service_subject TEXT NOT NULL,
    owner_provider TEXT NOT NULL,
    owner_subject TEXT NOT NULL,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    FOREIGN KEY (service_provider, service_subject)
        REFERENCES service_identities(provider, subject) ON DELETE RESTRICT,
    FOREIGN KEY (owner_provider, owner_subject)
        REFERENCES identities(provider, subject) ON DELETE RESTRICT
) STRICT;

CREATE TABLE scheduled_job_revisions (
    job_id TEXT NOT NULL REFERENCES scheduled_jobs(job_id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK (revision > 0),
    schedule_kind TEXT NOT NULL CHECK (schedule_kind IN ('once', 'interval')),
    schedule_start_at INTEGER NOT NULL CHECK (schedule_start_at >= 0),
    interval_millis INTEGER CHECK (interval_millis IS NULL OR interval_millis > 0),
    prompt TEXT NOT NULL CHECK (length(prompt) BETWEEN 1 AND 8192),
    data_class TEXT NOT NULL CHECK (data_class IN ('public', 'workspace', 'sensitive')),
    max_model_turns INTEGER NOT NULL CHECK (max_model_turns > 0),
    max_actions INTEGER NOT NULL CHECK (max_actions > 0),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    next_due_at INTEGER CHECK (next_due_at IS NULL OR next_due_at >= 0),
    idempotent INTEGER NOT NULL CHECK (idempotent IN (0, 1)),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (job_id, revision)
) STRICT;

CREATE TABLE scheduled_job_runs (
    occurrence_key TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES scheduled_jobs(job_id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK (revision > 0),
    scheduled_for INTEGER NOT NULL CHECK (scheduled_for >= 0),
    run_id TEXT,
    state TEXT NOT NULL CHECK (state IN ('claimed', 'running', 'succeeded', 'failed', 'cancelled', 'unknown')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at)
) STRICT;

CREATE TABLE scheduled_job_leases (
    occurrence_key TEXT PRIMARY KEY REFERENCES scheduled_job_runs(occurrence_key) ON DELETE CASCADE,
    lease_id TEXT NOT NULL,
    leased_at INTEGER NOT NULL CHECK (leased_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > leased_at)
) STRICT;

CREATE TABLE agent_skills (
    skill_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    description TEXT NOT NULL CHECK (length(description) BETWEEN 1 AND 2048),
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

CREATE TABLE skill_versions (
    skill_id TEXT NOT NULL REFERENCES agent_skills(skill_id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    source_format TEXT NOT NULL CHECK (length(source_format) BETWEEN 1 AND 32),
    source_digest TEXT NOT NULL CHECK (length(source_digest) = 71),
    reviewed INTEGER NOT NULL CHECK (reviewed IN (0, 1)),
    created_provider TEXT NOT NULL,
    created_subject TEXT NOT NULL,
    reviewed_provider TEXT,
    reviewed_subject TEXT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    reviewed_at INTEGER CHECK (reviewed_at IS NULL OR reviewed_at >= created_at),
    PRIMARY KEY (skill_id, version),
    FOREIGN KEY (created_provider, created_subject)
        REFERENCES identities(provider, subject) ON DELETE RESTRICT,
    FOREIGN KEY (reviewed_provider, reviewed_subject)
        REFERENCES identities(provider, subject) ON DELETE RESTRICT
) STRICT;

CREATE TABLE skill_workspace_state (
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    skill_id TEXT NOT NULL,
    version TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    PRIMARY KEY (workspace_id, skill_id),
    FOREIGN KEY (skill_id, version)
        REFERENCES skill_versions(skill_id, version) ON DELETE RESTRICT
) STRICT;

CREATE TABLE workflow_capture_drafts (
    draft_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 128),
    body TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 65536),
    created_provider TEXT NOT NULL,
    created_subject TEXT NOT NULL,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    FOREIGN KEY (created_provider, created_subject)
        REFERENCES identities(provider, subject) ON DELETE RESTRICT
) STRICT;

CREATE INDEX scheduled_job_revisions_latest_idx
    ON scheduled_job_revisions(job_id, revision DESC);
CREATE INDEX scheduled_job_revisions_due_idx
    ON scheduled_job_revisions(enabled, next_due_at);
CREATE INDEX skill_workspace_state_enabled_idx
    ON skill_workspace_state(workspace_id, enabled);
