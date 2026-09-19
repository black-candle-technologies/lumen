CREATE TABLE skill_publication_intents (
    intent_id TEXT PRIMARY KEY,
    draft_id TEXT NOT NULL REFERENCES workflow_capture_drafts(draft_id) ON DELETE RESTRICT,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    skill_id TEXT NOT NULL,
    version TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    source_format TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    created_provider TEXT NOT NULL,
    created_subject TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('prepared', 'materialized', 'committed', 'reconciliation_required', 'abandoned')),
    diagnostic TEXT,
    FOREIGN KEY (created_provider, created_subject)
        REFERENCES identities(provider, subject) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX skill_publication_intents_active_version_idx
    ON skill_publication_intents(workspace_id, skill_id, version)
    WHERE state != 'abandoned';

CREATE INDEX skill_publication_intents_recovery_idx
    ON skill_publication_intents(state) WHERE state NOT IN ('committed', 'abandoned');
