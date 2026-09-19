CREATE TABLE run_lifecycle (
    run_id TEXT PRIMARY KEY REFERENCES agent_runs(id) ON DELETE CASCADE,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    owner_instance_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN (
        'admitted', 'preparing', 'running', 'awaiting_approval',
        'reserving_effect', 'terminal', 'reconciliation_required'
    )),
    effect_certainty TEXT NOT NULL CHECK (effect_certainty IN ('no_effect', 'known', 'unknown')),
    terminal_code TEXT,
    primary_diagnostic TEXT CHECK (
        primary_diagnostic IS NULL OR length(CAST(primary_diagnostic AS BLOB)) <= 1024
    ),
    secondary_diagnostic TEXT CHECK (
        secondary_diagnostic IS NULL OR length(CAST(secondary_diagnostic AS BLOB)) <= 1024
    ),
    terminal_audit_id TEXT UNIQUE,
    terminal_audit_pending INTEGER NOT NULL DEFAULT 0 CHECK (terminal_audit_pending IN (0, 1)),
    terminal_audit_occurred_at INTEGER CHECK (
        terminal_audit_occurred_at IS NULL OR terminal_audit_occurred_at >= 0
    ),
    terminal_audit_payload_json TEXT CHECK (
        terminal_audit_payload_json IS NULL OR
        length(CAST(terminal_audit_payload_json AS BLOB)) <= 8192
    ),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0)
) STRICT;

CREATE INDEX run_lifecycle_recovery_idx ON run_lifecycle(phase, owner_instance_id);
CREATE INDEX run_lifecycle_workspace_idx ON run_lifecycle(workspace_id, run_id);
