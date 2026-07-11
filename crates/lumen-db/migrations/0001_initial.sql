CREATE TABLE workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

CREATE TABLE identities (
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (provider, subject)
) STRICT;

CREATE TABLE workspace_memberships (
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    identity_provider TEXT NOT NULL,
    identity_subject TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'member', 'service')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (workspace_id, identity_provider, identity_subject),
    FOREIGN KEY (identity_provider, identity_subject)
        REFERENCES identities(provider, subject) ON DELETE CASCADE
) STRICT;

CREATE TABLE conversations (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('system', 'user', 'assistant', 'tool')),
    content_json TEXT NOT NULL CHECK (json_valid(content_json)),
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

CREATE TABLE agent_runs (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    actor_provider TEXT NOT NULL,
    actor_subject TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'created', 'running', 'awaiting_approval', 'completed', 'failed', 'cancelled'
    )),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    completed_at INTEGER,
    UNIQUE (id, workspace_id, actor_provider, actor_subject),
    FOREIGN KEY (actor_provider, actor_subject)
        REFERENCES identities(provider, subject) ON DELETE RESTRICT
) STRICT;

CREATE TABLE actions (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    actor_provider TEXT NOT NULL,
    actor_subject TEXT NOT NULL,
    requesting_component TEXT NOT NULL,
    kind TEXT NOT NULL,
    arguments_json TEXT NOT NULL CHECK (json_valid(arguments_json)),
    capabilities_json TEXT NOT NULL CHECK (json_valid(capabilities_json)),
    fingerprint TEXT NOT NULL UNIQUE CHECK (
        length(fingerprint) = 64 AND fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL CHECK (state IN (
        'proposed', 'normalized', 'evaluating', 'denied', 'awaiting_approval',
        'approved', 'dispatching', 'running', 'succeeded', 'failed', 'cancelled',
        'timed_out', 'unknown'
    )),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    UNIQUE (id, fingerprint),
    FOREIGN KEY (run_id, workspace_id, actor_provider, actor_subject)
        REFERENCES agent_runs(id, workspace_id, actor_provider, actor_subject)
        ON DELETE CASCADE,
    FOREIGN KEY (actor_provider, actor_subject)
        REFERENCES identities(provider, subject) ON DELETE RESTRICT
) STRICT;

CREATE TABLE policy_decisions (
    id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    policy_version TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny', 'require_approval')),
    reasons_json TEXT NOT NULL CHECK (json_valid(reasons_json)),
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

CREATE TABLE approval_requests (
    id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    action_fingerprint TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'pending', 'granted', 'rejected', 'expired', 'consumed', 'invalidated'
    )),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    decided_by_provider TEXT,
    decided_by_subject TEXT,
    decided_at INTEGER,
    consumed_at INTEGER,
    CHECK (
        (decided_by_provider IS NULL AND decided_by_subject IS NULL AND decided_at IS NULL)
        OR
        (decided_by_provider IS NOT NULL AND decided_by_subject IS NOT NULL AND decided_at IS NOT NULL)
    ),
    CHECK (
        (state = 'consumed' AND consumed_at IS NOT NULL)
        OR (state != 'consumed' AND consumed_at IS NULL)
    ),
    FOREIGN KEY (action_id, action_fingerprint)
        REFERENCES actions(id, fingerprint) ON DELETE CASCADE,
    FOREIGN KEY (decided_by_provider, decided_by_subject)
        REFERENCES identities(provider, subject) ON DELETE RESTRICT
) STRICT;

CREATE TABLE execution_attempts (
    id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    approval_id TEXT UNIQUE REFERENCES approval_requests(id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK (state IN (
        'reserved', 'running', 'succeeded', 'failed', 'cancelled', 'timed_out', 'unknown'
    )),
    reserved_at INTEGER NOT NULL CHECK (reserved_at >= 0),
    completed_at INTEGER
) STRICT;

CREATE TABLE model_providers (
    id TEXT PRIMARY KEY,
    endpoint_class TEXT NOT NULL CHECK (endpoint_class IN ('local', 'remote')),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    config_json TEXT NOT NULL CHECK (json_valid(config_json)),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at)
) STRICT;

CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    timestamp INTEGER NOT NULL CHECK (timestamp >= 0),
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied', 'pending', 'unknown')),
    workspace_id TEXT REFERENCES workspaces(id) ON DELETE RESTRICT,
    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
    previous_hash TEXT NOT NULL CHECK (
        length(previous_hash) = 64 AND previous_hash NOT GLOB '*[^0-9a-f]*'
    ),
    event_hash TEXT NOT NULL UNIQUE CHECK (
        length(event_hash) = 64 AND event_hash NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

CREATE TABLE audit_checkpoints (
    sequence INTEGER PRIMARY KEY REFERENCES audit_events(sequence) ON DELETE RESTRICT,
    event_hash TEXT NOT NULL,
    verified_at INTEGER NOT NULL CHECK (verified_at >= 0)
) STRICT;

CREATE INDEX actions_run_id_idx ON actions(run_id);
CREATE INDEX actions_workspace_id_idx ON actions(workspace_id);
CREATE INDEX approvals_action_id_idx ON approval_requests(action_id);
CREATE INDEX audit_workspace_sequence_idx ON audit_events(workspace_id, sequence);
