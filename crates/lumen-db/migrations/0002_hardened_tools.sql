CREATE TABLE secret_references (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    label TEXT NOT NULL CHECK (
        length(label) BETWEEN 1 AND 128 AND trim(label) = label
    ),
    keychain_account TEXT NOT NULL UNIQUE CHECK (
        length(keychain_account) BETWEEN 1 AND 512
    ),
    executable TEXT NOT NULL CHECK (length(executable) BETWEEN 1 AND 4096),
    environment_name TEXT NOT NULL CHECK (
        length(environment_name) BETWEEN 1 AND 256
    ),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    UNIQUE (workspace_id, label),
    UNIQUE (workspace_id, id)
) STRICT;

CREATE INDEX secret_references_workspace_idx
    ON secret_references(workspace_id, label, id);
