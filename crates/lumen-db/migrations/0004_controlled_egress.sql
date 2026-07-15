CREATE TABLE egress_model_providers (
    provider_id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

CREATE TABLE egress_model_provider_revisions (
    provider_id TEXT NOT NULL REFERENCES egress_model_providers(provider_id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK (revision > 0),
    endpoint_class TEXT NOT NULL CHECK (endpoint_class IN ('local', 'remote')),
    endpoint_url TEXT NOT NULL,
    model TEXT NOT NULL CHECK (length(model) BETWEEN 1 AND 256),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    priority INTEGER NOT NULL CHECK (priority >= 0),
    credential_secret_ref TEXT,
    allowed_data_classes_json TEXT NOT NULL CHECK (json_valid(allowed_data_classes_json)),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (provider_id, revision),
    CHECK (
        credential_secret_ref IS NULL
        OR (
            length(credential_secret_ref) = 36
            AND credential_secret_ref GLOB
                '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]'
        )
    )
) STRICT;

CREATE TABLE egress_workspace_model_policies (
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    provider_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    allowed_data_classes_json TEXT NOT NULL CHECK (json_valid(allowed_data_classes_json)),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (workspace_id, provider_id, revision),
    FOREIGN KEY (provider_id)
        REFERENCES egress_model_providers(provider_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE egress_destinations (
    destination TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    allowed_data_classes_json TEXT NOT NULL CHECK (json_valid(allowed_data_classes_json)),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (destination, revision)
) STRICT;

CREATE TABLE egress_channel_mappings (
    provider TEXT NOT NULL,
    external_workspace_id TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    external_user_id TEXT NOT NULL,
    lumen_provider TEXT NOT NULL,
    lumen_subject TEXT NOT NULL,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    allowed INTEGER NOT NULL CHECK (allowed IN (0, 1)),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    PRIMARY KEY (provider, external_workspace_id, channel_id, external_user_id),
    FOREIGN KEY (lumen_provider, lumen_subject)
        REFERENCES identities(provider, subject) ON DELETE RESTRICT
) STRICT;

CREATE INDEX egress_model_provider_latest_idx
    ON egress_model_provider_revisions(provider_id, revision DESC);
CREATE INDEX egress_workspace_model_latest_idx
    ON egress_workspace_model_policies(workspace_id, provider_id, revision DESC);
CREATE INDEX egress_destinations_latest_idx
    ON egress_destinations(destination, revision DESC);
