CREATE TABLE plugin_staged_packages (
    id TEXT PRIMARY KEY,
    plugin_id TEXT NOT NULL,
    plugin_version TEXT NOT NULL,
    runtime_type TEXT NOT NULL CHECK (runtime_type IN ('wasm-component', 'subprocess')),
    quarantine_path TEXT NOT NULL CHECK (
        length(quarantine_path) BETWEEN 1 AND 4096
        AND substr(quarantine_path, 1, 1) != '/'
        AND instr(quarantine_path, '..') = 0
    ),
    package_digest TEXT NOT NULL CHECK (length(package_digest) = 64 AND package_digest NOT GLOB '*[^0-9a-f]*'),
    manifest_digest TEXT NOT NULL CHECK (length(manifest_digest) = 64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'),
    artifact_digest TEXT NOT NULL CHECK (length(artifact_digest) = 64 AND artifact_digest NOT GLOB '*[^0-9a-f]*'),
    manifest_json TEXT NOT NULL CHECK (json_valid(manifest_json)),
    file_hashes_json TEXT NOT NULL CHECK (json_valid(file_hashes_json)),
    source_type TEXT NOT NULL CHECK (source_type = 'local'),
    requested_by_provider TEXT NOT NULL,
    requested_by_subject TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('staged', 'installed', 'rejected')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    installed_at INTEGER,
    UNIQUE (package_digest),
    FOREIGN KEY (requested_by_provider, requested_by_subject)
        REFERENCES identities(provider, subject) ON DELETE RESTRICT
) STRICT;

ALTER TABLE actions ADD COLUMN extension_provenance_json TEXT
    CHECK (extension_provenance_json IS NULL OR json_valid(extension_provenance_json));

CREATE TABLE plugins (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

CREATE TABLE plugin_versions (
    plugin_id TEXT NOT NULL REFERENCES plugins(id) ON DELETE RESTRICT,
    version TEXT NOT NULL,
    runtime_type TEXT NOT NULL CHECK (runtime_type IN ('wasm-component', 'subprocess')),
    artifact_path TEXT NOT NULL CHECK (
        length(artifact_path) BETWEEN 1 AND 4096
        AND substr(artifact_path, 1, 1) != '/'
        AND instr(artifact_path, '..') = 0
    ),
    package_digest TEXT NOT NULL UNIQUE CHECK (length(package_digest) = 64 AND package_digest NOT GLOB '*[^0-9a-f]*'),
    manifest_digest TEXT NOT NULL CHECK (length(manifest_digest) = 64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'),
    artifact_digest TEXT NOT NULL CHECK (length(artifact_digest) = 64 AND artifact_digest NOT GLOB '*[^0-9a-f]*'),
    manifest_json TEXT NOT NULL CHECK (json_valid(manifest_json)),
    artifact_state TEXT NOT NULL CHECK (artifact_state IN ('installed', 'artifact_quarantine')),
    installed_at INTEGER NOT NULL CHECK (installed_at >= 0),
    artifact_quarantined_at INTEGER,
    PRIMARY KEY (plugin_id, version)
) STRICT;

CREATE TABLE plugin_components (
    plugin_id TEXT NOT NULL,
    plugin_version TEXT NOT NULL,
    component_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind = 'tool'),
    description TEXT NOT NULL,
    input_schema_path TEXT NOT NULL,
    output_schema_path TEXT NOT NULL,
    action_kinds_json TEXT NOT NULL CHECK (json_valid(action_kinds_json)),
    PRIMARY KEY (plugin_id, plugin_version, component_id),
    FOREIGN KEY (plugin_id, plugin_version)
        REFERENCES plugin_versions(plugin_id, version) ON DELETE RESTRICT
) STRICT;

CREATE TABLE plugin_capability_requests (
    plugin_id TEXT NOT NULL,
    plugin_version TEXT NOT NULL,
    component_id TEXT NOT NULL,
    capability_name TEXT NOT NULL,
    requested_scope TEXT NOT NULL CHECK (requested_scope = 'workspace'),
    PRIMARY KEY (plugin_id, plugin_version, component_id, capability_name),
    FOREIGN KEY (plugin_id, plugin_version, component_id)
        REFERENCES plugin_components(plugin_id, plugin_version, component_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE plugin_workspace_versions (
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    plugin_id TEXT NOT NULL,
    plugin_version TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('enabled', 'disabled', 'health_quarantine')),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    PRIMARY KEY (workspace_id, plugin_id, plugin_version),
    FOREIGN KEY (plugin_id, plugin_version)
        REFERENCES plugin_versions(plugin_id, version) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX plugin_workspace_one_enabled_idx
    ON plugin_workspace_versions(workspace_id, plugin_id)
    WHERE state = 'enabled';

CREATE TABLE plugin_grant_revisions (
    plugin_id TEXT NOT NULL,
    plugin_version TEXT NOT NULL,
    component_id TEXT NOT NULL,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('global', 'workspace')),
    scope_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    grant_set_digest TEXT NOT NULL CHECK (length(grant_set_digest) = 64 AND grant_set_digest NOT GLOB '*[^0-9a-f]*'),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (plugin_id, plugin_version, component_id, scope_type, scope_id, revision),
    FOREIGN KEY (plugin_id, plugin_version, component_id)
        REFERENCES plugin_components(plugin_id, plugin_version, component_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE plugin_capability_grants (
    plugin_id TEXT NOT NULL,
    plugin_version TEXT NOT NULL,
    component_id TEXT NOT NULL,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    capability_name TEXT NOT NULL,
    resource_json TEXT NOT NULL CHECK (json_valid(resource_json)),
    PRIMARY KEY (
        plugin_id, plugin_version, component_id, scope_type, scope_id,
        revision, capability_name, resource_json
    ),
    FOREIGN KEY (plugin_id, plugin_version, component_id, scope_type, scope_id, revision)
        REFERENCES plugin_grant_revisions(
            plugin_id, plugin_version, component_id, scope_type, scope_id, revision
        ) ON DELETE RESTRICT,
    FOREIGN KEY (plugin_id, plugin_version, component_id, capability_name)
        REFERENCES plugin_capability_requests(
            plugin_id, plugin_version, component_id, capability_name
        ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE plugin_settings (
    plugin_id TEXT NOT NULL,
    plugin_version TEXT NOT NULL,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('global', 'workspace', 'user', 'agent')),
    scope_id TEXT NOT NULL,
    config_version INTEGER NOT NULL CHECK (config_version > 0),
    config_json TEXT NOT NULL CHECK (json_valid(config_json)),
    schema_digest TEXT NOT NULL CHECK (length(schema_digest) = 64 AND schema_digest NOT GLOB '*[^0-9a-f]*'),
    settings_digest TEXT NOT NULL CHECK (length(settings_digest) = 64 AND settings_digest NOT GLOB '*[^0-9a-f]*'),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (plugin_id, plugin_version, scope_type, scope_id, config_version),
    FOREIGN KEY (plugin_id, plugin_version)
        REFERENCES plugin_versions(plugin_id, version) ON DELETE RESTRICT
) STRICT;

CREATE TABLE plugin_failures (
    id INTEGER PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    plugin_version TEXT NOT NULL,
    component_id TEXT NOT NULL,
    invocation_id TEXT NOT NULL UNIQUE,
    failure_class TEXT NOT NULL CHECK (failure_class IN (
        'plugin_fault', 'host_fault', 'policy_denied', 'cancelled', 'resource_exhaustion'
    )),
    counted INTEGER NOT NULL CHECK (counted IN (0, 1)),
    occurred_at INTEGER NOT NULL CHECK (occurred_at >= 0),
    FOREIGN KEY (workspace_id, plugin_id, plugin_version)
        REFERENCES plugin_workspace_versions(workspace_id, plugin_id, plugin_version) ON DELETE RESTRICT,
    FOREIGN KEY (plugin_id, plugin_version, component_id)
        REFERENCES plugin_components(plugin_id, plugin_version, component_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX plugin_staged_identity_idx
    ON plugin_staged_packages(plugin_id, plugin_version, created_at);
CREATE INDEX plugin_failures_window_idx
    ON plugin_failures(workspace_id, plugin_id, plugin_version, counted, occurred_at);
CREATE INDEX plugin_settings_latest_idx
    ON plugin_settings(plugin_id, plugin_version, scope_type, scope_id, config_version DESC);

CREATE TRIGGER plugin_staged_identity_immutable
BEFORE UPDATE OF
    plugin_id, plugin_version, runtime_type, quarantine_path, package_digest,
    manifest_digest, artifact_digest, manifest_json, file_hashes_json,
    source_type, requested_by_provider, requested_by_subject, created_at
ON plugin_staged_packages
BEGIN
    SELECT RAISE(ABORT, 'staged plugin identity is immutable');
END;

CREATE TRIGGER plugin_version_identity_immutable
BEFORE UPDATE OF
    plugin_id, version, runtime_type, artifact_path, package_digest,
    manifest_digest, artifact_digest, manifest_json, installed_at
ON plugin_versions
BEGIN
    SELECT RAISE(ABORT, 'installed plugin identity is immutable');
END;
