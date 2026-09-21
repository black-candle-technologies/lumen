CREATE TABLE context_sources (
source_id TEXT PRIMARY KEY,
workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
classification TEXT NOT NULL CHECK (
classification IN ('public', 'workspace', 'sensitive', 'secret')
),
compartments_json TEXT NOT NULL CHECK (json_valid(compartments_json)),
provenance_kind TEXT NOT NULL CHECK (
provenance_kind IN (
'user_message', 'file', 'tool_result', 'skill', 'artifact', 'generated'
)
),
provenance_reference TEXT NOT NULL CHECK (
length(provenance_reference) BETWEEN 1 AND 4096
),
content_json TEXT NOT NULL CHECK (json_valid(content_json)),
content_digest TEXT NOT NULL UNIQUE CHECK (
length(content_digest) = 64 AND content_digest NOT GLOB '*[^0-9a-f]*'
),
created_by_provider TEXT NOT NULL,
created_by_subject TEXT NOT NULL,
created_at INTEGER NOT NULL CHECK (created_at >= 0),
FOREIGN KEY (created_by_provider, created_by_subject)
REFERENCES identities(provider, subject) ON DELETE RESTRICT
) STRICT;
CREATE INDEX context_sources_workspace_idx
ON context_sources(workspace_id, classification, source_id);
CREATE TABLE model_data_policy_revisions (
workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
profile_id TEXT NOT NULL REFERENCES model_profiles(profile_id) ON DELETE RESTRICT,
revision INTEGER NOT NULL CHECK (revision > 0),
profile_revision INTEGER NOT NULL CHECK (profile_revision > 0),
trust_zone TEXT NOT NULL CHECK (
trust_zone IN (
'local_trusted', 'local_restricted', 'remote_approved', 'remote_untrusted'
)
),
allowed_data_classes_json TEXT NOT NULL CHECK (json_valid(allowed_data_classes_json)),
allowed_compartments_json TEXT NOT NULL CHECK (json_valid(allowed_compartments_json)),
allow_uncompartmented INTEGER NOT NULL CHECK (allow_uncompartmented IN (0, 1)),
created_at INTEGER NOT NULL CHECK (created_at >= 0),
PRIMARY KEY (workspace_id, profile_id, revision),
FOREIGN KEY (profile_id, profile_revision)
REFERENCES model_profile_revisions(profile_id, revision) ON DELETE RESTRICT
) STRICT;
CREATE INDEX model_data_policy_latest_idx
ON model_data_policy_revisions(workspace_id, profile_id, revision DESC);
CREATE TABLE task_projections (
projection_id TEXT PRIMARY KEY,
workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
task_key TEXT NOT NULL CHECK (
length(task_key) BETWEEN 1 AND 128 AND trim(task_key) = task_key
),
profile_id TEXT NOT NULL,
profile_revision INTEGER NOT NULL CHECK (profile_revision > 0),
policy_revision INTEGER NOT NULL CHECK (policy_revision > 0),
classification TEXT NOT NULL CHECK (
classification IN ('public', 'workspace', 'sensitive')
),
compartments_json TEXT NOT NULL CHECK (json_valid(compartments_json)),
payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
payload_digest TEXT NOT NULL UNIQUE CHECK (
length(payload_digest) = 64 AND payload_digest NOT GLOB '*[^0-9a-f]*'
),
created_at INTEGER NOT NULL CHECK (created_at >= 0),
FOREIGN KEY (profile_id, profile_revision)
REFERENCES model_profile_revisions(profile_id, revision) ON DELETE RESTRICT,
FOREIGN KEY (workspace_id, profile_id, policy_revision)
REFERENCES model_data_policy_revisions(workspace_id, profile_id, revision)
ON DELETE RESTRICT
) STRICT;
CREATE INDEX task_projections_workspace_idx
ON task_projections(workspace_id, created_at, projection_id);
CREATE INDEX task_projections_profile_idx
ON task_projections(profile_id, profile_revision, policy_revision);
CREATE TABLE task_projection_sources (
projection_id TEXT NOT NULL REFERENCES task_projections(projection_id) ON DELETE CASCADE,
ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
source_id TEXT NOT NULL REFERENCES context_sources(source_id) ON DELETE RESTRICT,
source_digest TEXT NOT NULL CHECK (
length(source_digest) = 64 AND source_digest NOT GLOB '*[^0-9a-f]*'
),
PRIMARY KEY (projection_id, ordinal),
UNIQUE (projection_id, source_id)
) STRICT;
