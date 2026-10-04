CREATE TABLE model_provider_runtime_revisions_new (
    provider_id TEXT NOT NULL REFERENCES egress_model_providers(provider_id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK(revision > 0),
    provider_kind TEXT NOT NULL CHECK(provider_kind IN ('openai','anthropic','openai_compatible')),
    endpoint_class TEXT NOT NULL CHECK(endpoint_class IN ('local','remote')),
    endpoint_url TEXT NOT NULL CHECK(length(endpoint_url) BETWEEN 1 AND 4096),
    local_runtime TEXT CHECK(local_runtime IS NULL OR local_runtime IN ('ollama','llama_cpp','vllm')),
    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
    credential_secret_ref TEXT,
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    PRIMARY KEY(provider_id, revision),
    CHECK (
        (endpoint_class='remote'
         AND provider_kind IN ('openai','anthropic','openai_compatible')
         AND local_runtime IS NULL AND credential_secret_ref IS NOT NULL)
        OR
        (endpoint_class='local' AND provider_kind='openai_compatible'
         AND local_runtime IS NOT NULL)
    ),
    CHECK(credential_secret_ref IS NULL OR length(credential_secret_ref)=36)
) STRICT;
INSERT INTO model_provider_runtime_revisions_new
    (provider_id,revision,provider_kind,endpoint_class,endpoint_url,
     local_runtime,enabled,credential_secret_ref,created_at)
SELECT provider_id,revision,provider_kind,endpoint_class,endpoint_url,
       local_runtime,enabled,credential_secret_ref,created_at
FROM model_provider_runtime_revisions;
DROP TABLE model_provider_runtime_revisions;
ALTER TABLE model_provider_runtime_revisions_new RENAME TO model_provider_runtime_revisions;
CREATE INDEX model_provider_runtime_latest_idx
    ON model_provider_runtime_revisions(provider_id, revision DESC);
CREATE TABLE model_provider_owners (
    provider_id TEXT PRIMARY KEY
        REFERENCES egress_model_providers(provider_id) ON DELETE RESTRICT,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    UNIQUE(provider_id, workspace_id)
) STRICT;

CREATE TABLE model_provider_secret_references (
    secret_ref_id TEXT PRIMARY KEY CHECK(length(secret_ref_id) = 36),
    workspace_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    provider_kind TEXT NOT NULL
        CHECK(provider_kind IN ('openai','anthropic','openai_compatible')),
    endpoint_url TEXT NOT NULL CHECK(length(endpoint_url) BETWEEN 1 AND 4096),
    label TEXT NOT NULL CHECK(length(label) BETWEEN 1 AND 128),
    state TEXT NOT NULL CHECK(state IN ('pending','ready','revoked')),
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    updated_at INTEGER NOT NULL CHECK(updated_at >= created_at),
    FOREIGN KEY(provider_id, workspace_id)
        REFERENCES model_provider_owners(provider_id, workspace_id) ON DELETE RESTRICT
) STRICT;
CREATE INDEX model_provider_secret_scope_idx
    ON model_provider_secret_references(workspace_id, provider_id, state);

-- Any FK violation must abort this migration before SQLx records success.
CREATE TEMP TABLE provider_migration_fk_guard(n INTEGER NOT NULL CHECK(n=0));
INSERT INTO provider_migration_fk_guard SELECT COUNT(*) FROM pragma_foreign_key_check;
DROP TABLE provider_migration_fk_guard;
