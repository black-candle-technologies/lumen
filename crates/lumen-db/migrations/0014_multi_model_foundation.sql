CREATE TABLE model_provider_runtime_revisions (
    provider_id TEXT NOT NULL REFERENCES egress_model_providers(provider_id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK (revision > 0), provider_kind TEXT NOT NULL CHECK (provider_kind IN ('openai','anthropic','openai_compatible')),
    endpoint_class TEXT NOT NULL CHECK (endpoint_class IN ('local','remote')), endpoint_url TEXT NOT NULL CHECK (length(endpoint_url) BETWEEN 1 AND 4096),
    local_runtime TEXT CHECK (local_runtime IS NULL OR local_runtime IN ('ollama','llama_cpp','vllm')), enabled INTEGER NOT NULL CHECK (enabled IN (0,1)), credential_secret_ref TEXT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0), PRIMARY KEY (provider_id, revision),
    CHECK ((provider_kind IN ('openai','anthropic') AND endpoint_class='remote' AND local_runtime IS NULL AND credential_secret_ref IS NOT NULL) OR (provider_kind='openai_compatible' AND endpoint_class='local' AND local_runtime IS NOT NULL)),
    CHECK (credential_secret_ref IS NULL OR length(credential_secret_ref)=36)
) STRICT;
CREATE TABLE model_profiles (profile_id TEXT PRIMARY KEY CHECK (length(profile_id) BETWEEN 1 AND 128), provider_id TEXT NOT NULL REFERENCES egress_model_providers(provider_id) ON DELETE RESTRICT, created_at INTEGER NOT NULL CHECK (created_at >= 0), UNIQUE (profile_id, provider_id)) STRICT;
CREATE TABLE model_profile_revisions (
    profile_id TEXT NOT NULL, provider_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK (revision > 0), provider_revision INTEGER NOT NULL CHECK (provider_revision > 0),
    model_name TEXT NOT NULL CHECK (length(model_name) BETWEEN 1 AND 256 AND trim(model_name)=model_name), enabled INTEGER NOT NULL CHECK (enabled IN (0,1)), capabilities_json TEXT NOT NULL CHECK (json_valid(capabilities_json)),
    context_window_tokens INTEGER NOT NULL CHECK (context_window_tokens > 0), trust_zone TEXT NOT NULL CHECK (trust_zone IN ('local_trusted','local_restricted','remote_approved','remote_untrusted')),
    concurrency_limit INTEGER NOT NULL CHECK (concurrency_limit > 0), priority INTEGER NOT NULL, created_at INTEGER NOT NULL CHECK (created_at >= 0), PRIMARY KEY (profile_id, revision),
    FOREIGN KEY (profile_id, provider_id) REFERENCES model_profiles(profile_id, provider_id) ON DELETE RESTRICT,
    FOREIGN KEY (provider_id, provider_revision) REFERENCES model_provider_runtime_revisions(provider_id, revision) ON DELETE RESTRICT
) STRICT;
CREATE INDEX model_provider_runtime_latest_idx ON model_provider_runtime_revisions(provider_id, revision DESC);
CREATE INDEX model_profile_latest_idx ON model_profile_revisions(profile_id, revision DESC);
CREATE INDEX model_profile_provider_idx ON model_profile_revisions(provider_id, provider_revision, enabled, priority);
