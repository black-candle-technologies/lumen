CREATE TABLE worker_artifacts(
    artifact_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    orchestration_id TEXT NOT NULL,
    graph_revision INTEGER NOT NULL CHECK(graph_revision > 0),
    task_node_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES worker_attempts(attempt_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
    artifact_kind TEXT NOT NULL,
    media_type TEXT NOT NULL CHECK(length(media_type) BETWEEN 1 AND 128),
    content BLOB NOT NULL CHECK(length(content) BETWEEN 1 AND 2097152),
    content_hash TEXT NOT NULL CHECK(length(content_hash) = 64 AND content_hash NOT GLOB '*[^0-9a-f]*'),
    classification TEXT NOT NULL CHECK(classification IN('public','workspace','sensitive')),
    compartments_json TEXT NOT NULL CHECK(json_valid(compartments_json)),
    provider_id TEXT NOT NULL,
    provider_revision INTEGER NOT NULL CHECK(provider_revision > 0),
    profile_id TEXT NOT NULL,
    profile_revision INTEGER NOT NULL CHECK(profile_revision > 0),
    reasoning_profile TEXT,
    policy_revision INTEGER NOT NULL CHECK(policy_revision > 0),
    projection_id TEXT NOT NULL REFERENCES task_projections(projection_id) ON DELETE RESTRICT,
    projection_digest TEXT NOT NULL CHECK(length(projection_digest) = 64 AND projection_digest NOT GLOB '*[^0-9a-f]*'),
    tool_action_ids_json TEXT NOT NULL CHECK(json_valid(tool_action_ids_json)),
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    FOREIGN KEY(orchestration_id,graph_revision,task_node_id) REFERENCES orchestration_task_nodes(orchestration_id,graph_revision,task_node_id) ON DELETE RESTRICT,
    FOREIGN KEY(provider_id,provider_revision) REFERENCES model_provider_runtime_revisions(provider_id,revision) ON DELETE RESTRICT,
    FOREIGN KEY(profile_id,profile_revision) REFERENCES model_profile_revisions(profile_id,revision) ON DELETE RESTRICT
) STRICT;
CREATE TABLE artifact_validation_revisions(
    artifact_id TEXT NOT NULL REFERENCES worker_artifacts(artifact_id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK(revision > 0),
    state TEXT NOT NULL CHECK(state IN('accepted','rejected')),
    method TEXT NOT NULL CHECK(length(method) BETWEEN 1 AND 128 AND trim(method)=method),
    validator_provider TEXT NOT NULL,
    validator_subject TEXT NOT NULL,
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    PRIMARY KEY(artifact_id,revision),
    FOREIGN KEY(validator_provider,validator_subject) REFERENCES identities(provider,subject) ON DELETE RESTRICT
) STRICT;
CREATE TABLE worker_attempt_failures(
    attempt_id TEXT PRIMARY KEY REFERENCES worker_attempts(attempt_id) ON DELETE CASCADE,
    failure_class TEXT NOT NULL,
    effect_risk TEXT NOT NULL CHECK(effect_risk IN('no_effect','known_effect','unknown_effect')),
    diagnostic TEXT CHECK(diagnostic IS NULL OR length(diagnostic) <= 1024),
    created_at INTEGER NOT NULL CHECK(created_at >= 0)
) STRICT;
CREATE TABLE worker_retry_reconciliations(
    attempt_id TEXT PRIMARY KEY REFERENCES worker_attempts(attempt_id) ON DELETE CASCADE,
    safe_to_retry INTEGER NOT NULL CHECK(safe_to_retry IN(0,1)),
    reconciled_by_provider TEXT NOT NULL,
    reconciled_by_subject TEXT NOT NULL,
    note TEXT NOT NULL CHECK(length(note) BETWEEN 1 AND 1024),
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    FOREIGN KEY(reconciled_by_provider,reconciled_by_subject) REFERENCES identities(provider,subject) ON DELETE RESTRICT
) STRICT;
CREATE TABLE worker_retry_decisions(
    decision_id TEXT PRIMARY KEY,
    prior_attempt_id TEXT NOT NULL REFERENCES worker_attempts(attempt_id) ON DELETE RESTRICT,
    new_attempt_id TEXT UNIQUE REFERENCES worker_attempts(attempt_id) ON DELETE RESTRICT,
    orchestration_id TEXT NOT NULL,
    graph_revision INTEGER NOT NULL CHECK(graph_revision > 0),
    task_node_id TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN('same_worker','reassign')),
    failure_class TEXT NOT NULL,
    effect_risk TEXT NOT NULL,
    disposition TEXT NOT NULL,
    allowed INTEGER NOT NULL CHECK(allowed IN(0,1)),
    requested_by_provider TEXT NOT NULL,
    requested_by_subject TEXT NOT NULL,
    previous_provider_id TEXT NOT NULL,
    previous_provider_revision INTEGER NOT NULL CHECK(previous_provider_revision > 0),
    previous_profile_id TEXT NOT NULL,
    previous_profile_revision INTEGER NOT NULL CHECK(previous_profile_revision > 0),
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    FOREIGN KEY(orchestration_id,graph_revision,task_node_id) REFERENCES orchestration_task_nodes(orchestration_id,graph_revision,task_node_id) ON DELETE RESTRICT,
    FOREIGN KEY(requested_by_provider,requested_by_subject) REFERENCES identities(provider,subject) ON DELETE RESTRICT
) STRICT;
CREATE TABLE worker_attempt_routing_bindings(
    attempt_id TEXT PRIMARY KEY REFERENCES worker_attempts(attempt_id) ON DELETE CASCADE,
    decision_id TEXT NOT NULL UNIQUE REFERENCES routing_decisions(decision_id) ON DELETE RESTRICT,
    reservation_id TEXT NOT NULL UNIQUE REFERENCES routing_budget_reservations(reservation_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL CHECK(created_at >= 0)
) STRICT;
CREATE INDEX worker_artifact_task_idx ON worker_artifacts(orchestration_id,graph_revision,task_node_id,created_at);
CREATE INDEX artifact_validation_latest_idx ON artifact_validation_revisions(artifact_id,revision DESC);
CREATE INDEX worker_retry_task_idx ON worker_retry_decisions(orchestration_id,graph_revision,task_node_id,created_at);
