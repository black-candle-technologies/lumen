CREATE TABLE mixed_trust_gate_evaluations(
 evaluation_id TEXT PRIMARY KEY,
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 orchestration_id TEXT NOT NULL,
 graph_revision INTEGER NOT NULL CHECK(graph_revision>0),
 task_node_id TEXT NOT NULL,
 profile_id TEXT NOT NULL,
 profile_revision INTEGER NOT NULL CHECK(profile_revision>0),
 policy_revision INTEGER NOT NULL CHECK(policy_revision>0),
 destination_trust_zone TEXT NOT NULL CHECK(destination_trust_zone IN('local_trusted','local_restricted','remote_approved','remote_untrusted')),
 mixed_trust INTEGER NOT NULL CHECK(mixed_trust IN(0,1)),
 allowed INTEGER NOT NULL CHECK(allowed IN(0,1)),
 decision_digest TEXT NOT NULL CHECK(length(decision_digest)=64 AND decision_digest NOT GLOB '*[^0-9a-f]*'),
 decision_json TEXT NOT NULL CHECK(json_valid(decision_json)),
 projection_id TEXT REFERENCES task_projections(projection_id) ON DELETE RESTRICT,
 projection_digest TEXT CHECK(projection_digest IS NULL OR(length(projection_digest)=64 AND projection_digest NOT GLOB '*[^0-9a-f]*')),
 created_at INTEGER NOT NULL CHECK(created_at>=0),
 CHECK((allowed=1 AND projection_id IS NOT NULL AND projection_digest IS NOT NULL) OR (allowed=0 AND projection_id IS NULL AND projection_digest IS NULL)),
 FOREIGN KEY(orchestration_id,graph_revision,task_node_id) REFERENCES orchestration_task_nodes(orchestration_id,graph_revision,task_node_id) ON DELETE RESTRICT,
 FOREIGN KEY(profile_id,profile_revision) REFERENCES model_profile_revisions(profile_id,revision) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,profile_id,policy_revision) REFERENCES model_data_policy_revisions(workspace_id,profile_id,revision) ON DELETE RESTRICT
) STRICT;
CREATE TRIGGER mixed_trust_gate_no_update BEFORE UPDATE ON mixed_trust_gate_evaluations BEGIN SELECT RAISE(ABORT,'trust gate evaluations are immutable');END;
CREATE TRIGGER mixed_trust_gate_no_delete BEFORE DELETE ON mixed_trust_gate_evaluations BEGIN SELECT RAISE(ABORT,'trust gate evaluations are immutable');END;
CREATE UNIQUE INDEX mixed_trust_gate_projection_idx ON mixed_trust_gate_evaluations(projection_id) WHERE allowed=1;
CREATE INDEX mixed_trust_gate_task_idx ON mixed_trust_gate_evaluations(orchestration_id,graph_revision,task_node_id,created_at);
CREATE TABLE orchestration_recovery_checks(
 check_id TEXT PRIMARY KEY,
 orchestration_id TEXT NOT NULL REFERENCES orchestrations(orchestration_id) ON DELETE CASCADE,
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 ok INTEGER NOT NULL CHECK(ok IN(0,1)),
 report_digest TEXT NOT NULL CHECK(length(report_digest)=64 AND report_digest NOT GLOB '*[^0-9a-f]*'),
 report_json TEXT NOT NULL CHECK(json_valid(report_json)),
 checked_at INTEGER NOT NULL CHECK(checked_at>=0)
) STRICT;
CREATE TABLE orchestration_security_quarantine(
 orchestration_id TEXT PRIMARY KEY REFERENCES orchestrations(orchestration_id) ON DELETE CASCADE,
 check_id TEXT NOT NULL REFERENCES orchestration_recovery_checks(check_id) ON DELETE RESTRICT,
 reason_digest TEXT NOT NULL CHECK(length(reason_digest)=64 AND reason_digest NOT GLOB '*[^0-9a-f]*'),
 created_at INTEGER NOT NULL CHECK(created_at>=0)
) STRICT;
CREATE TRIGGER worker_requires_trust_gate BEFORE INSERT ON worker_attempts
WHEN NOT EXISTS(
 SELECT 1 FROM mixed_trust_gate_evaluations g
 WHERE g.allowed=1
 AND g.workspace_id=NEW.workspace_id
 AND g.orchestration_id=NEW.orchestration_id
 AND g.graph_revision=NEW.graph_revision
 AND g.task_node_id=NEW.task_node_id
 AND g.profile_id=NEW.profile_id
 AND g.profile_revision=NEW.profile_revision
 AND g.policy_revision=NEW.policy_revision
 AND g.projection_id=NEW.projection_id
 AND g.projection_digest=NEW.projection_digest
)
BEGIN SELECT RAISE(ABORT,'mixed trust gate missing or stale');END;
CREATE TRIGGER ce_trust_gate AFTER INSERT ON mixed_trust_gate_evaluations
BEGIN INSERT INTO orchestration_control_events
 SELECT NULL,NEW.workspace_id,NEW.orchestration_id,'trust.gate',
 json_object('evaluation',NEW.evaluation_id,'task',NEW.task_node_id,'profile',NEW.profile_id,'allowed',NEW.allowed,'mixed_trust',NEW.mixed_trust,'digest',NEW.decision_digest),
 NEW.created_at;END;
CREATE TRIGGER ce_quarantine AFTER INSERT ON orchestration_security_quarantine
BEGIN INSERT INTO orchestration_control_events
 SELECT NULL,o.workspace_id,NEW.orchestration_id,'orchestration.quarantined',
 json_object('check',NEW.check_id,'digest',NEW.reason_digest),NEW.created_at
 FROM orchestrations o WHERE o.orchestration_id=NEW.orchestration_id;END;
