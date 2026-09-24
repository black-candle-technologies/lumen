-- 0023_execution_reservations.sql: durable persistence for the execution
-- budget lifecycle (reserve → dispatch → settle/release), the dispatch-side
-- half of the Phase 1 authority kernel. kernel_executions records one row
-- per authorized action: the atomic hold taken at authorize time, then
-- exactly one terminal transition — settled (the action dispatched, measured
-- actuals recorded as the durable debit receipt) or released (dispatch never
-- happened, or failed before any effect). The row is the authority the
-- in-memory ledger rehydrates from at boot; the guard trigger enforces the
-- held -> settled | released state machine in SQL.

CREATE TABLE kernel_executions(
 id TEXT PRIMARY KEY CHECK(length(id)>0),
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 lease_id TEXT NOT NULL REFERENCES kernel_leases(lease_id) ON DELETE RESTRICT,
 action_id TEXT NOT NULL CHECK(length(action_id)>0),
 held_json TEXT NOT NULL CHECK(json_valid(held_json)),
 state TEXT NOT NULL CHECK(state IN('held','settled','released')),
 idempotency_key TEXT NOT NULL CHECK(length(idempotency_key)>0),
 created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
 completed_at_ms INTEGER NULL CHECK(completed_at_ms IS NULL OR completed_at_ms>=0),
 actual_json TEXT NULL CHECK(actual_json IS NULL OR json_valid(actual_json)),
 UNIQUE(workspace_id, idempotency_key)
) STRICT;
CREATE TRIGGER kernel_executions_update_guard BEFORE UPDATE ON kernel_executions
WHEN (
 NEW.id!=OLD.id
 OR NEW.workspace_id!=OLD.workspace_id
 OR NEW.lease_id!=OLD.lease_id
 OR NEW.action_id!=OLD.action_id
 OR NEW.held_json!=OLD.held_json
 OR NEW.idempotency_key!=OLD.idempotency_key
 OR NEW.created_at_ms!=OLD.created_at_ms
 OR NEW.state NOT IN('held','settled','released')
 OR (OLD.state!='held' AND NEW.state!=OLD.state)
 OR (OLD.state='held' AND NEW.state='held')
 OR (NEW.state='settled' AND (NEW.actual_json IS NULL OR NEW.completed_at_ms IS NULL))
 OR (NEW.state='released' AND (NEW.actual_json IS NOT NULL OR NEW.completed_at_ms IS NULL))
 OR (NEW.state='held' AND (NEW.actual_json IS NOT NULL OR NEW.completed_at_ms IS NOT NULL))
)
BEGIN SELECT RAISE(ABORT,'illegal execution reservation mutation');END;
CREATE TRIGGER kernel_executions_no_delete BEFORE DELETE ON kernel_executions BEGIN SELECT RAISE(ABORT,'execution reservations are immutable');END;
CREATE INDEX kernel_executions_state_idx ON kernel_executions(workspace_id, state);
CREATE INDEX kernel_executions_action_idx ON kernel_executions(workspace_id, action_id);
CREATE INDEX kernel_executions_lease_idx ON kernel_executions(workspace_id, lease_id);

-- Recorded budget caps per lease (first write wins): the caps snapshot boot
-- reconciliation rehydrates the in-memory ledger from. Immutable.
CREATE TABLE kernel_lease_caps(
 lease_id TEXT PRIMARY KEY REFERENCES kernel_leases(lease_id) ON DELETE RESTRICT,
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 caps_json TEXT NOT NULL CHECK(json_valid(caps_json)),
 recorded_at_ms INTEGER NOT NULL CHECK(recorded_at_ms>=0)
) STRICT;
CREATE TRIGGER kernel_lease_caps_no_update BEFORE UPDATE ON kernel_lease_caps BEGIN SELECT RAISE(ABORT,'lease caps are immutable');END;
CREATE TRIGGER kernel_lease_caps_no_delete BEFORE DELETE ON kernel_lease_caps BEGIN SELECT RAISE(ABORT,'lease caps are immutable');END;
