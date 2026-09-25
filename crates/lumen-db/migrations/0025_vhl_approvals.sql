-- 0025_vhl_approvals.sql: durable persistence for Phase 4 human authority
-- (VHL approval requests, decisions, and hold-and-release challenges).
--
-- Reuses 0022 tables instead of duplicating them:
--   * attestation-id replay uses kernel_nonces (nonce = attestation id),
--   * single-use lease consumption uses kernel_one_shot_uses,
--   * VHL audit events live in kernel_audit_events.
-- Session private keys are NEVER persisted: the per-session identity vault
-- is kernel memory only (see lumen-core session_identity); the audit trail
-- retains public identities. There is deliberately no sessions table here.

-- ---------------------------------------------------------------------------
-- VHL approval requests: the live state machine
-- Requested -> Decided -> Minted -> Consumed.
--
-- The request body (view_json) is immutable: changed inputs create a new
-- request, never an update. State moves forward only; every other column is
-- set-once or immutable. The BEFORE UPDATE trigger below enforces this in
-- SQL so a buggy host fails closed at the database.
-- ---------------------------------------------------------------------------
CREATE TABLE vhl_approval_requests(
 request_id TEXT PRIMARY KEY,
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 action_digest TEXT NOT NULL CHECK(length(action_digest)=64 AND action_digest NOT GLOB '*[^0-9a-f]*'),
 input_hashes_json TEXT NOT NULL CHECK(json_valid(input_hashes_json)),
 session_subject TEXT NOT NULL CHECK(length(session_subject)>0),
 nonce TEXT NOT NULL CHECK(length(nonce)>0),
 created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
 expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>created_at_ms),
 state TEXT NOT NULL CHECK(state IN ('requested','approved','denied','expired','minted','consumed')),
 view_json TEXT NOT NULL CHECK(json_valid(view_json)),
 decided_at_ms INTEGER NULL CHECK(decided_at_ms IS NULL OR decided_at_ms>=0),
 decided_by TEXT NULL CHECK(decided_by IS NULL OR length(decided_by)>0),
 decision_reason TEXT NULL,
 attestation_id TEXT NULL CHECK(attestation_id IS NULL OR length(attestation_id)>0),
 lease_id TEXT NULL,
 minted_at_ms INTEGER NULL CHECK(minted_at_ms IS NULL OR minted_at_ms>=0),
 consumed_at_ms INTEGER NULL CHECK(consumed_at_ms IS NULL OR consumed_at_ms>=0),
 UNIQUE(workspace_id, nonce),
 /* Like 0022's other authority records, the lease reference is scoped to
    the workspace: the composite FK makes a cross-workspace lease
    association fail closed at the SQL layer instead of letting durable
    approval state point at another tenant's lease. NULL lease_id (no mint
    yet) satisfies the FK, per SQL semantics. */
 FOREIGN KEY(workspace_id, lease_id)
   REFERENCES kernel_leases(workspace_id, lease_id) ON DELETE RESTRICT
 ) STRICT;
CREATE INDEX vhl_approval_requests_subject_idx ON vhl_approval_requests(workspace_id, session_subject);
CREATE INDEX vhl_approval_requests_state_idx ON vhl_approval_requests(workspace_id, state);
CREATE INDEX vhl_approval_requests_digest_idx ON vhl_approval_requests(workspace_id, action_digest);

/* Forward-only state machine + immutable request body, enforced in SQL.
   Legal edges: requested->{approved,denied,expired}, approved->minted,
   minted->consumed. Mutable columns: state, decided_at_ms, decided_by,
   decision_reason, attestation_id, lease_id, minted_at_ms, consumed_at_ms —
   the detail columns are set-once (NULL -> value). */
CREATE TRIGGER vhl_approval_requests_state_guard BEFORE UPDATE ON vhl_approval_requests
BEGIN
    SELECT CASE WHEN NOT (
        (NEW.state = OLD.state) OR
        (OLD.state='requested' AND NEW.state IN ('approved','denied','expired')) OR
        (OLD.state='approved' AND NEW.state='minted') OR
        (OLD.state='minted' AND NEW.state='consumed')
    ) THEN RAISE(ABORT,'vhl request: illegal state transition') END;
    SELECT CASE WHEN NOT (
        OLD.request_id IS NEW.request_id AND
        OLD.workspace_id IS NEW.workspace_id AND
        OLD.action_digest IS NEW.action_digest AND
        OLD.input_hashes_json IS NEW.input_hashes_json AND
        OLD.session_subject IS NEW.session_subject AND
        OLD.nonce IS NEW.nonce AND
        OLD.created_at_ms IS NEW.created_at_ms AND
        OLD.expires_at_ms IS NEW.expires_at_ms AND
        OLD.view_json IS NEW.view_json
    ) THEN RAISE(ABORT,'vhl request: immutable column changed') END;
    SELECT CASE WHEN NOT (
        (OLD.decided_at_ms IS NEW.decided_at_ms OR (OLD.decided_at_ms IS NULL AND NEW.decided_at_ms IS NOT NULL)) AND
        (OLD.decided_by IS NEW.decided_by OR (OLD.decided_by IS NULL AND NEW.decided_by IS NOT NULL)) AND
        (OLD.decision_reason IS NEW.decision_reason OR (OLD.decision_reason IS NULL AND NEW.decision_reason IS NOT NULL)) AND
        (OLD.attestation_id IS NEW.attestation_id OR (OLD.attestation_id IS NULL AND NEW.attestation_id IS NOT NULL)) AND
        (OLD.lease_id IS NEW.lease_id OR (OLD.lease_id IS NULL AND NEW.lease_id IS NOT NULL)) AND
        (OLD.minted_at_ms IS NEW.minted_at_ms OR (OLD.minted_at_ms IS NULL AND NEW.minted_at_ms IS NOT NULL)) AND
        (OLD.consumed_at_ms IS NEW.consumed_at_ms OR (OLD.consumed_at_ms IS NULL AND NEW.consumed_at_ms IS NOT NULL))
    ) THEN RAISE(ABORT,'vhl request: decision column rewritten') END;
    SELECT CASE WHEN NOT (
        (NEW.state='requested') OR
        (NEW.state IN ('approved','denied','expired') AND NEW.decided_at_ms IS NOT NULL AND NEW.decided_by IS NOT NULL) OR
        (NEW.state='minted' AND NEW.lease_id IS NOT NULL AND NEW.minted_at_ms IS NOT NULL) OR
        (NEW.state='consumed' AND NEW.lease_id IS NOT NULL AND NEW.consumed_at_ms IS NOT NULL)
    ) THEN RAISE(ABORT,'vhl request: state missing required detail columns') END;
END;
CREATE TRIGGER vhl_approval_requests_no_delete BEFORE DELETE ON vhl_approval_requests BEGIN SELECT RAISE(ABORT,'vhl approval requests are immutable history');END;

-- ---------------------------------------------------------------------------
-- VHL decisions: append-only record of every decision event. Immutable.
-- ---------------------------------------------------------------------------
CREATE TABLE vhl_decisions(
 id INTEGER PRIMARY KEY,
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 request_id TEXT NOT NULL REFERENCES vhl_approval_requests(request_id) ON DELETE RESTRICT,
 decision TEXT NOT NULL CHECK(decision IN ('approved','denied','expired')),
 approver TEXT NOT NULL CHECK(length(approver)>0),
 attestation_id TEXT NULL,
 reason TEXT NOT NULL,
 decided_at_ms INTEGER NOT NULL CHECK(decided_at_ms>=0)
) STRICT;
CREATE TRIGGER vhl_decisions_no_update BEFORE UPDATE ON vhl_decisions BEGIN SELECT RAISE(ABORT,'vhl decisions are immutable');END;
CREATE TRIGGER vhl_decisions_no_delete BEFORE DELETE ON vhl_decisions BEGIN SELECT RAISE(ABORT,'vhl decisions are immutable');END;
CREATE INDEX vhl_decisions_request_idx ON vhl_decisions(workspace_id, request_id);

-- ---------------------------------------------------------------------------
-- Hold-and-release challenges: the kernel mints the challenge bound to the
-- exact action digest; only the code hash is stored, never the code.
-- The guarded UPDATE allows only: attempts increment, used 0->1,
-- ceremony 0->1. Everything else is immutable.
-- ---------------------------------------------------------------------------
CREATE TABLE vhl_challenges(
 challenge_id TEXT PRIMARY KEY,
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 action_digest TEXT NOT NULL CHECK(length(action_digest)=64 AND action_digest NOT GLOB '*[^0-9a-f]*'),
 code_hash TEXT NOT NULL CHECK(length(code_hash)=64 AND code_hash NOT GLOB '*[^0-9a-f]*'),
 issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms>=0),
 expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>issued_at_ms),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
 used INTEGER NOT NULL DEFAULT 0 CHECK(used IN (0,1)),
 ceremony_complete INTEGER NOT NULL DEFAULT 0 CHECK(ceremony_complete IN (0,1))
) STRICT;
CREATE TRIGGER vhl_challenges_state_guard BEFORE UPDATE ON vhl_challenges
BEGIN
    SELECT CASE WHEN NOT (
        OLD.challenge_id IS NEW.challenge_id AND
        OLD.workspace_id IS NEW.workspace_id AND
        OLD.action_digest IS NEW.action_digest AND
        OLD.code_hash IS NEW.code_hash AND
        OLD.issued_at_ms IS NEW.issued_at_ms AND
        OLD.expires_at_ms IS NEW.expires_at_ms
    ) THEN RAISE(ABORT,'vhl challenge: immutable column changed') END;
    SELECT CASE WHEN NOT (
        NEW.attempts >= OLD.attempts AND
        (NEW.used = OLD.used OR (OLD.used = 0 AND NEW.used = 1)) AND
        (NEW.ceremony_complete = OLD.ceremony_complete OR
         (OLD.ceremony_complete = 0 AND NEW.ceremony_complete = 1 AND NEW.used = 0))
    ) THEN RAISE(ABORT,'vhl challenge: illegal state change') END;
END;
CREATE TRIGGER vhl_challenges_no_delete BEFORE DELETE ON vhl_challenges BEGIN SELECT RAISE(ABORT,'vhl challenges are immutable history');END;
CREATE INDEX vhl_challenges_digest_idx ON vhl_challenges(workspace_id, action_digest);
