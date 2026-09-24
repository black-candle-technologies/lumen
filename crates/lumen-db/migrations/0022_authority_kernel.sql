-- 0022_authority_kernel.sql: durable persistence for the Phase 1 authority
-- kernel (leases, revocations, nonces, one-shot uses, budget ledger, and the
-- hash-chained audit log). All kernel records are append-only: signed leases,
-- revocations, debit receipts, and audit events can never be updated or
-- deleted (triggers abort such writes). Budget accounts and reservations are
-- live balance-sheet rows; their mutations are constrained by guard triggers
-- (caps immutable, state machine active->released only).

-- ---------------------------------------------------------------------------
-- Leases: signed authority documents. Immutable once written.
-- ---------------------------------------------------------------------------
CREATE TABLE kernel_leases(
 lease_id TEXT PRIMARY KEY,
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 parent_id TEXT NULL REFERENCES kernel_leases(lease_id) ON DELETE RESTRICT,
 subject TEXT NOT NULL CHECK(length(subject)>0),
 issuer_key_id TEXT NOT NULL CHECK(length(issuer_key_id)>0),
 issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms>=0),
 protocol_version INTEGER NOT NULL CHECK(protocol_version>0),
 scope_digest TEXT NOT NULL CHECK(length(scope_digest)=64 AND scope_digest NOT GLOB '*[^0-9a-f]*'),
 scope_json TEXT NOT NULL CHECK(json_valid(scope_json)),
 limits_json TEXT NOT NULL CHECK(json_valid(limits_json)),
 depth INTEGER NOT NULL CHECK(depth>=0),
 depth_limit INTEGER NOT NULL CHECK(depth_limit>0),
 lease_nonce TEXT NOT NULL CHECK(length(lease_nonce)>0),
 signature TEXT NOT NULL CHECK(length(signature)=128 AND signature NOT GLOB '*[^0-9a-f]*'),
 document_digest TEXT NOT NULL CHECK(length(document_digest)=64 AND document_digest NOT GLOB '*[^0-9a-f]*'),
 created_at INTEGER NOT NULL CHECK(created_at>=0),
 UNIQUE(workspace_id, lease_nonce)
) STRICT;
CREATE TRIGGER kernel_leases_no_update BEFORE UPDATE ON kernel_leases BEGIN SELECT RAISE(ABORT,'kernel leases are immutable');END;
CREATE TRIGGER kernel_leases_no_delete BEFORE DELETE ON kernel_leases BEGIN SELECT RAISE(ABORT,'kernel leases are immutable');END;
CREATE INDEX kernel_leases_parent_idx ON kernel_leases(parent_id);
CREATE INDEX kernel_leases_subject_idx ON kernel_leases(workspace_id, subject);

-- ---------------------------------------------------------------------------
-- Revocations: append-only. Revoking a parent transitively invalidates
-- descendants at validation time; no cascade writes are needed.
-- ---------------------------------------------------------------------------
CREATE TABLE kernel_revocations(
 lease_id TEXT PRIMARY KEY REFERENCES kernel_leases(lease_id) ON DELETE RESTRICT,
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 revoked_at_ms INTEGER NOT NULL CHECK(revoked_at_ms>=0),
 reason TEXT NOT NULL
) STRICT;
CREATE TRIGGER kernel_revocations_no_update BEFORE UPDATE ON kernel_revocations BEGIN SELECT RAISE(ABORT,'revocations are immutable');END;
CREATE TRIGGER kernel_revocations_no_delete BEFORE DELETE ON kernel_revocations BEGIN SELECT RAISE(ABORT,'revocations are immutable');END;

-- ---------------------------------------------------------------------------
-- Nonces: replay protection. Insert-only; expired rows may be purged by
-- DELETE (enforced in code: purge only expires_at_ms < now). UPDATE blocked.
-- ---------------------------------------------------------------------------
CREATE TABLE kernel_nonces(
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 nonce TEXT NOT NULL CHECK(length(nonce)>0),
 used_at_ms INTEGER NOT NULL CHECK(used_at_ms>=0),
 expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>=0),
 PRIMARY KEY(workspace_id, nonce)
) STRICT;
CREATE TRIGGER kernel_nonces_no_update BEFORE UPDATE ON kernel_nonces BEGIN SELECT RAISE(ABORT,'nonces are immutable');END;
CREATE INDEX kernel_nonces_expiry_idx ON kernel_nonces(workspace_id, expires_at_ms);

-- ---------------------------------------------------------------------------
-- One-shot uses: single-use lease consumption. Immutable once recorded.
-- ---------------------------------------------------------------------------
CREATE TABLE kernel_one_shot_uses(
 lease_id TEXT PRIMARY KEY REFERENCES kernel_leases(lease_id) ON DELETE RESTRICT,
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 consumed_at_ms INTEGER NOT NULL CHECK(consumed_at_ms>=0)
) STRICT;
CREATE TRIGGER kernel_one_shot_uses_no_update BEFORE UPDATE ON kernel_one_shot_uses BEGIN SELECT RAISE(ABORT,'one-shot uses are immutable');END;
CREATE TRIGGER kernel_one_shot_uses_no_delete BEFORE DELETE ON kernel_one_shot_uses BEGIN SELECT RAISE(ABORT,'one-shot uses are immutable');END;

-- ---------------------------------------------------------------------------
-- Budget accounts: live balance sheet per lease. Caps are immutable after
-- insert; reserved_out/consumed move only via the transactional
-- reserve/debit/release paths. DELETE blocked.
-- ---------------------------------------------------------------------------
CREATE TABLE kernel_budget_accounts(
 lease_id TEXT PRIMARY KEY REFERENCES kernel_leases(lease_id) ON DELETE RESTRICT,
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 caps_json TEXT NOT NULL CHECK(json_valid(caps_json)),
 reserved_out_json TEXT NOT NULL CHECK(json_valid(reserved_out_json)),
 consumed_json TEXT NOT NULL CHECK(json_valid(consumed_json)),
 updated_at INTEGER NOT NULL CHECK(updated_at>=0)
) STRICT;
CREATE TRIGGER kernel_budget_accounts_update_guard BEFORE UPDATE ON kernel_budget_accounts
WHEN (NEW.lease_id!=OLD.lease_id OR NEW.workspace_id!=OLD.workspace_id OR NEW.caps_json!=OLD.caps_json)
BEGIN SELECT RAISE(ABORT,'budget caps are immutable');END;
CREATE TRIGGER kernel_budget_accounts_no_delete BEFORE DELETE ON kernel_budget_accounts BEGIN SELECT RAISE(ABORT,'budget accounts are immutable');END;

-- ---------------------------------------------------------------------------
-- Reservations: holds carved out of a parent account for a child lease.
-- Identity columns immutable; state machine active -> released only;
-- held/consumed move only via the transactional debit path.
-- ---------------------------------------------------------------------------
CREATE TABLE kernel_reservations(
 reservation_id TEXT PRIMARY KEY,
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 parent_lease_id TEXT NOT NULL REFERENCES kernel_leases(lease_id) ON DELETE RESTRICT,
 child_lease_id TEXT NOT NULL REFERENCES kernel_leases(lease_id) ON DELETE RESTRICT,
 held_json TEXT NOT NULL CHECK(json_valid(held_json)),
 consumed_json TEXT NOT NULL CHECK(json_valid(consumed_json)),
 state TEXT NOT NULL CHECK(state IN('active','released')),
 created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
 released_at_ms INTEGER NULL CHECK(released_at_ms IS NULL OR released_at_ms>=0)
) STRICT;
CREATE TRIGGER kernel_reservations_update_guard BEFORE UPDATE ON kernel_reservations
WHEN (
 NEW.reservation_id!=OLD.reservation_id
 OR NEW.workspace_id!=OLD.workspace_id
 OR NEW.parent_lease_id!=OLD.parent_lease_id
 OR NEW.child_lease_id!=OLD.child_lease_id
 OR NEW.created_at_ms!=OLD.created_at_ms
 OR NEW.state NOT IN('active','released')
 OR (OLD.state='released' AND NEW.state='active')
 OR (NEW.state='released' AND NEW.released_at_ms IS NULL)
 OR (NEW.state='active' AND NEW.released_at_ms IS NOT NULL)
)
BEGIN SELECT RAISE(ABORT,'illegal reservation mutation');END;
CREATE TRIGGER kernel_reservations_no_delete BEFORE DELETE ON kernel_reservations BEGIN SELECT RAISE(ABORT,'reservations are immutable');END;
CREATE INDEX kernel_reservations_child_idx ON kernel_reservations(child_lease_id);
CREATE INDEX kernel_reservations_parent_idx ON kernel_reservations(parent_lease_id, state);

-- ---------------------------------------------------------------------------
-- Debits: idempotent spend records against a reservation. The idempotency
-- key is the primary key: a retried debit with the same key is a no-op.
-- Immutable.
-- ---------------------------------------------------------------------------
CREATE TABLE kernel_debits(
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 idempotency_key TEXT NOT NULL CHECK(length(idempotency_key)>0),
 reservation_id TEXT NOT NULL REFERENCES kernel_reservations(reservation_id) ON DELETE RESTRICT,
 amounts_json TEXT NOT NULL CHECK(json_valid(amounts_json)),
 debited_at_ms INTEGER NOT NULL CHECK(debited_at_ms>=0),
 PRIMARY KEY(workspace_id, idempotency_key)
) STRICT;
CREATE TRIGGER kernel_debits_no_update BEFORE UPDATE ON kernel_debits BEGIN SELECT RAISE(ABORT,'debits are immutable');END;
CREATE TRIGGER kernel_debits_no_delete BEFORE DELETE ON kernel_debits BEGIN SELECT RAISE(ABORT,'debits are immutable');END;
CREATE INDEX kernel_debits_reservation_idx ON kernel_debits(reservation_id);

/* Direct debits against a lease's own caps (root-lease spend), kept separate
   from reservation debits so idempotency keys cannot collide across kinds. */
CREATE TABLE kernel_lease_debits(
    workspace_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    lease_id_link TEXT NOT NULL,
    amounts_json TEXT NOT NULL,
    debited_at_ms INTEGER NOT NULL,
    PRIMARY KEY(workspace_id,idempotency_key),
    FOREIGN KEY(lease_id_link) REFERENCES kernel_leases(lease_id)
);
CREATE TRIGGER kernel_lease_debits_no_update BEFORE UPDATE ON kernel_lease_debits BEGIN SELECT RAISE(ABORT,'lease debits are immutable');END;
CREATE TRIGGER kernel_lease_debits_no_delete BEFORE DELETE ON kernel_lease_debits BEGIN SELECT RAISE(ABORT,'lease debits are immutable');END;
CREATE INDEX kernel_lease_debits_lease_idx ON kernel_lease_debits(workspace_id,lease_id_link);

-- ---------------------------------------------------------------------------
-- Audit events: the hash-chained, append-only kernel audit log.
-- seq is a global rowid; per-workspace chains are linked by prev_hash.
-- ---------------------------------------------------------------------------
CREATE TABLE kernel_audit_events(
 seq INTEGER PRIMARY KEY,
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 prev_hash TEXT NOT NULL CHECK(length(prev_hash)=64 AND prev_hash NOT GLOB '*[^0-9a-f]*'),
 hash TEXT NOT NULL CHECK(length(hash)=64 AND hash NOT GLOB '*[^0-9a-f]*'),
 action_digest TEXT NOT NULL CHECK(length(action_digest)=64 AND action_digest NOT GLOB '*[^0-9a-f]*'),
 decision TEXT NOT NULL CHECK(length(decision)>0),
 actor TEXT NOT NULL CHECK(length(actor)>0),
 details_json TEXT NOT NULL CHECK(json_valid(details_json)),
 recorded_at INTEGER NOT NULL CHECK(recorded_at>=0)
) STRICT;
CREATE TRIGGER kernel_audit_events_no_update BEFORE UPDATE ON kernel_audit_events BEGIN SELECT RAISE(ABORT,'audit events are immutable');END;
CREATE TRIGGER kernel_audit_events_no_delete BEFORE DELETE ON kernel_audit_events BEGIN SELECT RAISE(ABORT,'audit events are immutable');END;

/* Sequences are gapless per workspace: an insert that skips (or reuses) a
   sequence number fails closed, so a missing event is always detectable. */
CREATE TRIGGER kernel_audit_events_seq_gapless BEFORE INSERT ON kernel_audit_events
BEGIN
    SELECT CASE WHEN NEW.seq != (SELECT COALESCE(MAX(seq),-1)+1 FROM kernel_audit_events WHERE workspace_id=NEW.workspace_id)
    THEN RAISE(ABORT,'audit seq must be gapless per workspace') END;
END;
CREATE UNIQUE INDEX kernel_audit_events_hash_idx ON kernel_audit_events(workspace_id, hash);
CREATE INDEX kernel_audit_events_action_idx ON kernel_audit_events(workspace_id, action_digest);
CREATE INDEX kernel_audit_events_actor_idx ON kernel_audit_events(workspace_id, actor);
CREATE INDEX kernel_audit_events_decision_idx ON kernel_audit_events(workspace_id, decision);
CREATE INDEX kernel_audit_events_time_idx ON kernel_audit_events(workspace_id, recorded_at);

-- ---------------------------------------------------------------------------
-- Audit checkpoints: host-key signatures over chain prefixes. Immutable.
-- ---------------------------------------------------------------------------
CREATE TABLE kernel_audit_checkpoints(
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 seq INTEGER NOT NULL REFERENCES kernel_audit_events(seq) ON DELETE RESTRICT,
 hash TEXT NOT NULL CHECK(length(hash)=64 AND hash NOT GLOB '*[^0-9a-f]*'),
 signature TEXT NOT NULL CHECK(length(signature)=128 AND signature NOT GLOB '*[^0-9a-f]*'),
 key_id TEXT NOT NULL CHECK(length(key_id)>0),
 created_at INTEGER NOT NULL CHECK(created_at>=0),
 PRIMARY KEY(workspace_id, seq)
) STRICT;
CREATE TRIGGER kernel_audit_checkpoints_no_update BEFORE UPDATE ON kernel_audit_checkpoints BEGIN SELECT RAISE(ABORT,'checkpoints are immutable');END;
CREATE TRIGGER kernel_audit_checkpoints_no_delete BEFORE DELETE ON kernel_audit_checkpoints BEGIN SELECT RAISE(ABORT,'checkpoints are immutable');END;
