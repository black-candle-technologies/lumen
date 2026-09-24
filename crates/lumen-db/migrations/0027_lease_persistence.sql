-- 0027_lease_persistence.sql: lease persistence across kernel restarts.
--
-- (1) kernel_key_generations: replace the blanket no-delete trigger with a
--     guarded variant. A delete is permitted only while a purge permit row
--     for that key_id is present in `_kernel_key_purge_permit`. The
--     kernel's purge routine inserts the permit, deletes the generation
--     row, and removes the permit in ONE transaction, so the permit is
--     never visible outside the purging transaction: a crashed purge rolls
--     it back, and it cannot leak onto a reused pooled connection.
--
--     NOTE: the permit table is deliberately NOT a TEMP table. SQLite
--     forbids triggers on main-database tables from referencing TEMP
--     objects ("trigger ... cannot reference objects in database temp"),
--     so a per-connection TEMP permit is unimplementable; the tx-scoped
--     persistent permit is the equivalent mechanism. This stops
--     application-layer accidents; it is not claimed to stop an attacker
--     with raw SQL access. The no-update trigger is unchanged: generation
--     rows stay immutable.
-- (2) kernel_killed_generations: append-only kill-list for compromised
--     generations (compromise response; verification fails closed).
-- (3) kernel_sessions: durable session registry, public parts only. The
--     only allowed mutation is the destroy transition (active 1 -> 0 with
--     destroyed_at_ms set, exactly once); rows are never deleted.

DROP TRIGGER IF EXISTS kernel_key_generations_no_delete;

CREATE TABLE _kernel_key_purge_permit(key_id TEXT PRIMARY KEY);

CREATE TRIGGER kernel_key_generations_guarded_delete
BEFORE DELETE ON kernel_key_generations
BEGIN
  SELECT RAISE(ABORT, 'kernel key generation delete requires purge permit')
  WHERE NOT EXISTS (
    SELECT 1 FROM _kernel_key_purge_permit WHERE key_id = OLD.key_id
  );
END;

-- ---------------------------------------------------------------------------
-- Killed generations: (workspace_id, key_id) -> kill record, append-only.
-- ---------------------------------------------------------------------------
CREATE TABLE kernel_killed_generations(
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 key_id TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('issuer','host')),
 killed_at_ms INTEGER NOT NULL CHECK(killed_at_ms >= 0),
 reason TEXT NOT NULL CHECK(length(reason) > 0),
 -- The operator principal that authorized the kill
 -- (`provider:subject`), durable actor evidence for the kill-list.
 killed_by TEXT NOT NULL CHECK(length(killed_by) > 0),
 PRIMARY KEY(workspace_id, key_id)
) STRICT;

CREATE TRIGGER kernel_killed_generations_no_update
BEFORE UPDATE ON kernel_killed_generations
BEGIN
 SELECT RAISE(ABORT, 'kernel killed generations are append-only');
END;

CREATE TRIGGER kernel_killed_generations_no_delete
BEFORE DELETE ON kernel_killed_generations
BEGIN
 SELECT RAISE(ABORT, 'kernel killed generations are append-only');
END;

-- ---------------------------------------------------------------------------
-- Sessions: (workspace_id, subject) -> public session record.
-- Public material only: the verifying key and liveness, never private keys.
-- ---------------------------------------------------------------------------
CREATE TABLE kernel_sessions(
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 subject TEXT NOT NULL CHECK(length(subject) > 0),
 parent_subject TEXT NULL,
 verifying_key_hex TEXT NOT NULL CHECK(length(verifying_key_hex) = 64
   AND verifying_key_hex NOT GLOB '*[^0-9a-f]*'),
 active INTEGER NOT NULL CHECK(active IN (0, 1)),
 created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
 destroyed_at_ms INTEGER NULL
   CHECK(destroyed_at_ms IS NULL OR destroyed_at_ms >= 0),
 -- Lifecycle consistency, enforced at insert as well as update: a live
 -- row carries no destroy timestamp; a destroyed row carries one that is
 -- not earlier than creation.
 CHECK(
   (active = 1 AND destroyed_at_ms IS NULL)
   OR (active = 0 AND destroyed_at_ms IS NOT NULL
       AND destroyed_at_ms >= created_at_ms)
 ),
 PRIMARY KEY(workspace_id, subject),
 -- Parent linkage integrity: a non-null parent must name a recorded
 -- session in the same workspace. (NULL parents are root sessions and
 -- are not checked, per SQL standard.)
 FOREIGN KEY (workspace_id, parent_subject)
   REFERENCES kernel_sessions(workspace_id, subject)
   ON DELETE RESTRICT
) STRICT;

-- The only allowed mutation is the destroy transition, once: active 1 -> 0
-- with destroyed_at_ms set, every other column unchanged. Anything else
-- (resurrecting a destroyed session, swapping a verifying key, touching
-- timestamps) aborts, so a restart can never resurrect a terminated session.
CREATE TRIGGER kernel_sessions_destroy_only
BEFORE UPDATE ON kernel_sessions
BEGIN
 SELECT RAISE(ABORT, 'kernel sessions: only the destroy transition is allowed')
 WHERE NOT (
   OLD.active = 1 AND NEW.active = 0
   AND OLD.destroyed_at_ms IS NULL AND NEW.destroyed_at_ms IS NOT NULL
   AND OLD.subject = NEW.subject
   AND OLD.workspace_id = NEW.workspace_id
   AND OLD.parent_subject IS NEW.parent_subject
   AND OLD.verifying_key_hex = NEW.verifying_key_hex
   AND OLD.created_at_ms = NEW.created_at_ms
 );
END;

CREATE TRIGGER kernel_sessions_no_delete
BEFORE DELETE ON kernel_sessions
BEGIN
 SELECT RAISE(ABORT, 'kernel sessions are append-only');
END;
