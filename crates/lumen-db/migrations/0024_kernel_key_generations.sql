-- 0024_kernel_key_generations.sql: record every kernel key generation's
-- public keys. The kernel generates fresh issuer/host Ed25519 keys on each
-- open (private keys live only in memory and are zeroized on drop); the
-- verifying keys are recorded here, keyed by key_id, so that signatures made
-- by retired generations (audit checkpoints, and in future lease documents)
-- remain verifiable after a restart. Key material is public, so this table
-- carries no secrecy requirement — but rows are append-only: a generation's
-- recorded key must never change, otherwise a store tamperer could substitute
-- keys and forge history.

-- ---------------------------------------------------------------------------
-- Key generations: (workspace_id, key_id) -> verifying key, append-only.
-- ---------------------------------------------------------------------------
CREATE TABLE kernel_key_generations(
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 key_id TEXT NOT NULL CHECK(length(key_id)>0),
 role TEXT NOT NULL CHECK(role IN ('issuer','host')),
 verifying_key_hex TEXT NOT NULL CHECK(length(verifying_key_hex)=64
   AND verifying_key_hex NOT GLOB '*[^0-9a-f]*'),
 created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
 PRIMARY KEY(workspace_id, key_id)
);

-- A generation's key material is immutable once recorded.
CREATE TRIGGER kernel_key_generations_no_update
BEFORE UPDATE ON kernel_key_generations
BEGIN
 SELECT RAISE(ABORT, 'kernel key generations are immutable');
END;

CREATE TRIGGER kernel_key_generations_no_delete
BEFORE DELETE ON kernel_key_generations
BEGIN
 SELECT RAISE(ABORT, 'kernel key generations are immutable');
END;
