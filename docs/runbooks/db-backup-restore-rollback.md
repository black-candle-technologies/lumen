# Runbook: database backup, restore, and migration rollback

## Purpose

Back up the SQLite database safely, restore from backup, and roll back a
failed migration — without ever rewriting audit history.

## Background

- The database is a single SQLite file at `[database] path`. Migrations are
  **forward-only** and transactional; there is no down-migration that
  rewrites history.
- Startup is blocked if the database is newer than the binary or if
  migration verification fails — this is a safety feature, not an error to
  work around.
- Audit payloads are never transformed or deleted in place; corrections are
  appended as new events.

## Procedure

### Backup

1. Stop writes first. Either stop the runtime (`emergency-stop.md`, Level 1)
   or checkpoint through the SQLite backup API. **Never `cp` a live SQLite
   file** — you can copy a torn page.
   ```
   systemctl stop lumen
   sqlite3 <db> "VACUUM INTO '/backups/lumen-<utc-timestamp>.sqlite3';"
   sha256sum /backups/lumen-<utc-timestamp>.sqlite3 > /backups/lumen-<utc-timestamp>.sha256
   ```
2. Record the backup (path, digest, schema version) in your ops log. The
   schema version is the migration count the binary expects — `lumen migrate`
   is idempotent and reports what it applied.

### Restore

1. Stop the runtime.
2. **CONFIRM** — move the current database aside (never delete it; it may
   contain the only copy of recent audit events):
   ```
   mv <db> <db>.pre-restore-<utc-timestamp>
   cp /backups/lumen-<utc-timestamp>.sqlite3 <db>
   sha256sum -c /backups/lumen-<utc-timestamp>.sha256
   ```
3. Verify before starting the runtime:
   ```
   lumen audit verify --config <lumen.toml pointing at restored db>
   ```
   The chain must verify end-to-end on the restored copy. If it does not,
   the backup is bad — do not start the runtime on it.
4. Start the runtime. Its migration check runs automatically; if the backup
   is older than the binary, pending migrations apply forward (this is safe:
   migrations are forward-only by design).

### Migration rollback

There is no automated down-migration, deliberately. If a migration fails or
misbehaves:

1. Stop the runtime immediately.
2. Restore the pre-migration backup (procedure above). The backup taken
   before the upgrade is the rollback.
3. Report the failing migration (name + checksum) — a migration that fails
   verification blocks startup, which is the system protecting you from a
   half-applied schema.

**Rule:** the rollback target is always "the last known-good backup", never
"undo the migration in place". In-place undo risks audit-history rewrites,
which are forbidden.

## Verification

- `lumen audit verify` passes on the restored database.
- `lumen health` passes (config, migrations, workspace bootstrap).
- The pre-restore database file still exists alongside the restored one
  until the restore is proven in production; only then archive it.

## Failure posture

- If the restored chain does not verify, **do not start the runtime**.
  Diff the restored chain against the pre-restore copy to find the
  divergence, and escalate with both digests.
- If no backup exists (new deployment), the recovery path is
  re-initialization: `lumen migrate` on an empty path creates a fresh
  database with an empty audit chain. This is only acceptable if the loss of
  history is explicitly accepted and recorded — it is never a silent default.
