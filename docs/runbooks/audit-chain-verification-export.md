# Runbook: audit-chain verification and export

## Purpose

Prove the audit log is intact (hash chain verifies end-to-end) and produce a
redacted export suitable for incident review or external auditors.

## Background

Every audit event is hash-linked: each record stores `previous_hash` and
`event_hash`, computed over the canonical event bytes. Verification recomputes
every link from genesis. The chain is append-only — corrections are new events,
never edits. A single broken link fails the whole verification; there is no
"verify up to the break" mode, because a break means the log is not trustworthy
past that point.

## Procedure

### Verify

```
lumen audit verify
```

- Exit 0: the full chain verifies.
- Non-zero with `AuditIntegrity` error: the chain is broken. **Stop.** Do not
  run further mutations until the break is understood (see Failure posture).
  The tamper-evidence test (`audit_verify_rejects_a_tampered_persisted_event`)
  proves a single modified payload is caught.

For a quick health signal without the full walk, `lumen health` includes the
chain check.

### Export (redacted)

1. Page the log out of the database (read-only; never export the live `<db>`
   file itself — it contains secret *references* and operational tables):
   ```
   lumen audit list --after 0 --limit 200 > audit-page-1.json
   ```
   Repeat with increasing `--after` until a page returns fewer than `limit`
   rows. `sequence` values must be contiguous across pages — any gap is itself
   a finding (report it; do not "fill" it).

2. Redact before sharing. The export contains payloads that may reference
   file paths, prompts, and principal names. Apply the same secret scan the
   support bundle uses:
   ```
   lumen support bundle --out /tmp/audit-export --audit-only
   ```
   The bundle's secret scan **blocks** export if it finds anything matching
   secret patterns; a blocked export is a finding, not an inconvenience —
   investigate before overriding (there is no override flag; remove or
   explicitly allowlist the content first).

   Share only the generated support bundle. Delete the raw
   `audit-page-*.json` files before sharing; they are unredacted and must
   not leave the machine.

3. Record the export itself as an audit event (who exported what range,
   when, and the export's own digest), so the export is part of the chain it
   describes.

## Verification

- `lumen audit verify` exits 0 **after** the export. The export appends its
  own audit event (step 3), so verification must include that event: the
  chain verifies with the export event present, and the recorded export
  digest matches the exported bytes. Any other post-export mutation is an
  error — something wrote to the log outside the append path; escalate.
- The exported pages cover a contiguous `sequence` range with no gaps.
- The export digest recorded in the audit log matches the exported bytes.

## Failure posture

- **Broken chain:** quarantine the database file (copy it aside, read-only),
  stop the runtime (see `emergency-stop.md`), and escalate. Do not restore
  from backup over the broken chain — restore to a *new* path and diff the
  two chains to find the divergence point first.
- **Gap in sequence:** treat as tampering until proven otherwise. The
  append path never skips a sequence; a gap means rows were deleted or the
  export was filtered. Re-export directly from the database and compare.
