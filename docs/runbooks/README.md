# Lumen operator runbooks

Operational procedures for the Lumen control plane. Every procedure below maps
to a real command, API, or stored record in this tree. Where a procedure
depends on a Phase-1/2/5 surface that has not landed in this build, the runbook
says so explicitly instead of inventing commands.

Conventions:

- `lumen` is the thin CLI (`crates/lumen-cli`). It never bypasses policy: every
  mutation it requests goes through the kernel's approval machinery.
- `<data>` is the runtime data directory (`[runtime] data_directory` in
  `lumen.toml`).
- `<db>` is the SQLite database (`[database] path` in `lumen.toml`).
- Dangerous steps require explicit confirmation and are marked **CONFIRM**.
- After any revocation/disablement/rollback, verify with the matching
  `Verification` section. A procedure is not done until verification passes.

| Runbook | Covers |
|---|---|
| [lease-session-revocation](lease-session-revocation.md) | Revoking leases and terminating sessions |
| [orphaned-sandbox-cleanup](orphaned-sandbox-cleanup.md) | Reclaiming sandboxes/runs left behind by crashes |
| [credential-host-key-rotation](credential-host-key-rotation.md) | Rotating the API token, provider credentials, host keys |
| [audit-chain-verification-export](audit-chain-verification-export.md) | Verifying and exporting the audit chain |
| [emergency-stop](emergency-stop.md) | Emergency stop and feature-flag shutdown |
| [db-backup-restore-rollback](db-backup-restore-rollback.md) | Database backup, restore, migration rollback |
| [image-rollback](image-rollback.md) | Rolling back a sandbox guest image |
| [plugin-revocation](plugin-revocation.md) | Revoking a compromised plugin digest |
| [adapter-disablement](adapter-disablement.md) | Disabling a messaging adapter |

Related references: `docs/SECURITY.md` (threat model), `docs/ARCHITECTURE.md`,
`docs/PLUGIN_SYSTEM.md`.
