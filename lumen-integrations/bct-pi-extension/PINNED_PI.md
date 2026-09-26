# Pinned Pi source (phase-0 spike)

> Historical build record, not current launch admission. These candidate hashes
> need independent reproduction for the boundary reset. The new PiBridge v2
> extension has different bytes and requires a new reviewed immutable manifest.
> Do not launch it with the unconfined command below; see
> [Phase 0](../../docs/rebuild/phase-0.md).

- Repository: https://github.com/earendil-works/pi
- Commit: `b45597504eeaba1f11a9920a1d1048c361ed4b8e`
- Commit date: 2026-09-23 23:21:15 +0200
- Subject: `feat(durable): export scoped storage conformance suite (#9977)`

## Reproducible build (verified 2026-09-24)

```bash
git clone https://github.com/earendil-works/pi /tmp/pi-spike   # any scratch dir
cd /tmp/pi-spike
git checkout b45597504eeaba1f11a9920a1d1048c361ed4b8e
npm ci --no-audit --no-fund   # frozen: uses the committed package-lock.json
npm run build
```

- `package-lock.json` SHA-256:
  `95dbf4d7aa54eebf235edccd6926efac42fbf4e1c6a92c625c9ac706a8b367f7`
- Build artifact: `packages/coding-agent/dist/bundle/cli.js` (`pi` 0.87.1)
- Artifact SHA-256:
  `e79626f2dd6f94aa45d30f3fa63cd84319a6eefcd150b353cfaf274366926774`

Note: this Pi checkout uses npm workspaces (committed `package-lock.json`).
Do NOT use pnpm here — the repo has no pnpm workspace config at this commit
and a pnpm install produces an incomplete lockfile (missing workspace
packages such as `marked`, breaking the `packages/tui` build).

RPC protocol references (all read at the pinned commit):

- `packages/coding-agent/docs/rpc.md` — RPC mode, framing, lifecycle
- `packages/coding-agent/docs/rpc-commands.md` — stdin commands
- `packages/coding-agent/docs/json.md` — stdout session events
- `packages/coding-agent/docs/extensions.md` — extension API
- `packages/coding-agent/docs/custom-provider.md` — provider registration
- `packages/coding-agent/examples/extensions/permission-gate.ts` — `tool_call` blocking pattern

Built-in tool inventory at the pinned commit
(`packages/coding-agent/src/core/tools/`):

`bash`, `edit`, `find`, `grep`, `ls`, `powershell`, `read`, `write`
(+ `edit-diff`, `file-mutation-queue`, `output-accumulator`, `path-utils`,
`truncate`, `render-utils`, `renderers` — helpers, not tools).
Default-enabled: `read`, `bash`, `edit`, `write`.

Lockdown: `--no-builtin-tools` (`noTools: "builtin"`, see
`packages/coding-agent/src/main.ts` and `src/core/sdk.ts`) prevents all
built-in tools from registering while keeping extension tools.
