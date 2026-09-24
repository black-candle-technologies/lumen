# BCT Pi extension (phase-0 spike)

Kernel-mediated tools for the Lumen rebuild's Pi boundary. This is a **stub,
not a security boundary**: it registers `bct.*` tools and serializes every
request to the Lumen kernel over the authenticated local transport
(`lumen-kernel/1` on a Unix socket). All enforcement is repeated kernel-side;
if this extension lies, crashes, or is replaced, actions still cannot bypass
the kernel.

## Tools

| Tool | Effect | Kernel action |
|---|---|---|
| `bct.read_file` | Read a UTF-8 text file (truncated at 64 KiB) | `ActionEnvelope` v1, `file_read` only |

On `allow` the read is performed and returned with the action digest and
audit sequence in `details`. On `deny` the model receives the kernel's reason
code. On `pending` the model is told a human approval is required (VHL in
phase 4 mints the one-shot lease).

## Built-in tool lockdown

Three layers, outermost first:

1. **Process launch**: `pi --mode rpc --no-session --no-builtin-tools` —
   Pi itself never registers `bash`, `read`, `write`, `edit`, `grep`, `find`,
   `ls`, or `powershell` (`packages/coding-agent/src/main.ts`, `noTools:
   "builtin"`).
2. **Extension**: `session_start` calls `pi.setActiveTools(["bct.read_file"])`;
   a `tool_call` handler blocks anything not under `bct.*` (a handler failure
   blocks as a fail-safe).
3. **RPC command path**: a `user_bash` handler returns a replacement result
   for the raw `bash` RPC command, so it can never fall through to local
   execution. The supervisor additionally never sends it.

## Environment (set by the host supervisor)

- `LUMEN_KERNEL_SOCKET` — kernel Unix socket path
- `LUMEN_KERNEL_NONCE` — per-session credential for the kernel transport
- `LUMEN_SESSION_ID` — ephemeral Courier subject for this session
- `LUMEN_LEASE_IDS` — comma-separated lease chain, leaf → root

## Development

```bash
npm run typecheck   # tsc --noEmit against local API stubs
```

Runtime imports (`@earendil-works/pi-coding-agent`, `@earendil-works/pi-ai`)
resolve through Pi's bundled virtual modules; the `types/*.d.ts` stubs are
compile-time only. Pinned Pi source: see `PINNED_PI.md`.
