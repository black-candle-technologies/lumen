# BCT Pi extension — proposed PiBridge v2

This untrusted stub registers only `bct.read_file`. It sends typed intent through
Pi's documented RPC extension-dialog subprotocol and renders host-produced output.
It does not read files, spawn processes, open sockets, contact providers, access
environment credentials, create envelopes, choose leases, or hold session keys.

`ctx.ui.input` emits an `extension_ui_request` on stdout. The reserved title is
`lumen.pi-bridge/2`; the placeholder holds the versioned request JSON. The host
must intercept this machine request, bind it to the live child generation, and
return an `extension_ui_response` with the same dialog ID and a JSON reply value.
The inner tool call ID must match too. **This is not a human approval dialog.**
A generic Pi UI is not a supported host for this extension.

Only a completed response with digest, bounded output, known usage, and durable
audit reference returns content. Denial, pending approval, unknown fields/version,
cancellation, timeout, and uncertain completion fail once without local fallback.
The host and kernel repeat all validation; replacing the extension must confer no
authority. OS confinement, not the extension's tool filters, is the boundary.

The shared [PiBridge v2 reply budget](../../crates/lumen-protocol/fixtures/pibridge_reply_budget.v2.json)
permits 1,048,576 decoded UTF-8 output bytes. JSON escaping needs at most six wire
bytes per decoded byte (for example, U+0001 becomes `\u0001`). Both codecs reserve
and enforce 16,384 bytes for the compact JSON envelope with an empty `output_tail`,
including correlation, digests, usage, and audit metadata. The inner reply wire
limit is therefore `6 × 1,048,576 + 16,384 = 6,307,840` UTF-8 bytes. This metadata
allowance provides ample margin over an ordinary completed envelope; both the
wire limit and the requested decoded output limit remain enforced. Both test
suites check their constants against the shared budget fixture.

The host codec is in `crates/lumen-server/src/pi_tool_bridge.rs`. Both reference
supervisors currently reject production launches. Wiring the codec into a confined
real Pi session and reviewing the new immutable extension manifest are still
required; **this package is not operationally admitted**.

The candidate upstream source/build pins in [PINNED_PI.md](PINNED_PI.md) are
historical. The [Phase-0 reset](../../docs/rebuild/phase-0.md) records migration,
owner sign-offs, bypasses, and remaining evidence. v1 fixtures are unchanged.

Development checks:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run typecheck
npm test
```

The local declarations model only the API used by this stub. They are not a
substitute for the mandatory test against pinned upstream Pi declarations and a
real confined Pi runtime. Tests use fake host responses and never launch Pi.
