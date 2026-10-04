# Issue 87: provider configuration verification

Implementation baseline: `master` at `161a7033b03dbab0727728ad2e4dd4b85e4bc19c`.
The two architecture comments on issue 87 were read in full. Work is on
`fix/apiint`; master is unchanged. The operator workflow is documented in
[Remote Provider Configuration](../REMOTE_PROVIDERS.md).

## Implementation and review

The change covers scoped provider-purpose OS credential references, audited
pending/ready/revoked states, atomic registration with four independent expected
heads, explicit profile pinning, metadata-only inspection/readiness and a shared
late resolver. Normal runs, planner and scheduled runs use the registered model
port; workers retain their pinned assignment and projection/data-policy gates.
All three remote protocols authenticate through the ordinary runtime after restart.

Changes span `lumen-core` provider/audit types; `lumen-db` registration, audit,
egress and migration helpers; `lumen-integrations` credential/HTTP/protocol and
keyring handling; `lumen-control-plane` materialization; and `lumen-cli`
configuration, commands, composition, health, redaction and support export.
Migration `0032_provider_configuration.sql` preserves historical provider/profile,
worker, routing and artifact foreign keys and adds ownership/reference metadata.

The architecture's existing worker generation/usage limitation was explicitly
fixed and tested. The lazy adapter also rechecks the exact remote egress snapshot
after projection acceptance, preventing a queued worker from using a changed
destination or policy. No live provider-management HTTP API was added; the specified
offline owner-lock contract remains authoritative. Registered selection requires
`streaming=false`; legacy loopback/Ollama behavior is preserved, while legacy remote
startup requires explicit migration.

Self-review covered the full diff, credential/account purpose separation, ownership,
current-head checks, four-head CAS rollback, endpoint binding, relative URL joins,
TLS/no-proxy/no-redirect behavior, cancellation/response limits, output reflection,
safe audit fields, store errors, metadata-only commands and retained key copies.
Provider keys are never hashed into audit payloads. The host redactor retains known
key copies for later scrubbing; this is not a claim of complete HTTP/OS zeroization
or detection of arbitrary secret transformations. Revocation blocks subsequent
admissions and cannot unsend an admitted request.

## Commands and results

Final results unless otherwise stated:

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS on the native Windows checkout |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | PASS in WSL Ubuntu |
| `cargo test --workspace --all-features` | FAIL at the existing dedicated KVM integration gate: 8 failed, 4 ignored; the ordinary WSL user is not its required root runner |
| `cargo test --workspace --all-features -- --skip kvm_` | PASS in WSL; excludes only the named dedicated KVM cases |
| `cargo test -p lumen-cli --lib provider` | PASS: 19 cases, including all three protocol restart paths, tool/approval/result/final sequence, planner, scheduler, remote and local workers, stale/denied routes, reference state, reflected values and support export |
| `cargo test -p lumen-db --test provider_configuration` | PASS: 8 cases, including populated 0031 upgrade, failed upgrade with no serving handle, scope/purpose separation, independent counters, concurrent CAS and per-insert/audit rollback |
| `cargo test -p lumen-integrations --test provider_authentication --test provider_proxy_environment` | PASS: 4 verified-TLS transport cases plus 1 isolated environment-proxy case |
| `cargo test -p lumen-server --test kernel_authority_pipeline` | PASS: 20 cases |
| `cargo check -p lumen-cli` | FAIL on native Windows in unchanged `lumen-core/src/pi_boundary.rs`: UnixListener/UnixStream, Unix networking and libc getuid are Unix-only |
| `git diff --check` | PASS |

WSL Cargo version was `1.97.0`. The Linux source copy excluded the user's untracked
`lumen.toml`, `.git`, `target` and `node_modules`. Linux checks used:

```sh
CARGO_TARGET_DIR=/home/laneb/.cache/lumen-apiint-target
CARGO_BUILD_JOBS=2
CARGO_PROFILE_DEV_DEBUG=0
```

The workspace test command used a temporary local Cargo target runner. It executes
only `lumen_sandboxd-*` unit-test binaries as WSL root because their pinned-file
`linkat(AT_EMPTY_PATH)` proof requires privileges; all other test binaries run as
the ordinary user. The same unit test fails unprivileged and passes privileged,
and the full sandboxd unit suite passes (152 cases). The runner's contents were:

```sh
#!/bin/sh
case "$1" in
  */lumen_sandboxd-*)
    exec /mnt/c/Windows/System32/wsl.exe -d Ubuntu -u root \
      --cd /home/laneb/lumen-apiint --exec "$@"
    ;;
  *) exec "$@" ;;
esac
```

For workspace tests, it was selected with
`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=/home/laneb/lumen-apiint-test-runner.sh`.
It does not elevate the `kvm-*` integration executable or provision microVMs.
`/dev/kvm` is present in this WSL environment, but the required guest fixture is
unconfigured and Firecracker/jailer were not found in the checked root PATH.
The KVM file directs operators to the dedicated `scripts/sandbox/kvm-runner.sh`
environment. Its gate was neither weakened nor reported as passing.

During development, wider runs caught old hardcoded migration counts, a restart
test snapshot taken before scheduler shutdown finished its audit write, and an
audit-failure test that deleted FK-referenced audit history before reconnecting.
Counts now include 0032, the restart snapshot waits for drain, and the audit-failure
fixture uses an insert-failure trigger to preserve its post-commit failure assertion
without contradicting the new startup foreign-key integrity guard.

All provider requests were hermetic: counting fake stores and local HTTPS fixtures
with a trusted test CA and explicit test hostname mapping. Production TLS validation,
redirect/proxy policy and endpoint validation were retained. No real provider key,
OS credential mutation or paid model request was used in these tests. A real-vendor
smoke test remains optional and requires explicit operator authorization as described
in the guide.
