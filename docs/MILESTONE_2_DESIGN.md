# Milestone 2: Hardened Local Tools

## Status

Accepted for implementation. The project owner delegated implementation decisions and asked that the roadmap be completed one milestone at a time with incremental commits.

## Goal

Milestone 2 makes local side effects suitable for routine use without changing Lumen's authority model. File writes, secret injection, and process execution must use the same immutable action, capability, policy, approval, dispatch, and audit path established in Milestone 1.

## Scope

Milestone 2 includes:

- Bounded UTF-8 file replacement inside an allowlisted workspace.
- Exact, trusted file-write previews bound to one-shot approvals.
- A Linux process sandbox with explicit, testable kernel guarantees.
- OS credential-store secrets referenced by opaque IDs and injected into one authorized process action.
- End-to-end cancellation, crash recovery, run quotas, and process resource limits.
- A least-privilege Tauri shell and action-specific approval presentation.

It does not include arbitrary binary writes, patch application, deletion, network egress, remote providers, plugin loading, scheduled jobs, or reusable approval grants.

## Chosen Approach

The existing built-in tool path will be hardened incrementally. Lumen will not introduce a container daemon, a second privileged helper, or the Milestone 3 extension protocol to implement built-in tools.

Alternatives considered:

1. **Incremental hardening of built-in executors (chosen).** This preserves one dispatch path, keeps the trusted computing base small, and produces contracts that the later plugin host can reuse.
2. **OCI container execution.** This offers strong isolation but requires a daemon or substantially more lifecycle and image-management machinery than local tools need.
3. **Start the WASM/plugin host early.** This would mix Milestone 2 tool safety with unsettled Milestone 3 extension contracts and would not solve native process execution by itself.

## File-Write Contract

The model may propose `filesystem.write` with a workspace-relative path and complete UTF-8 replacement content. The trusted normalizer reads the current file through the capability-based workspace directory and produces canonical arguments containing:

- The normalized workspace path.
- Whether the target existed.
- The exact prior UTF-8 content, or `null` for a new file.
- The SHA-256 digest and byte length of the prior state.
- The complete replacement content.
- The SHA-256 digest and byte length of the replacement.

The action requires path-scoped `fs.write`. Default policy requires approval for every write. The API returns the canonical arguments, and the approval UI renders the before and after content rather than a generic risk label.

Immediately before replacement, the executor opens the target through the capability directory and recomputes the prior-state digest. A missing, created, removed, changed, non-regular, symlinked, oversized, or non-UTF-8 target causes a conflict and no write. Successful replacement writes a temporary file in the same directory, flushes it, and renames it over the target. The executor never accepts an ambient absolute path.

This is optimistic concurrency control, not a promise to merge concurrent edits. A changed file requires a newly normalized action and a new approval.

## Linux Sandbox

Linux uses the system `bwrap` executable only from fixed administrator-controlled paths. Lumen does not search an action-provided `PATH`. Availability reporting distinguishes the backend from its effective guarantees.

The Linux profile will:

- Create new user, mount, PID, IPC, UTS, cgroup, and network namespaces.
- Disable further user-namespace creation where supported.
- Expose only required runtime directories read-only and the workspace read-only.
- Create private `/proc`, `/dev`, and temporary directories.
- Drop all Linux capabilities.
- Start a new terminal session and die with the Lumen parent.
- Clear the environment and add only validated variables.
- Deny network access by retaining only the isolated loopback namespace.
- Apply inherited CPU, address-space, file-size, open-file, and process-count rlimits before starting the sandbox wrapper.

The profile deliberately does not claim seccomp enforcement in Milestone 2. Bubblewrap supports seccomp, but a correct portable syscall policy is action- and architecture-specific. The platform report lists each guarantee separately so policy and operators do not mistake namespace isolation for seccomp filtering. Kernel-enforced strength requires the complete Milestone 2 baseline profile; otherwise startup fails closed under the default configuration.

The implementation follows bubblewrap's documented requirement to use `--new-session` when a TIOCSTI seccomp filter is absent and `--die-with-parent` for parent-loss cleanup.

## Resource Limits And Cancellation

`SandboxRequest` carries explicit resource limits. Zero or nonsensical limits are rejected before dispatch. Unix process launch applies hard and soft rlimits to the wrapper so the sandboxed command and descendants inherit them.

The run cancellation token is passed through `ExecutorPort` into the process sandbox. Cancellation terminates the process group and records a cancelled outcome. It is not translated into a generic tool failure.

Run budgets add a wall-clock deadline and a cumulative captured-result byte quota to the existing model-turn and action quotas. Quota exhaustion is a terminal, audited run outcome and cannot start another model turn or action.

Startup recovery retains Milestone 1's conservative rule: a reserved or running attempt becomes `unknown`, the run fails, an audit event is appended, and no automatic retry occurs.

## Secret References

`SecretStore` is a narrow port with put, resolve, and delete operations. The production adapter uses the operating system credential store through the Rust `keyring` ecosystem. Tests use an in-memory implementation.

SQL stores only metadata:

- Opaque secret-reference ID.
- Owning workspace.
- Human-readable label.
- Credential-store account identifier.
- Canonical executable scope.
- Permitted environment-variable name.
- Creation and update timestamps.

The CLI writes secret values from standard input so values do not appear in shell history or process arguments. A process proposal may bind a permitted environment name to an opaque reference ID. The normalized action and approval include the reference ID and environment name, never the value.

After final policy and approval checks, the executor verifies workspace, executable, and environment scope against SQL, resolves the credential, and injects it only into that process. Resolution failure denies dispatch. Known injected values are redacted from stdout, stderr, run events, and audit payloads before persistence.

Secret references require `secret.use` capability. Process actions using secrets remain approval-required even if a future policy allows ordinary process execution.

## Desktop Boundary And Approval UX

The Tauri shell remains packaging, not an alternate runtime. It will:

- Remove the sample `greet` command and unrestricted opener plugin.
- Disable the global Tauri JavaScript object.
- Enable only one explicitly named capability for the `main` window.
- Grant no filesystem, shell, process, opener, or remote-source permissions.
- Use a production CSP limited to bundled content, Tauri IPC, and the configured loopback runtime origin.
- Keep development-only Vite origins in `devCsp`, not production CSP.
- Disable remote capability sources.

The shared approval UI recognizes file writes and process actions. File writes show path, prior state, replacement state, hashes, and byte counts. Secret-bearing process actions show reference labels and destination environment names without resolving values in the frontend.

## Persistence And API Changes

An append-only SQLite migration adds secret-reference metadata. Existing action and approval JSON remains the authoritative immutable preview. No plaintext secret column is permitted.

The authenticated API adds a workspace-scoped runtime capability report. It exposes backend name and boolean guarantees, not host-sensitive paths or credentials. The desktop/web surface uses the report for operator visibility only; policy enforcement remains in the runtime.

## Failure Rules

- A changed file fails with conflict and is not overwritten.
- Missing sandbox guarantees deny process dispatch.
- Missing or out-of-scope secret references deny dispatch.
- Secret-store failures do not fall back to environment variables.
- Resource-limit, timeout, and cancellation outcomes remain distinct.
- An uncertain post-dispatch result is `unknown` and is never retried automatically.
- Audit persistence failure before dispatch prevents the side effect.

## Verification

The milestone is complete only when tests demonstrate:

- New-file and replacement previews are exact and fingerprinted.
- Changed targets, symlink escapes, oversized writes, and approval mutation cannot write.
- Linux profile construction includes every declared namespace and lockdown guarantee.
- Runtime capability reports match the active backend.
- Secret values never enter SQL, action JSON, approval JSON, SSE payloads, or audit JSON.
- Secret scope mismatches cannot dispatch.
- Cancellation terminates an in-flight process tree.
- Wall-time, result-byte, CPU, memory, file-size, descriptor, process-count, and output limits fail closed.
- Crash recovery produces `unknown` without retry.
- Tauri configuration has an explicit CSP and contains no opener, shell, filesystem, or process capability.
- Desktop and mobile browser tests render actionable file-write and secret-reference previews.

The final gate is formatting, strict Clippy, all workspace tests, Svelte diagnostics, frontend unit tests, production builds, Playwright desktop/mobile tests, Tauri configuration validation, and diff hygiene.

## References

- [Bubblewrap project and security model](https://github.com/containers/bubblewrap)
- [Bubblewrap command reference](https://manpages.debian.org/testing/bubblewrap/bwrap.1.en.html)
- [Rust keyring crate](https://docs.rs/keyring/latest/keyring/)
- [Tauri capabilities](https://v2.tauri.app/security/capabilities/)
- [Tauri Content Security Policy](https://v2.tauri.app/security/csp/)

