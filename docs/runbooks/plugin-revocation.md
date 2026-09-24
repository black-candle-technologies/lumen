# Runbook: compromised plugin revocation

## Purpose

Immediately disable a plugin digest suspected of compromise, so it cannot be
installed, enabled, or invoked again — without rewriting any audit history.

## Preconditions

- The plugin id, version, and (ideally) the exact `package_digest` from
  `lumen plugin inspect` or the admission record. Digests only — never "the
  latest version".

## Procedure

1. **Identify the exact digest.** A version string is not enough: revocation
   disables a *digest*, because a version label can be re-pointed but a
   digest cannot.
   ```
   lumen plugin inspect <stage-id>   # or read <data>/plugins/admissions/<digest>.json
   ```

2. **CONFIRM — revoke the digest.**
   ```
   lumen plugin revoke <plugin-id> <version> --reason "<incident reference>"
   ```
   This does two things, in order:
   - Records an immutable revocation in the admission store
     (`<data>/plugins/admissions/<package-digest>.json` gains a `revoked`
     decision; the prior `approved` decision is preserved, not overwritten).
   - Submits the disable request for the running runtime through the
     approval-bound path, so already-enabled copies are disabled by the
     kernel, not by a CLI side-effect.

   From this point on, `lumen plugin enable` / `install` for that digest is
   refused at the CLI gate — even if someone re-submits the same bytes,
   the digest matches the revocation record.

3. **Quarantine the installed bytes** (do not delete yet — forensics):
   the installed package directory under `<data>/plugins/installed/` is
   content-addressed by digest; leave it in place, read-only, until the
   investigation closes. Deleting it now destroys evidence and does not
   improve safety, because the digest is already disabled.

4. **Hunt for prior effects.** Query the audit log for invocations of the
   digest's components and review every granted approval touching it:
   ```
   lumen audit list --after 0 --limit 200   # page through; filter by plugin id
   ```
   Any action the compromised plugin influenced is suspect — approvals it
   triggered, files it wrote, secrets it could have observed.

5. **Rotate anything it could have touched** (`credential-host-key-rotation.md`).

## Verification

- The admission record shows `status: "revoked"` with `revoked_by`,
  `revoked_at`, and `reason`; the original approval decision is still
  present underneath.
- `lumen plugin enable <id> <version>` is refused with `digest_revoked`.
- The runtime no longer lists the version as enabled
  (`plugin_workspace_state` / Plugins page).
- `lumen audit verify` passes — revocation appended records; it did not
  mutate any.

## Failure posture

- **Revocation never rewrites history.** Prior audit records referencing the
  digest stay exactly as they were; the revocation is a new record. If you
  need the past to "not have happened", you need incident response, not
  revocation.
- If the plugin is mid-invocation, revocation does not kill the running
  component — cancel the owning run explicitly (see `emergency-stop.md`
  Level 2). The next invocation is refused.
- A revoked digest stays revoked. Re-enabling requires a *new* submission
  (new bytes → new digest → new admission review). There is no "unrevoke".
