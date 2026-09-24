# Runbook: sandbox guest image rollback

## Purpose

Restore the previously signed guest image after a bad image promotion, and
pause new sandbox runs until the rollback is verified.

## Current build status

> **Forward-looking.** Signed guest images, `sandboxd`, and the Firecracker
> lifecycle are Phase-2 surfaces. The promotion/rollback scripts
> (`scripts/sandbox/promote.sh`, `sign-image.sh`) land with Phase-2. This
> runbook describes the intended procedure so the workflow exists before the
> tooling does; adapt paths to the Phase-2 layout when it lands.

## Preconditions

- The prior image's **signed digest** (from the promotion log — never "the
  image from last Tuesday"; digests only).
- Operator authority to pause sandbox runs.

## Procedure

1. **Pause new runs.** No new sandbox run may start on the suspect image
   while you investigate:
   ```
   # via the orchestration control API: narrow the control policy, or stop
   # the runtime per emergency-stop.md Level 1 if the exposure is severe
   ```
   In-flight runs on the bad image: let short-lived runs finish; cancel
   long-lived ones explicitly. Do not kill the host mid-run without
   recording why.

2. **CONFIRM — restore the prior signed digest.** The rollback restores the
   exact bytes of the previously signed image; it never "rebuilds from the
   same Dockerfile" (a rebuild is a *new* image with a *new* digest and needs
   its own promotion review):
   ```
   scripts/sandbox/promote.sh --digest <prior-signed-digest> --reason "<incident>"
   ```
   The script verifies the signature on the digest before switching the
   active pointer. If signature verification fails, the switch is refused —
   an unsigned image can never become active, even in an emergency.

3. **Re-verify the image** before unpausing:
   ```
   lumen plugin test --image   # Phase-2: image conformance suite
   scripts/sandbox/kvm-runner.sh --smoke
   ```
   At minimum: boot the image, confirm the expected guest agent answers,
   confirm default-deny egress is in place.

4. **Resume** new runs, then watch the first few runs' audit events for
   anomalies.

## Verification

- The active image digest reported by the sandbox service equals the prior
  signed digest, byte for byte.
- `lumen audit verify` passes (the rollback itself is audit-recorded).
- New sandbox runs start and complete on the restored image.

## Failure posture

- If no prior signed digest is available (the promotion log is missing),
  **do not guess**. Keep runs paused and rebuild the image through the full
  Phase-2 build → sign → promote pipeline; the rebuilt image gets a new
  digest and a fresh promotion review.
- If the suspect image already executed untrusted work, rollback is not
  cleanup: treat it as an incident — preserve the image bytes for forensics,
  rotate any credentials the sandbox could have observed
  (`credential-host-key-rotation.md`), and review the audit trail for
  exfiltration indicators before resuming.
