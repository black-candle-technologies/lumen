# Signal eligibility decision

**Date:** 2026-09-23
**Verdict:** NOT ELIGIBLE — the Signal adapter stays disabled.
**Decided by:** Phase-5 worker, per the design posture ("Signal = conditional
only; unofficial linked-device automation does NOT qualify").

## Requirement

Per the Lumen rebuild design doc (Messaging Agents), Signal support is
committed **only if an official, supported bot or application surface
exists** that is compatible with the security model: credential brokering,
explicit identity mapping, auditability, and the adapter lifecycle
(authenticate → register → ingest → lease-checked mutations → revoke).

## Finding

Signal offers **no official bot API**. Verified 2026-09-23 via web search:

- Signal's own posture prioritizes user privacy over third-party
  integration; there is no supported bot/application surface comparable to
  Discord's application model or WhatsApp's Cloud API.
- The only automation paths are unofficial linked-device clients —
  `signal-cli` / `signal-cli-rest-api` — which register or link a **personal
  phone number** and act as that user. This is exactly the category the
  design excludes: "a personal user account acting as a bot" and
  "reverse-engineered protocols."

## Gap analysis against Lumen's requirements

| Requirement | Unofficial linked-device path | Result |
|---|---|---|
| Credential brokering (no ambient secrets) | A linked device holds the account's identity keys; any process with the `signal-cli` data dir *is* the user | ❌ fails — no scoped bot credential exists |
| Explicit identity mapping, fail closed | The "bot" is indistinguishable from the human's own devices | ❌ fails — sender/recipient identity is the personal account |
| Audit of provider auth lifecycle | No application/registration surface to bind or revoke | ❌ fails — revocation means de-linking a personal device |
| No v1 dependency on unofficial automation | `signal-cli` is community-maintained, reverse-engineered | ❌ fails by definition |

## Decision

- The Signal adapter (`adapters::signal::SignalAdapter`) exists as an
  explicit, typed disabled state: `bind` always returns
  `AdapterError::Disabled`, `SignalEligibility::CURRENT` is `NotEligible`.
- `MessagingConfig.signal_enabled` is accepted but ignored; the adapter is
  never registered.
- The `Provider::Signal` envelope variant is retained so a future eligible
  adapter can normalize into it without a schema change.

## Re-evaluation criteria

Revisit this decision only if Signal ships an official, supported
bot/application surface providing: scoped application credentials (not a
personal identity), a registration/revocation lifecycle, and documented
webhook or event delivery. Until then, v1 must not depend on Signal.
