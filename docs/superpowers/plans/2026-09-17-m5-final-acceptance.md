# M5 #8 final acceptance plan

Parent: `qa-m5-27-platform-matrix` (PR #51). Child: `qa-m5-08-final-acceptance`. This is an acceptance evidence slice with one local deterministic QA fixture, not a production runtime change; upstream defects are not silently repaired on the last branch of the stack.

1. Read issue #8, historical QA records and the #27 named inventory. Use only the fully committed parent source SHA and an owned WSL fixture.
2. Separate live Ollama, deterministic fault injection, agent-operated browser, automated test, and unrun/blocked evidence. Retain final run text, action/approval/occurrence states, audit records, model identity/digest, and exact fixture/source metadata.
3. Exercise text, tool read/write, zero grant, reject/expiry/replay, scheduled success/failure, restart, cancellation, workflow capture/publish/load/tamper, audit verify/tamper/recovery, browser connection and pause/resume/error states, and bounded shutdown. Do not convert missing crash or request-level GPU proof to a pass.
4. Freeze sanitized evidence, remove any credential-bearing browser artifact, stop the owned fixtures, and publish a machine-readable case matrix plus human-readable report. Validate the JSON, evidence hashes, status counts and diff.
5. Commit and push this issue branch, open a normal PR against the immediately previous branch, comment on issue #8, and leave every canonical issue open unless the maintainer separately dispositions it. Do not merge or enable auto-merge.

Observed disposition: 34 PASS, 1 FAIL, 6 PARTIAL, 4 NOT RUN, 2 BLOCKED. Full M5 acceptance is **not** established. The failed rejected-action terminal state, unrun crash/timeout paths, partial workflow/GPU/wire proof, and blocked native Linux desktop/CI require explicit follow-up.
