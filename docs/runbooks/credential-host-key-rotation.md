# Runbook: credential and host-key rotation

## Purpose

Rotate every credential the runtime depends on — the API bearer token,
provider credentials, and host keys — without ever exposing a secret value
in logs, shell history, or the audit trail. The API token rotation requires
a runtime restart; expect a brief maintenance interruption while the service
restarts (there is no rolling or dual-token acceptance; plan the window
accordingly).

## Preconditions

- Operator access to the host running `lumen serve`.
- The environment variable named in `[authentication] token_environment`
  (default per your `lumen.toml`) for the API token.
- OS keyring access for provider credentials (`lumen secret`).

## Procedure

### 1. API bearer token

1. Generate a new token out-of-band (e.g. `openssl rand -hex 32`). Do not
   paste it into chat, tickets, or the audit log.
2. Update the token where the runtime reads it. Do not embed the secret in
   command text (it would land in shell history); write it via a file
   descriptor or a secret manager instead:
   ```
   # the runtime reads the token from the environment variable named in lumen.toml
   # Write the new token to the service environment file without echoing it:
   printf '%s' "$(cat /run/lumen/new-token)" >> /etc/lumen/environment
   # Or: update the secret in your secret manager and re-render the environment.
   ```
   Then restart the runtime (see step 3).
   The server authenticates with `state.authenticate(authorization)` on every
   request; there is no token cache beyond the process, so a restart applies
   the rotation atomically.
3. Restart the runtime (`systemctl restart lumen` or your supervisor).
4. Verify with the **new** token, then confirm the **old** token is rejected:
   ```
   curl -s -o /dev/null -w '%{http_code}\n' $LUMEN_URL/api/v1/workspaces/<ws>/runtime/capabilities \
     -H "Authorization: Bearer $NEW_TOKEN"   # expect 200
   curl -s -o /dev/null -w '%{http_code}\n' $LUMEN_URL/api/v1/workspaces/<ws>/runtime/capabilities \
     -H "Authorization: Bearer $OLD_TOKEN"   # expect 401
   ```
5. Update every stored client (web app connection settings, scripts) to the
   new token. The web app keeps the token in `sessionStorage` only — closing
   the tab discards it.

### 2. Provider credentials (model providers)

Provider credentials live in the OS keyring, referenced by id from
`secret_references`. Rotation never prints the value:

1. Create the replacement reference (value comes from stdin, never argv):
   ```
   printf '%s' '<new-credential>' | lumen secret create --label "<provider> api key" \
     --program /usr/bin/curl --environment "<PROVIDER>_API_KEY"
   ```
2. Point the provider config at the new reference (model registry update —
   goes through the normal approval-bound config path, not a direct edit).
3. Verify a probe model call succeeds (`runtime/capabilities?probe_model=true`).
4. **CONFIRM** — delete the old reference only after the new one is proven:
   ```
   lumen secret delete --id <old-secret-ref-id>
   ```
   Deletion removes the keychain value *before* the metadata row, so a crash
   cannot leave a dangling reference to a live secret.

### 3. Host keys (TLS / SSH, as deployed)

- TLS for the sync/API surface is terminated by the site's reverse proxy
  (Caddy). Rotate via the proxy's certificate workflow; the runtime itself
  holds no TLS private key.
- If the host's SSH key is rotated, update `known_hosts` on every operator
  machine and verify the new fingerprint out-of-band before trusting it.

## Verification

- `lumen health` passes.
- Old token returns `401`; new token returns `200`.
- `lumen secret list` shows only the new reference ids (labels only, never values).
- No secret value appears in the support bundle: `lumen support bundle --out /tmp/rotation-check`
  runs a secret scan that **blocks** export on any hit.

## Failure posture

- If the new token does not authenticate after restart, the service
  environment did not pick it up — check the supervisor's env file, not the
  token value. Roll back by restoring the previous env file and restarting;
  the old token remains valid until replaced.
- Never commit tokens or key material to the repo, the audit log, or a
  ticket. If a secret is ever pasted into the audit payload, the payload is
  immutable — rotate the credential immediately and record the exposure as a
  new audit event; do not attempt to rewrite history.
