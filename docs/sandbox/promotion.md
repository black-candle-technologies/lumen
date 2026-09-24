# Promotion & Rollback Runbook

## Slots

`/var/lib/lumen/images/` contains:

- `canary/` — new image under validation.
- `stable/` — production image.
- `previous/` — last stable (for instant rollback).

## Promoting a New Image

1. Build and sign the image (see `build.md`).
2. Deploy to canary: `cp -r ./guest-out /var/lib/lumen/images/canary/`
3. Run KVM tests: `sudo ./scripts/sandbox/kvm-runner.sh --image /var/lib/lumen/images/canary`
4. If tests pass: `sudo ./scripts/sandbox/promote.sh canary`
5. Monitor: watch `sandboxd` logs for the first 10 canary runs.

## Rollback

If stable is bad:

```bash
sudo ./scripts/sandbox/promote.sh rollback
sudo systemctl restart lumen-sandboxd
```

The bad stable is preserved as `canary/` for forensics. The previous
stable is now live. No data loss: runs are disposable; in-flight runs
are cancelled and retried by the kernel.

## Emergency: Revoke an Image

If an image is compromised:

1. Remove it from all slots.
2. Rotate the signing key (see `build.md`).
3. Restart sandboxd on all hosts.
4. The driver will refuse to boot the revoked digest (not in the
   allowlist).
