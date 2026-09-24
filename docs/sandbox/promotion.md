# Promotion & Rollback Runbook

## Store Layout

`/var/lib/lumen/images/` is digest-keyed:

```
/var/lib/lumen/images/
  sha256:<hex>/manifest.json        # embedded signatures[] (see build.md)
  sha256:<hex>/vmlinux
  sha256:<hex>/rootfs.ext4
  sha256:<hex>/workspace-template.raw
  slots/canary    # pointer file: "sha256:<hex>"
  slots/stable    # pointer file: "sha256:<hex>"
  slots/previous  # pointer file: "sha256:<hex>"
```

sandboxd resolves ONLY full digests from run specs
(`provenance::resolve_image` opens `<store>/<image_digest>/`). The slot
pointer files do not change which image a running or prepared run boots;
they are what the operator/kernel reads to choose the digest for NEW
runs. Every pointer update is atomic (write temp + rename).

## Promoting a New Image

1. Build the image (see `build.md`):
   `./scripts/sandbox/build-guest.sh --out ./guest-out`
2. Sign the manifest; the digest is printed by the signer:
   `DIGEST=$(./scripts/sandbox/sign-image.sh sign \
     --manifest ./guest-out/manifest.json \
     --key /etc/lumen/image-sign.key | awk '{print $2}')`
3. Install into the store under the digest directory (copy the files,
   not the directory — never nest `guest-out/` inside an existing
   directory):
   ```bash
   mkdir -p "/var/lib/lumen/images/$DIGEST"
   cp ./guest-out/{manifest.json,vmlinux,rootfs.ext4,workspace-template.raw} \
      "/var/lib/lumen/images/$DIGEST/"
   ```
4. Stage to canary (verifies the embedded signature, then atomically
   points the canary slot at the digest):
   `sudo ./scripts/sandbox/promote.sh canary "$DIGEST"`
5. Run KVM tests against the canary digest:
   `sudo ./scripts/sandbox/kvm-runner.sh --image "/var/lib/lumen/images/$DIGEST"`
6. If tests pass, promote (rotates `previous <- stable`,
   `stable <- canary`; refuses without `--kvm-ok`):
   `sudo ./scripts/sandbox/promote.sh promote --kvm-ok`
7. Monitor: point new runs at the stable digest and watch `sandboxd`
   logs for the first runs.

## Rollback

If stable is bad:

```bash
sudo ./scripts/sandbox/promote.sh rollback
sudo systemctl restart lumen-sandboxd
```

The bad stable is preserved as the canary pointer for forensics. The
previous stable is now live. No data loss: runs are disposable;
in-flight runs are cancelled and retried by the kernel.

## Emergency: Revoke an Image

If an image is compromised:

1. Remove its digest directory from the store on all hosts.
2. Clear any slot pointer still naming it (`slots/{canary,stable,previous}`).
3. Rotate the signing key (see `build.md`).
4. Restart sandboxd on all hosts.
5. The driver will refuse to boot the revoked digest (not in the store).
