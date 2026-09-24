# Guest Build, Toolchain & Signing

## Toolchain

The guest image is built with a pinned toolchain:

- Kernel: Linux 6.8, config in `guest/kernel-config` (must have
  `CONFIG_VIRTIO`, `CONFIG_VIRTIO_NET`, `CONFIG_VSOCK`, `CONFIG_EXT4_FS`).
- Rootfs: built via `scripts/sandbox/build-guest.sh`.
- Guest agent: `cargo build --release -p lumen-sandboxd --bin lumen-guest-agent`
  with the `guest` feature (no host-only deps).

## Reproducibility

- All inputs are pinned by digest in the manifest.
- The build runs in a container (`Dockerfile.guest`) with fixed versions.
- `SOURCE_DATE_EPOCH` is set for deterministic timestamps.

## Signing

1. Build the image: `./scripts/sandbox/build-guest.sh --out ./guest-out`
2. Sign the manifest: `./scripts/sandbox/sign-image.sh sign \
     --manifest ./guest-out/manifest.json \
     --key /etc/lumen/image-sign.key \
     --sig ./guest-out/manifest.sig`
3. Verify: `./scripts/sandbox/sign-image.sh verify \
     --manifest ./guest-out/manifest.json \
     --sig ./guest-out/manifest.sig \
     --key /etc/lumen/image-verify.key`

The signing key is an Ed25519 private key, stored offline or in a KMS.
The verify key is deployed to all sandboxd hosts at
`/etc/lumen/image-verify.key` (0644).

## Promotion

Images move through slots: `canary` -> `stable` -> `previous`.

- New images go to `canary`. The KVM test suite runs against canary.
- On success: `./scripts/sandbox/promote.sh canary` (rotates slots).
- On failure: `./scripts/sandbox/promote.sh rollback` (restores previous).

See `docs/sandbox/promotion.md` for the full runbook.
