# Guest Build, Toolchain & Signing

## Toolchain

The build script consumes supplied kernel and guest-agent artifacts
(`scripts/sandbox/build-guest.sh [--out DIR] [--kernel SRC]`):

- Kernel: pass `--kernel SRC` or place a prebuilt `vmlinux` at
  `$OUT/vmlinux`. The kernel must have `CONFIG_VIRTIO`,
  `CONFIG_VIRTIO_NET`, `CONFIG_VIRTIO_BLK`, `CONFIG_VSOCK`,
  `CONFIG_EXT4_FS`, and `CONFIG_DEVTMPFS`.
- Rootfs: built by the script (`/init` + busybox + guest agent →
  `rootfs.ext4`).
- Guest agent: path via `GUEST_AGENT_BIN` (default
  `./target/release/lumen-guest-agent`); build it with
  `cargo build --release -p lumen-sandboxd --bin lumen-guest-agent`.
- Busybox: path via `BUSYBOX_BIN` (required; the build fails without it).

## Reproducibility

- The manifest records SHA-256 digests for the generated artifacts
  (`kernel_digest`, `rootfs_digest`, `workspace_template_digest`).
- Reproducibility is not implemented: the script does not consume
  `guest/kernel-config` or a `Dockerfile.guest`, sets no
  `SOURCE_DATE_EPOCH`, and the manifest sets `kernel_config_digest` to
  `sha256:unknown`, leaves `tool_versions` empty, and sets
  `reproducible` to `false`.

## Signing

1. Build the image: `./scripts/sandbox/build-guest.sh --out ./guest-out`
2. Sign the manifest (the signature is embedded in `signatures[]`):
   `./scripts/sandbox/sign-image.sh sign \
     --manifest ./guest-out/manifest.json \
     --key /etc/lumen/image-sign.key`
3. Verify: `./scripts/sandbox/sign-image.sh verify \
     --manifest ./guest-out/manifest.json \
     --key /etc/lumen/image-verify.key`

The signing key is an Ed25519 private key, stored offline or in a KMS.
The key file holds the 32-byte seed as 64-char hex or 32 raw bytes
(see `provenance::load_signing_key`); PEM is not accepted. The verify
key is the 32-byte public key in the same formats, deployed to all
sandboxd hosts at `/etc/lumen/image-verify.key` (0644).

## Promotion

Images move through slots: `canary` -> `stable` -> `previous` (atomic
digest pointer files under `<store>/slots/`, see `promotion.md`).

- New images are staged with `./scripts/sandbox/promote.sh canary <digest>`
  (verifies the embedded signature). The KVM test suite runs against the
  canary digest.
- On success: `./scripts/sandbox/promote.sh promote --kvm-ok` (rotates
  slots; refuses without KVM evidence).
- On failure: `./scripts/sandbox/promote.sh rollback` (restores previous;
  the bad stable is kept as canary for forensics).

See `docs/sandbox/promotion.md` for the full runbook.
