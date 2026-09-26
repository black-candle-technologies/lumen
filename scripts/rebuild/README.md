# Phase 0 confinement experiment

Development verification only. Both production Pi launchers remain disabled.
Read [ADR-0008](../../docs/adr/0008-pi-runtime-confinement.md) before changing the
trusted bootstrap, syscall rules, mounts, or transient service policy.

Prerequisites: unprivileged Linux x86-64, cgroup v2 with a working systemd user
manager, bubblewrap, system Node 22.22.1 at `/usr/bin/node`, GCC, N-API headers,
Python with `cryptography`, Rust, npm and git. The prototype has no fallback when
these facilities fail. lane-vps uses its distro AppArmor profile for bubblewrap.
The Ubuntu CI job changes only its disposable runner's namespace setting.

From the repository root, in a new **absolute** scratch directory:

```sh
# The existing extension test build emits the actual host-client.js used below.
(cd lumen-integrations/bct-pi-extension && npm ci --ignore-scripts --no-audit --no-fund && npm test)
cargo build -p lumen-server --example phase0_kernel_probe
(cd scripts/rebuild/confinement && python3 -m unittest -v test_runtime test_audit)
bash scripts/rebuild/build-pinned-pi.sh /absolute/scratch/upstream
python3 scripts/rebuild/confinement/prepare_pi.py /absolute/scratch/upstream/repo /absolute/scratch/runtime
# Supply the candidate manifest digest printed by preparation, after inspection.
python3 scripts/rebuild/confinement/probe_pi.py /absolute/scratch/runtime MANIFEST_SHA256 \
  target/debug/examples/phase0_kernel_probe /absolute/scratch/evidence
python3 scripts/rebuild/confinement/verify_audit.py \
  /absolute/scratch/evidence/kernel-evidence.json /absolute/scratch/evidence/audit-anchor.json
```

The upstream source is exactly `f07218c4d4bbc12bef056a7058c3dd49dfe41abe` (the
registry release's gitHead for Pi 0.87.1), with package-lock SHA-256
`95dbf4d7aa54eebf235edccd6926efac42fbf4e1c6a92c625c9ac706a8b367f7`.
The historical `b455975…` candidate has model-data schema v6; the 0.87.1 published
artifact uses schema v3. Those inputs cannot be mixed. The model-data generator
fetches mutable provider catalogues, so the build instead extracts only the 42
JSON files from the exact pi-ai 0.87.1 tarball, SHA-256
`35b4432f27cc2665f86beebb9af6a39b1251970883c3044bd8be4f4e8c731ca0`.
The upstream offline validator checks their manifest/structure. Dependency fetch
disables lifecycle scripts; repository compilation runs without network or host
home mounts. No provider credentials are used.

The tiny upstream `dist/bundle/cli.js` hash is **not** the Pi build identity. The
runtime manifest enumerates every copied dist chunk, dependency, system runtime
library, fixture, and native addon. `runtime.py` refuses missing/extra/tampered
files, symlinks, unknown manifest fields and digest mismatch, and executes a new
verified private snapshot. Each changed candidate requires a new manifest and
independent admission review. These experimental manifests have no signature or
production admission status. Registry provenance signatures have not yet been
independently verified; matching a published gitHead is not such verification.

`probe_pi.py` supervises the actual upstream CLI over bounded JSONL stdio. Its
pinned test extension supplies a deterministic model and calls the compiled BCT
`requestRead` bridge; it is not a live model gateway. Pi 0.87.1's `--no-tools`
disables custom tools too, so the fixture uses `--no-builtin-tools --tools
bct.read_file` plus discovery-disable flags and one exact extension path. The
fixture repeats direct filesystem, shell, native socket/process/namespace/ioctl
probes inside real Pi. Observations are compared against the expected denials.

The separate Rust probe opens a new SQLite database and the real authority
kernel, creates an ephemeral session and a short one-use lease for an empty
directory, and processes exactly one unauthorized read. The kernel first denies
the missing one-shot action binding: a signed root is not human approval. The
path also lies outside scope, but this run does not establish that path-subset
evaluation was reached. Separate real-kernel tests cover path scope. It has **no executor**;
an allow/fault/pending response fails the probe. It destroys the identity, checks
the durable audit, and returns only public evidence. The Python verifier checks
the hash chain, every Ed25519 checkpoint, a separately captured head, and the
reply's exact kernel decision digest. Mutation tests cover digest substitution,
bad signatures/keys, missing checkpoints, changed records and truncation. The
development anchor is captured from this kernel run; production host enrollment
and a remote trusted checkpoint store are not provided here.

No existing database or deployed service is touched. There is no database schema
migration in this experiment. Keep production launch rejection when reverting
prototype code. For an interrupted test, inspect only its `lumen-phase0-*`
transient unit, stop that exact unit through `systemctl --user stop UNIT`, and
verify its cgroup and private snapshot are gone before removing the scratch
directory. Do not stop similarly named jobs indiscriminately. Abrupt supervisor
death currently relies on RuntimeMaxSec for eventual termination; immediate
orphan-free restart recovery and staging rollback are still open acceptance work.

Passing this experiment is not full Phase 0 acceptance, signed release evidence,
Firecracker execution evidence, an independent security review, or authorization
to merge or deploy. Producer/consumer and sandbox owner review remain required.
