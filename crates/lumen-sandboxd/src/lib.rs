//! lumen-sandboxd: the strict-profile sandbox broker.
//!
//! Every effectful tool action runs in a FRESH Firecracker microVM booted
//! from a known, signed snapshot (strict profile = one disposable microVM
//! per action). This crate implements the broker service (`sandboxd`) that
//! owns KVM, the jailer, network setup, and cleanup — and nothing else.
//! Policy lives in the kernel; sandboxd enforces the frozen [`SandboxSpec`]
//! it is given.
//!
//! # Layout
//!
//! - [`contracts`]: the frozen phase-0 `SandboxDriver` v1 boundary
//!   (re-exported verbatim from `lumen-protocol`; never redefined here)
//!   plus the daemon's runtime-internal shapes.
//! - [`driver`]: [`contracts::SandboxDriver`] implementation over Firecracker,
//!   including the frozen-spec -> runtime-spec adapter.
//! - [`api`]: authenticated local (Unix socket) API used by the kernel; its
//!   method set mirrors the frozen trait 1:1.
//! - [`state`]: crash-safe run state machine + startup reconciliation.
//! - `jailer`, [`cgroups`]: host policy perimeter (Firecracker runs with its default seccomp filters).
//! - [`network`], [`dns`], [`proxy`]: default-deny egress.
//! - [`storage`], [`export`]: copy-on-write workspace + controlled export.
//! - [`guest_agent`]: vsock guest-agent protocol (host side). The guest-side
//!   agent is the `lumen-guest-agent` binary in `src/bin/`.
//! - [`provenance`]: image/kernel/rootfs digests, toolchain manifest,
//!   Ed25519 manifest signing/verification.
//! - [`secrets`]: opaque secret handles; brokered use, never disclosure.
//!
//! # KVM gating
//!
//! This machine (dev) has no `/dev/kvm`. Everything that touches KVM,
//! Firecracker, netns, or mounts is isolated behind small `System` traits
//! with hermetic fakes; the real lifecycle tests live in `tests/kvm/` and
//! compile only with `--features kvm` for the lane-vps runner.

pub mod api;
pub mod cgroups;
pub mod config;
pub mod contracts;
pub mod dns;
pub mod driver;
pub mod error;
pub mod export;
pub mod guest_agent;
pub mod jailer;
pub mod network;
pub mod provenance;
pub mod proxy;
pub mod secrets;
pub mod state;
pub mod storage;

pub use contracts::{
    ExportManifest, ExportedFile, NetworkResource, OutputChunk, OutputSink, SANDBOX_DRIVER_VERSION,
    SandboxDriver, SandboxError, SandboxHandle, SandboxOutcome, SandboxProfile, SandboxQuotas,
    SandboxResult, SandboxRunSpec, SandboxSpec, StreamStats,
};
pub use error::SandboxdError;
