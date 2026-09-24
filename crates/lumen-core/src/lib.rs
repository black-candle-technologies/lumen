//! Runtime core for Lumen agent orchestration.
//!
//! Phase 1 of the rebuild adds the authority kernel alongside the existing
//! modules: [`canonical`] (typed canonical resources), [`lease`] (signed
//! lease engine), [`budget`] (reservation accounting), [`execution`]
//! (execution lifecycle driver), [`nonce`] (replay protection), [`kernel_audit`] (append-only audit + checkpoints), and
//! [`store`] (repository traits).

pub mod action;
pub mod approval;
pub mod artifact;
pub mod audit;
pub mod automation;
pub mod budget;
pub mod canonical;
pub mod capability;
pub mod context;
pub mod egress;
pub mod execution;
pub mod executor;
pub mod extension;
pub mod identity;
pub mod kernel_audit;
pub mod lease;
pub mod model;
pub mod nonce;
pub mod operator;
pub mod orchestration;
pub mod pi_boundary;
pub mod policy;
pub mod provider;
pub mod routing;
pub mod run;
pub mod secret;
pub mod store;
pub mod trust_gate;
pub mod worker;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}
