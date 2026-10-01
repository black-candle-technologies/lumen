//! Admission gate for the reference Pi launchers.
//!
//! A tool allowlist and a subprocess are not OS confinement. Neither reference
//! launcher can currently prove filesystem, exec, network, or credential
//! isolation, so neither is admissible in a non-test build. There is deliberately
//! no environment variable, feature flag, or public unchecked constructor.
//!
//! Replace this gate only with a reviewed confined launcher and current negative
//! execution evidence. See docs/rebuild/phase-0.md.

pub(crate) const UNAVAILABLE: &str = "Pi launch disabled: verified OS confinement and host-only execution are required (phase-0 gate)";

pub(crate) fn require_confinement() -> Result<(), &'static str> {
    Err(UNAVAILABLE)
}
