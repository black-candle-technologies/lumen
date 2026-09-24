//! Provider, tool, and plugin integration boundaries for Lumen.

pub mod admission;
pub mod extension_package;
pub mod extension_process;
mod extension_protocol;
pub mod extension_schema;
#[cfg(feature = "wasm-host")]
pub mod extension_wasm;
pub mod filesystem;
#[cfg(feature = "model-client")]
pub mod openai_compatible;
pub mod process;
#[cfg(feature = "model-client")]
pub mod providers;
pub mod sandbox;
pub mod secrets;
