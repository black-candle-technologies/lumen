use lumen_core::{
    action::{ActionKind, CanonicalValue},
    extension::{ExtensionFailure, ExtensionFailureClass, ExtensionResponse},
};
use lumen_extension_sdk::{FailureClass as WireFailureClass, Response as WireResponse};
use thiserror::Error;

pub(crate) fn wire_response_to_core(
    response: WireResponse,
) -> Result<ExtensionResponse, ResponseConversionError> {
    match response {
        WireResponse::Result { value } => Ok(ExtensionResponse::result(canonical_value(value)?)),
        WireResponse::Proposal { kind, arguments } => Ok(ExtensionResponse::proposal(
            ActionKind::new(kind).map_err(|_| ResponseConversionError)?,
            canonical_value(arguments)?,
        )),
        WireResponse::Failure { failure } => {
            let class = match failure.class() {
                WireFailureClass::PluginFault => ExtensionFailureClass::PluginFault,
                WireFailureClass::HostFault => ExtensionFailureClass::HostFault,
                WireFailureClass::PolicyDenied => ExtensionFailureClass::PolicyDenied,
                WireFailureClass::Cancelled => ExtensionFailureClass::Cancelled,
                WireFailureClass::ResourceExhaustion => ExtensionFailureClass::ResourceExhaustion,
            };
            let failure = ExtensionFailure::new(class, failure.message())
                .map_err(|_| ResponseConversionError)?;
            Ok(ExtensionResponse::failure(failure))
        }
    }
}

fn canonical_value(value: serde_json::Value) -> Result<CanonicalValue, ResponseConversionError> {
    serde_json::from_value(value).map_err(|_| ResponseConversionError)
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("wire response cannot be represented by the runtime contract")]
pub(crate) struct ResponseConversionError;
