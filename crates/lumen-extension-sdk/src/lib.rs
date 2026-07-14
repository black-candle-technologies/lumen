//! Guest-safe wire contract shared by Lumen components and subprocesses.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const CURRENT_PROTOCOL_VERSION: u16 = 1;
pub const MAX_REQUEST_ID_BYTES: usize = 128;
pub const MAX_COMPONENT_ID_BYTES: usize = 128;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const NONCE_BYTES: usize = 32;

#[cfg(target_arch = "wasm32")]
#[doc(hidden)]
pub use wit_bindgen as __wit_bindgen;

/// Generates guest bindings for the versioned Lumen component world.
#[macro_export]
macro_rules! generate_guest_bindings {
    () => {
        $crate::__wit_bindgen::generate!({
            path: "wit",
            world: "plugin",
        });
    };
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationRequest {
    protocol_version: u16,
    request_id: String,
    component_id: String,
    input: Value,
    settings: Value,
    deadline_millis: u64,
}

impl InvocationRequest {
    pub fn new(
        request_id: impl Into<String>,
        component_id: impl Into<String>,
        input: Value,
        settings: Value,
        deadline_millis: u64,
    ) -> Result<Self, WireContractError> {
        let request_id = request_id.into();
        let component_id = component_id.into();
        validate_request_id(&request_id)?;
        validate_component_id(&component_id)?;
        if deadline_millis == 0 {
            return Err(WireContractError::InvalidDeadline);
        }
        Ok(Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            request_id,
            component_id,
            input,
            settings,
            deadline_millis,
        })
    }

    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn component_id(&self) -> &str {
        &self.component_id
    }

    pub const fn input(&self) -> &Value {
        &self.input
    }

    pub const fn settings(&self) -> &Value {
        &self.settings
    }

    pub const fn deadline_millis(&self) -> u64 {
        self.deadline_millis
    }

    pub fn encode(&self) -> Result<String, WireContractError> {
        serde_json::to_string(self).map_err(|_| WireContractError::InvalidJson)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    PluginFault,
    HostFault,
    PolicyDenied,
    Cancelled,
    ResourceExhaustion,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    class: FailureClass,
    message: String,
}

impl Failure {
    pub fn new(class: FailureClass, message: impl Into<String>) -> Result<Self, WireContractError> {
        let message = message.into();
        if message.is_empty() || message.len() > 4096 || message.chars().any(char::is_control) {
            return Err(WireContractError::InvalidFailure);
        }
        Ok(Self { class, message })
    }

    pub const fn class(&self) -> FailureClass {
        self.class
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Result { value: Value },
    Proposal { kind: String, arguments: Value },
    Failure { failure: Failure },
}

impl Response {
    pub const fn result(value: Value) -> Self {
        Self::Result { value }
    }

    pub fn proposal(kind: impl Into<String>, arguments: Value) -> Self {
        Self::Proposal {
            kind: kind.into(),
            arguments,
        }
    }

    pub const fn failure(failure: Failure) -> Self {
        Self::Failure { failure }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationResponse {
    protocol_version: u16,
    request_id: String,
    response: Response,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubprocessRequest {
    nonce: String,
    invocation: InvocationRequest,
}

impl SubprocessRequest {
    pub fn new(
        nonce: impl Into<String>,
        invocation: InvocationRequest,
    ) -> Result<Self, WireContractError> {
        let nonce = nonce.into();
        validate_nonce(&nonce)?;
        Ok(Self { nonce, invocation })
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub const fn invocation(&self) -> &InvocationRequest {
        &self.invocation
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubprocessResponse {
    nonce: String,
    response: InvocationResponse,
}

impl SubprocessResponse {
    pub fn new(
        nonce: impl Into<String>,
        response: InvocationResponse,
    ) -> Result<Self, WireContractError> {
        let nonce = nonce.into();
        validate_nonce(&nonce)?;
        Ok(Self { nonce, response })
    }

    pub fn validate_for(
        self,
        expected_nonce: &str,
        expected_protocol: u16,
        expected_request_id: &str,
    ) -> Result<Response, WireContractError> {
        if self.nonce != expected_nonce {
            return Err(WireContractError::NonceMismatch);
        }
        self.response
            .validate_for(expected_protocol, expected_request_id)
    }
}

pub fn encode_frame<T: Serialize>(value: &T, max_bytes: usize) -> Result<Vec<u8>, FrameError> {
    let payload = serde_json::to_vec(value).map_err(|_| FrameError::InvalidJson)?;
    if max_bytes == 0 || payload.len() > max_bytes || payload.len() > u32::MAX as usize {
        return Err(FrameError::TooLarge);
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_frame<T: DeserializeOwned>(frame: &[u8], max_bytes: usize) -> Result<T, FrameError> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or(FrameError::Truncated)?
        .try_into()
        .expect("four-byte slice");
    let length = u32::from_be_bytes(prefix) as usize;
    if max_bytes == 0 || length > max_bytes {
        return Err(FrameError::TooLarge);
    }
    let expected = 4_usize.checked_add(length).ok_or(FrameError::TooLarge)?;
    if frame.len() < expected {
        return Err(FrameError::Truncated);
    }
    if frame.len() > expected {
        return Err(FrameError::TrailingData);
    }
    let payload = std::str::from_utf8(&frame[4..]).map_err(|_| FrameError::InvalidUtf8)?;
    serde_json::from_str(payload).map_err(|_| FrameError::InvalidJson)
}

impl InvocationResponse {
    pub fn new(
        request_id: impl Into<String>,
        response: Response,
    ) -> Result<Self, WireContractError> {
        let request_id = request_id.into();
        validate_request_id(&request_id)?;
        Ok(Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            request_id,
            response,
        })
    }

    pub fn decode_bounded(encoded: &str, max_bytes: u64) -> Result<Self, WireContractError> {
        if max_bytes == 0 || encoded.len() as u64 > max_bytes {
            return Err(WireContractError::ResponseTooLarge);
        }
        let response: Self =
            serde_json::from_str(encoded).map_err(|_| WireContractError::InvalidJson)?;
        validate_request_id(&response.request_id)?;
        Ok(response)
    }

    pub fn encode(&self) -> Result<String, WireContractError> {
        serde_json::to_string(self).map_err(|_| WireContractError::InvalidJson)
    }

    pub fn validate_for(
        self,
        expected_protocol: u16,
        expected_request_id: &str,
    ) -> Result<Response, WireContractError> {
        if self.protocol_version != expected_protocol {
            return Err(WireContractError::ProtocolMismatch);
        }
        if self.request_id != expected_request_id {
            return Err(WireContractError::RequestMismatch);
        }
        Ok(self.response)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WireContractError {
    #[error("request ID must be bounded printable ASCII")]
    InvalidRequestId,
    #[error("component ID must be a bounded canonical lowercase ASCII identifier")]
    InvalidComponentId,
    #[error("deadline must be greater than zero")]
    InvalidDeadline,
    #[error("extension failure text must be bounded printable text")]
    InvalidFailure,
    #[error("extension response exceeded the configured byte limit")]
    ResponseTooLarge,
    #[error("extension response was not valid protocol JSON")]
    InvalidJson,
    #[error("extension response protocol version did not match the request")]
    ProtocolMismatch,
    #[error("extension response request ID did not match the request")]
    RequestMismatch,
    #[error("subprocess nonce must be exactly 256 bits of lowercase hexadecimal")]
    InvalidNonce,
    #[error("subprocess response nonce did not match the request")]
    NonceMismatch,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FrameError {
    #[error("protocol frame is truncated")]
    Truncated,
    #[error("protocol frame exceeds its configured limit")]
    TooLarge,
    #[error("protocol frame contains trailing data")]
    TrailingData,
    #[error("protocol frame payload is not UTF-8")]
    InvalidUtf8,
    #[error("protocol frame payload is not valid JSON")]
    InvalidJson,
}

fn validate_request_id(value: &str) -> Result<(), WireContractError> {
    if value.is_empty()
        || value.len() > MAX_REQUEST_ID_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(WireContractError::InvalidRequestId);
    }
    Ok(())
}

fn validate_component_id(value: &str) -> Result<(), WireContractError> {
    if value.is_empty()
        || value.len() > MAX_COMPONENT_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(WireContractError::InvalidComponentId);
    }
    Ok(())
}

fn validate_nonce(value: &str) -> Result<(), WireContractError> {
    if value.len() != NONCE_BYTES * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(WireContractError::InvalidNonce);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn request_identity_and_deadlines_are_bounded() {
        assert!(InvocationRequest::new("request-1", "echo", Value::Null, Value::Null, 1).is_ok());
        assert_eq!(
            InvocationRequest::new("bad request", "echo", Value::Null, Value::Null, 1).unwrap_err(),
            WireContractError::InvalidRequestId
        );
        assert_eq!(
            InvocationRequest::new("request-1", "Bad", Value::Null, Value::Null, 1).unwrap_err(),
            WireContractError::InvalidComponentId
        );
        assert_eq!(
            InvocationRequest::new("request-1", "echo", Value::Null, Value::Null, 0).unwrap_err(),
            WireContractError::InvalidDeadline
        );
    }

    #[test]
    fn frames_are_exact_bounded_utf8_json() {
        let request = InvocationRequest::new(
            "request-1",
            "echo",
            serde_json::json!({"value": 1}),
            Value::Null,
            100,
        )
        .unwrap();
        let framed = encode_frame(&request, MAX_FRAME_BYTES).unwrap();
        assert_eq!(
            decode_frame::<InvocationRequest>(&framed, MAX_FRAME_BYTES).unwrap(),
            request
        );

        let mut trailing = framed.clone();
        trailing.push(0);
        assert_eq!(
            decode_frame::<InvocationRequest>(&trailing, MAX_FRAME_BYTES).unwrap_err(),
            FrameError::TrailingData
        );
        assert_eq!(
            decode_frame::<InvocationRequest>(&framed[..3], MAX_FRAME_BYTES).unwrap_err(),
            FrameError::Truncated
        );
        assert_eq!(
            decode_frame::<InvocationRequest>(&framed, 1).unwrap_err(),
            FrameError::TooLarge
        );
    }
}
