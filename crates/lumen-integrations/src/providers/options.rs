use lumen_core::provider::ProviderError;
#[derive(Clone, Copy, Debug)]
pub struct ProviderHttpOptions {
    pub timeout: std::time::Duration,
    pub max_response_bytes: usize,
}
impl ProviderHttpOptions {
    pub fn validate(self) -> Result<Self, ProviderError> {
        if self.timeout.is_zero() || self.max_response_bytes == 0 {
            return Err(ProviderError::configuration("invalid provider HTTP limits"));
        }
        Ok(self)
    }
}
impl Default for ProviderHttpOptions {
    fn default() -> Self {
        Self {
            timeout: lumen_core::provider::DEFAULT_PROVIDER_TIMEOUT,
            max_response_bytes: lumen_core::provider::DEFAULT_PROVIDER_MAX_RESPONSE_BYTES,
        }
    }
}
