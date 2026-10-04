use lumen_core::provider::ProviderError;
use zeroize::Zeroizing;

pub struct ProviderCredential(Zeroizing<Vec<u8>>); // no Clone, Debug, Serialize
impl ProviderCredential {
    pub fn from_stdin(mut bytes: Zeroizing<Vec<u8>>) -> Result<Self, ProviderError> {
        // CLI contract permits precisely one terminating LF or CRLF.
        if bytes.ends_with(b"\r\n") {
            let len = bytes.len();
            bytes.truncate(len - 2);
        } else if bytes.ends_with(b"\n") {
            let len = bytes.len();
            bytes.truncate(len - 1);
        }
        Self::from_keyring(bytes)
    }
    pub fn from_keyring(bytes: Zeroizing<Vec<u8>>) -> Result<Self, ProviderError> {
        if bytes.is_empty()
            || bytes.len() > 16 * 1024
            || bytes.iter().any(|b| !b.is_ascii_graphic())
        {
            return Err(ProviderError::configuration("invalid provider credential"));
        }
        Ok(Self(bytes))
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
    // Trusted host integration only; never expose through tools or serialization.
    pub fn with_exposed_str<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        f(std::str::from_utf8(self.bytes()).expect("validated ASCII credential"))
    }
}

impl ProviderCredential {
    pub(crate) fn bearer_header(&self) -> Result<reqwest::header::HeaderValue, ProviderError> {
        let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(7 + self.bytes().len()));
        bytes.extend_from_slice(b"Bearer ");
        bytes.extend_from_slice(self.bytes());
        let mut header = reqwest::header::HeaderValue::from_bytes(&bytes)
            .map_err(|_| ProviderError::configuration("invalid provider credential"))?;
        header.set_sensitive(true);
        Ok(header)
    }
    pub(crate) fn api_key_header(&self) -> Result<reqwest::header::HeaderValue, ProviderError> {
        let mut header = reqwest::header::HeaderValue::from_bytes(self.bytes())
            .map_err(|_| ProviderError::configuration("invalid provider credential"))?;
        header.set_sensitive(true);
        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_bounded_ascii_without_trimming() {
        for bytes in [
            Vec::new(),
            b" key".to_vec(),
            b"key ".to_vec(),
            b"key\n\n".to_vec(),
            b"key\r".to_vec(),
            vec![b'a'; 16385],
            vec![0],
            vec![255],
        ] {
            assert!(ProviderCredential::from_stdin(Zeroizing::new(bytes)).is_err());
        }
        for bytes in [b"key".to_vec(), b"key\n".to_vec(), b"key\r\n".to_vec()] {
            let key = ProviderCredential::from_stdin(Zeroizing::new(bytes)).unwrap();
            key.with_exposed_str(|s| assert_eq!(s, "key"));
            assert!(!format!("{:?}", key.bearer_header().unwrap()).contains("key"));
            assert!(!format!("{:?}", key.api_key_header().unwrap()).contains("key"));
        }
        assert!(ProviderCredential::from_keyring(Zeroizing::new(b"key\n".to_vec())).is_err());
    }
}
