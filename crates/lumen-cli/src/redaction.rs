//! Host-only known-secret guard shared by provider resolution, runtime diagnostics and support export.
//! It retains in-memory copies for later scrubbing. Never serialize or expose it to models.
use lumen_control_plane::provider_runtime::ProviderSecretObserver;
use lumen_core::action::CanonicalValue;
use std::sync::RwLock;
pub(crate) struct SecretRedactor {
    secrets: RwLock<Vec<String>>,
}

impl SecretRedactor {
    pub(crate) fn new(secrets: Vec<String>) -> Self {
        let redactor = Self {
            secrets: RwLock::new(Vec::new()),
        };
        for secret in secrets {
            redactor.register(&secret);
        }
        redactor
    }

    pub(crate) fn register(&self, secret: &str) {
        if secret.is_empty() {
            return;
        }
        let mut secrets = self.secrets.write().expect("secret redactor lock");
        secrets.push(secret.to_owned());
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        secrets.dedup();
    }

    pub(crate) fn redact_value(&self, value: &mut CanonicalValue) {
        match value {
            CanonicalValue::String(value) => self.redact_string(value),
            CanonicalValue::Array(values) => {
                for value in values {
                    self.redact_value(value);
                }
            }
            CanonicalValue::Object(values) => {
                for value in values.values_mut() {
                    self.redact_value(value);
                }
            }
            CanonicalValue::Null | CanonicalValue::Bool(_) | CanonicalValue::Integer(_) => {}
        }
    }

    pub(crate) fn redact_string(&self, value: &mut String) {
        for secret in self.secrets.read().expect("secret redactor lock").iter() {
            if value.contains(secret) {
                *value = value.replace(secret, "[REDACTED]");
            }
        }
    }

    pub(crate) fn contains_secret(&self, value: &str) -> bool {
        self.secrets
            .read()
            .expect("secret redactor lock")
            .iter()
            .any(|secret| value.contains(secret))
    }
}

impl ProviderSecretObserver for SecretRedactor {
    fn observe(&self, value: &str) {
        self.register(value);
    }
    fn contains_secret(&self, value: &str) -> bool {
        self.contains_secret(value)
    }
}
