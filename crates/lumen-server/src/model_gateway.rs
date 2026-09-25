//! Model gateway (3C).
//!
//! Provider credentials live host-side and never enter Pi or guest
//! processes. The gateway:
//! - enforces model/provider classes from the lease before any spend,
//! - normalizes token, latency, and cost usage across providers,
//! - supports cancellation, timeout, bounded retry budgets, and provider
//!   outage handling,
//! - redacts provider payloads before anything reaches the audit log,
//! - quarantines the spend pool when usage comes back unknown -- or when
//!   an attempt's spend is unknowable (timeout, mid-flight cancellation)
//!   -- with no new spend until reconciliation. Timeouts and
//!   cancellations are never retried: the attempt may already have spent.

use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize;

use crate::kernel_client::sha256_hex;

/// A credential that is zeroized on drop and never rendered in Debug.
#[derive(Clone)]
pub struct SecretString {
    inner: String,
}

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            inner: value.into(),
        }
    }

    /// Expose the secret to a provider adapter call. Callers must not
    /// retain or log the returned reference.
    pub fn expose(&self) -> &str {
        &self.inner
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString([redacted])")
    }
}

/// Host-side credential store. Provider credentials are inserted here at
/// host startup and handed only to provider adapters, never to Pi.
#[derive(Debug, Default)]
pub struct CredentialVault {
    secrets: Mutex<HashMap<String, SecretString>>,
}

impl CredentialVault {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, provider: impl Into<String>, secret: SecretString) {
        self.secrets.lock().unwrap().insert(provider.into(), secret);
    }

    pub fn get(&self, provider: &str) -> Option<SecretString> {
        self.secrets.lock().unwrap().get(provider).cloned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// A model request as the host sees it. Credentials are resolved from the
/// vault at call time, never carried in the request.
#[derive(Debug, Clone)]
pub struct ModelRequest {
    pub provider: String,
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub max_output_tokens: u32,
    pub cancel: CancellationToken,
}

/// Raw completion from a provider adapter. Token counts and cost may be
/// absent; the gateway treats unknown usage as a quarantine trigger, not
/// as zero.
#[derive(Debug, Clone)]
pub struct ProviderCompletion {
    pub content: String,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    /// Provider-reported cost in micro-credits, if the provider reports it.
    pub cost_micros: Option<u64>,
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("provider timeout")]
    Timeout,
    #[error("provider transient failure: {0}")]
    Transient(String),
    #[error("provider hard failure: {0}")]
    Hard(String),
    #[error("cancelled")]
    Cancelled,
}

/// Boxed future for [`ProviderAdapter`] (object-safe seam).
pub type ProviderFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ProviderError>> + Send + 'a>>;

/// Provider adapter seam. Implementations speak one provider's API using
/// the vault-held credential. They never see lease or policy state.
pub trait ProviderAdapter: Send + Sync {
    fn provider_name(&self) -> &str;

    fn complete<'a>(
        &'a self,
        request: &'a ModelRequest,
        credential: &'a SecretString,
        cancel: &'a CancellationToken,
    ) -> ProviderFuture<'a, ProviderCompletion>;
}

/// Model/provider classes permitted by the lease, as interpreted by the host.
#[derive(Debug, Clone)]
pub struct ModelPolicy {
    pub allowed_models: Vec<String>,
    pub allowed_providers: Vec<String>,
    pub max_cost_micros_per_request: u64,
    pub max_output_tokens: u32,
}

impl ModelPolicy {
    pub fn permits(&self, provider: &str, model: &str) -> bool {
        self.allowed_providers.iter().any(|p| p == provider)
            && self.allowed_models.iter().any(|m| m == model)
    }
}

/// Normalized usage: one shape for every provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedUsage {
    pub provider: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_micros: u64,
    pub latency_ms: u64,
    /// False when the provider did not report full usage (token counts
    /// AND cost): the spend pool has been conservatively charged the
    /// request ceiling and quarantined, and `cost_micros` is that
    /// ceiling debit -- an estimate, not a bill. A missing cost is
    /// unknown usage, never zero cost.
    pub usage_known: bool,
}

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("model {model} on {provider} not permitted by lease policy")]
    PolicyDenied { provider: String, model: String },
    #[error("unknown provider: {0}")]
    UnknownProvider(String),
    #[error("missing credential for provider: {0}")]
    MissingCredential(String),
    #[error("budget exhausted: {0}")]
    BudgetDenied(String),
    #[error("provider outage: {0} (circuit open)")]
    ProviderOutage(String),
    #[error("request cancelled")]
    Cancelled,
    #[error("provider failed after {attempts} attempts: {last}")]
    ProviderFailed { attempts: u32, last: String },
}

/// Spend pool seam: the lease's budget as the host sees it.
pub trait SpendPool: Send + Sync {
    /// Attempt to reserve `micros`; false when the pool cannot cover it.
    fn try_reserve(&self, micros: u64) -> bool;
    /// Commit a reservation after success.
    fn commit(&self, micros: u64);
    /// Release a reservation for an attempt that provably spent nothing
    /// (hard failure before provider work, pre-attempt cancellation,
    /// exhausted transient retries). Attempts that may have incurred
    /// provider spend (unknown usage, provider/gateway timeout,
    /// mid-flight cancellation) use [`SpendPool::commit_unknown`]
    /// instead: releasing them would book the attempt as known-zero
    /// spend.
    fn release(&self, micros: u64);
    /// Conservatively commit `micros` (the request ceiling) and
    /// quarantine the pool: the attempt's spend is unknown, so the
    /// worst case is charged until [`SpendPool::reconcile`] reports the
    /// actual. No new spend is permitted while quarantined.
    fn commit_unknown(&self, micros: u64);
    /// Reconcile unknown usage and lift the quarantine. Reverses the
    /// conservative debit from `commit_unknown` before charging the
    /// actual spend, so the ceiling is never double-counted.
    fn reconcile(&self, actual_micros: u64);
    fn quarantined(&self) -> bool;
}

/// In-memory spend pool for tests and single-host deployments.
#[derive(Debug)]
pub struct MemorySpendPool {
    state: Mutex<PoolState>,
}

#[derive(Debug)]
struct PoolState {
    balance_micros: u64,
    reserved_micros: u64,
    quarantined: bool,
    /// Amount conservatively committed by `commit_unknown` (the request
    /// ceiling of the unknown attempt). `reconcile` reverses exactly
    /// this before charging the actual spend, so the ceiling is never
    /// double-counted.
    quarantined_micros: u64,
}

impl MemorySpendPool {
    pub fn new(balance_micros: u64) -> Self {
        Self {
            state: Mutex::new(PoolState {
                balance_micros,
                reserved_micros: 0,
                quarantined: false,
                quarantined_micros: 0,
            }),
        }
    }

    pub fn balance(&self) -> u64 {
        let state = self.state.lock().unwrap();
        state.balance_micros.saturating_sub(state.reserved_micros)
    }
}

impl SpendPool for MemorySpendPool {
    fn try_reserve(&self, micros: u64) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.quarantined {
            return false;
        }
        if state.balance_micros.saturating_sub(state.reserved_micros) < micros {
            return false;
        }
        state.reserved_micros += micros;
        true
    }

    fn commit(&self, micros: u64) {
        let mut state = self.state.lock().unwrap();
        state.reserved_micros = state.reserved_micros.saturating_sub(micros);
        state.balance_micros = state.balance_micros.saturating_sub(micros);
    }

    fn release(&self, micros: u64) {
        let mut state = self.state.lock().unwrap();
        state.reserved_micros = state.reserved_micros.saturating_sub(micros);
    }

    fn commit_unknown(&self, micros: u64) {
        let mut state = self.state.lock().unwrap();
        // The reservation converts into a conservative charge: the
        // attempt may have spent up to the ceiling, so the ceiling is
        // what the pool books until reconciliation.
        state.reserved_micros = state.reserved_micros.saturating_sub(micros);
        state.balance_micros = state.balance_micros.saturating_sub(micros);
        state.quarantined_micros = state.quarantined_micros.saturating_add(micros);
        state.quarantined = true;
    }

    fn reconcile(&self, actual_micros: u64) {
        let mut state = self.state.lock().unwrap();
        // Reverse the conservative debit first, then charge the actual
        // spend: net effect is `balance -= actual`, never
        // `balance -= ceiling + actual`. When the actual is below the
        // ceiling the over-held difference is credited back.
        state.balance_micros = state
            .balance_micros
            .saturating_add(state.quarantined_micros);
        state.quarantined_micros = 0;
        state.balance_micros = state.balance_micros.saturating_sub(actual_micros);
        state.quarantined = false;
    }

    fn quarantined(&self) -> bool {
        self.state.lock().unwrap().quarantined
    }
}

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Per-attempt timeout.
    pub attempt_timeout: Duration,
    /// Maximum attempts per request (1 = no retry).
    pub max_attempts: u32,
    /// Backoff between attempts.
    pub retry_backoff: Duration,
    /// Consecutive failures before the circuit opens.
    pub outage_threshold: u32,
    /// How long the circuit stays open.
    pub outage_cooldown: Duration,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            attempt_timeout: Duration::from_secs(60),
            max_attempts: 2,
            retry_backoff: Duration::from_millis(500),
            outage_threshold: 5,
            outage_cooldown: Duration::from_secs(300),
        }
    }
}

/// Audit-safe record of a gateway call. Contains normalized usage and a
/// digest of the content -- never prompts, completions, or raw provider
/// payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedAuditRecord {
    pub provider: String,
    pub model: String,
    pub usage: NormalizedUsage,
    pub content_digest: String,
}

/// The gateway response: content for Pi plus normalized usage for metering.
#[derive(Debug, Clone)]
pub struct GatewayResponse {
    pub content: String,
    pub usage: NormalizedUsage,
}

impl GatewayResponse {
    pub fn redacted_audit_record(&self) -> RedactedAuditRecord {
        RedactedAuditRecord {
            provider: self.usage.provider.clone(),
            model: self.usage.model.clone(),
            usage: self.usage.clone(),
            content_digest: sha256_hex(self.content.as_bytes()),
        }
    }
}

#[derive(Debug, Default)]
struct CircuitState {
    consecutive_failures: u32,
    opened_at: Option<Instant>,
}

/// The model gateway. Holds provider credentials and enforces
/// lease-derived model policy on every request.
pub struct ModelGateway {
    config: GatewayConfig,
    vault: Arc<CredentialVault>,
    adapters: HashMap<String, Arc<dyn ProviderAdapter>>,
    circuits: Mutex<HashMap<String, CircuitState>>,
}

impl ModelGateway {
    pub fn new(config: GatewayConfig, vault: Arc<CredentialVault>) -> Self {
        Self {
            config,
            vault,
            adapters: HashMap::new(),
            circuits: Mutex::new(HashMap::new()),
        }
    }

    pub fn register_adapter(&mut self, adapter: Arc<dyn ProviderAdapter>) {
        self.adapters
            .insert(adapter.provider_name().to_string(), adapter);
    }

    fn circuit_open(&self, provider: &str) -> bool {
        let mut circuits = self.circuits.lock().unwrap();
        let state = circuits.entry(provider.to_string()).or_default();
        match state.opened_at {
            Some(opened) if opened.elapsed() < self.config.outage_cooldown => true,
            Some(_) => {
                state.opened_at = None;
                state.consecutive_failures = 0;
                false
            }
            None => false,
        }
    }

    fn record_failure(&self, provider: &str) {
        let mut circuits = self.circuits.lock().unwrap();
        let state = circuits.entry(provider.to_string()).or_default();
        state.consecutive_failures += 1;
        if state.consecutive_failures >= self.config.outage_threshold {
            state.opened_at = Some(Instant::now());
        }
    }

    fn record_success(&self, provider: &str) {
        let mut circuits = self.circuits.lock().unwrap();
        if let Some(state) = circuits.get_mut(provider) {
            state.consecutive_failures = 0;
        }
    }

    /// Run one model request through policy, budget, retry, and metering.
    pub async fn complete(
        &self,
        request: &ModelRequest,
        policy: &ModelPolicy,
        pool: &dyn SpendPool,
    ) -> Result<GatewayResponse, GatewayError> {
        if !policy.permits(&request.provider, &request.model) {
            return Err(GatewayError::PolicyDenied {
                provider: request.provider.clone(),
                model: request.model.clone(),
            });
        }
        if request.max_output_tokens > policy.max_output_tokens {
            return Err(GatewayError::PolicyDenied {
                provider: request.provider.clone(),
                model: request.model.clone(),
            });
        }
        let adapter = self
            .adapters
            .get(&request.provider)
            .ok_or_else(|| GatewayError::UnknownProvider(request.provider.clone()))?;
        let credential = self
            .vault
            .get(&request.provider)
            .ok_or_else(|| GatewayError::MissingCredential(request.provider.clone()))?;
        if self.circuit_open(&request.provider) {
            return Err(GatewayError::ProviderOutage(request.provider.clone()));
        }
        // Reserve the per-request ceiling up front; the reservation is
        // released or committed once the true cost is known.
        let ceiling = policy.max_cost_micros_per_request;
        if !pool.try_reserve(ceiling) {
            return Err(GatewayError::BudgetDenied(format!(
                "cannot reserve {ceiling} micro-credits{}",
                if pool.quarantined() {
                    " (pool quarantined)"
                } else {
                    ""
                }
            )));
        }

        let start = Instant::now();
        let mut last_error = String::new();
        for attempt in 1..=self.config.max_attempts {
            if request.cancel.is_cancelled() {
                pool.release(ceiling);
                return Err(GatewayError::Cancelled);
            }
            let attempt_future = adapter.complete(request, &credential, &request.cancel);
            match tokio::time::timeout(self.config.attempt_timeout, attempt_future).await {
                Ok(Ok(completion)) => {
                    self.record_success(&request.provider);
                    // Usage is known only when the provider reported
                    // token counts AND cost. A missing cost is unknown
                    // usage, not zero cost: committing it as zero would
                    // under-bill the spend pool, so the ceiling is
                    // conservatively committed and the pool quarantined
                    // until the host reconciles out of band.
                    let usage_known = completion.input_tokens.is_some()
                        && completion.output_tokens.is_some()
                        && completion.cost_micros.is_some();
                    let cost_micros = if usage_known {
                        let cost = completion.cost_micros.unwrap_or(0);
                        pool.release(ceiling);
                        pool.commit(cost);
                        cost
                    } else {
                        pool.commit_unknown(ceiling);
                        ceiling
                    };
                    let usage = NormalizedUsage {
                        provider: request.provider.clone(),
                        model: request.model.clone(),
                        input_tokens: completion.input_tokens.unwrap_or(0),
                        output_tokens: completion.output_tokens.unwrap_or(0),
                        cost_micros,
                        latency_ms: start.elapsed().as_millis() as u64,
                        usage_known,
                    };
                    return Ok(GatewayResponse {
                        content: completion.content,
                        usage,
                    });
                }
                Ok(Err(ProviderError::Hard(message))) => {
                    self.record_failure(&request.provider);
                    pool.release(ceiling);
                    return Err(GatewayError::ProviderFailed {
                        attempts: attempt,
                        last: message,
                    });
                }
                Ok(Err(ProviderError::Cancelled)) => {
                    // Cancelled mid-flight: the provider may already have
                    // done (and billed) the work, so spend is unknown.
                    // Conservatively commit the ceiling and quarantine --
                    // no new spend until the host reconciles -- instead
                    // of releasing the attempt as known-zero spend, and
                    // never retry a cancelled attempt (a retry could
                    // double-spend).
                    pool.commit_unknown(ceiling);
                    return Err(GatewayError::Cancelled);
                }
                Ok(Err(ProviderError::Transient(message))) => {
                    last_error = message;
                    self.record_failure(&request.provider);
                    // Bounded retry: release this attempt's reservation
                    // BEFORE reserving the next attempt's, so at most one
                    // ceiling is ever held. A retry proceeds only when
                    // attempts remain and the pool can still cover another
                    // attempt's ceiling.
                    pool.release(ceiling);
                    if attempt < self.config.max_attempts && pool.try_reserve(ceiling) {
                        tokio::time::sleep(self.config.retry_backoff).await;
                        continue;
                    }
                    return Err(GatewayError::ProviderFailed {
                        attempts: attempt,
                        last: last_error.clone(),
                    });
                }
                Ok(Err(ProviderError::Timeout)) => {
                    // A provider-reported timeout may still have incurred
                    // spend on the provider side. Conservatively commit
                    // the ceiling and quarantine instead of retrying: a
                    // retry could double-spend, and releasing without
                    // quarantine would treat the attempt as known-zero
                    // spend.
                    self.record_failure(&request.provider);
                    pool.commit_unknown(ceiling);
                    return Err(GatewayError::ProviderFailed {
                        attempts: attempt,
                        last: "provider timed out".to_string(),
                    });
                }
                Err(_) => {
                    // The gateway's own attempt timeout fired: the
                    // attempt's spend is unknowable, so the same
                    // conservative-commit-and-quarantine rule applies as
                    // for a provider timeout. No retry: the timed-out
                    // attempt may already have spent.
                    self.record_failure(&request.provider);
                    pool.commit_unknown(ceiling);
                    return Err(GatewayError::ProviderFailed {
                        attempts: attempt,
                        last: "attempt timed out".to_string(),
                    });
                }
            }
        }
        pool.release(ceiling);
        Err(GatewayError::ProviderFailed {
            attempts: self.config.max_attempts,
            last: last_error,
        })
    }
}

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/// Scripted provider adapter for tests.
#[derive(Debug)]
pub struct MockProviderAdapter {
    name: String,
    script: Mutex<VecDeque<MockProviderOutcome>>,
    calls: Mutex<u32>,
    seen_credential: Mutex<bool>,
}

#[derive(Debug, Clone)]
pub enum MockProviderOutcome {
    Ok {
        content: String,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
        cost_micros: Option<u64>,
    },
    Transient(String),
    Hard(String),
    Timeout,
    Hang,
}

impl MockProviderAdapter {
    pub fn new(name: impl Into<String>, script: Vec<MockProviderOutcome>) -> Self {
        Self {
            name: name.into(),
            script: Mutex::new(script.into_iter().collect()),
            calls: Mutex::new(0),
            seen_credential: Mutex::new(false),
        }
    }

    pub fn calls(&self) -> u32 {
        *self.calls.lock().unwrap()
    }

    /// True once the adapter has observed a non-empty credential.
    pub fn saw_credential(&self) -> bool {
        *self.seen_credential.lock().unwrap()
    }
}

impl ProviderAdapter for MockProviderAdapter {
    fn provider_name(&self) -> &str {
        &self.name
    }

    fn complete<'a>(
        &'a self,
        _request: &'a ModelRequest,
        credential: &'a SecretString,
        cancel: &'a CancellationToken,
    ) -> ProviderFuture<'a, ProviderCompletion> {
        Box::pin(async move {
            *self.calls.lock().unwrap() += 1;
            *self.seen_credential.lock().unwrap() = !credential.expose().is_empty();
            let outcome =
                self.script
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(MockProviderOutcome::Ok {
                        content: "mock reply".to_string(),
                        input_tokens: Some(10),
                        output_tokens: Some(5),
                        cost_micros: Some(3),
                    });
            match outcome {
                MockProviderOutcome::Ok {
                    content,
                    input_tokens,
                    output_tokens,
                    cost_micros,
                } => Ok(ProviderCompletion {
                    content,
                    input_tokens,
                    output_tokens,
                    cost_micros,
                }),
                MockProviderOutcome::Transient(message) => Err(ProviderError::Transient(message)),
                MockProviderOutcome::Hard(message) => Err(ProviderError::Hard(message)),
                MockProviderOutcome::Timeout => Err(ProviderError::Timeout),
                MockProviderOutcome::Hang => {
                    cancel.cancelled().await;
                    Err(ProviderError::Cancelled)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_gateway(
        script: Vec<MockProviderOutcome>,
    ) -> (ModelGateway, Arc<MockProviderAdapter>, Arc<MemorySpendPool>) {
        let vault = Arc::new(CredentialVault::new());
        vault.insert("acme", SecretString::new("sk-test"));
        let mut gateway = ModelGateway::new(GatewayConfig::default(), vault);
        let adapter = Arc::new(MockProviderAdapter::new("acme", script));
        gateway.register_adapter(adapter.clone());
        let pool = Arc::new(MemorySpendPool::new(1_000_000));
        (gateway, adapter, pool)
    }

    fn request() -> ModelRequest {
        ModelRequest {
            provider: "acme".to_string(),
            model: "acme-large".to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: "hi".to_string(),
            }],
            max_output_tokens: 100,
            cancel: CancellationToken::new(),
        }
    }

    fn policy() -> ModelPolicy {
        ModelPolicy {
            allowed_models: vec!["acme-large".to_string()],
            allowed_providers: vec!["acme".to_string()],
            max_cost_micros_per_request: 1000,
            max_output_tokens: 1000,
        }
    }

    #[tokio::test]
    async fn policy_denies_unlisted_model() {
        let (gateway, _, pool) = test_gateway(vec![]);
        let mut req = request();
        req.model = "acme-ultra".to_string();
        let err = gateway
            .complete(&req, &policy(), pool.as_ref())
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayError::PolicyDenied { .. }));
    }

    #[tokio::test]
    async fn success_meters_and_debits() {
        let (gateway, adapter, pool) = test_gateway(vec![]);
        let before = pool.balance();
        let response = gateway
            .complete(&request(), &policy(), pool.as_ref())
            .await
            .unwrap();
        assert_eq!(response.content, "mock reply");
        assert!(response.usage.usage_known);
        assert_eq!(response.usage.input_tokens, 10);
        assert_eq!(pool.balance(), before - 3);
        assert!(adapter.saw_credential());

        let record = response.redacted_audit_record();
        let serialized = serde_json::to_string(&record).unwrap();
        assert!(!serialized.contains("mock reply"));
        assert!(!serialized.contains("sk-test"));
        assert_eq!(record.content_digest.len(), 64);
    }

    #[tokio::test]
    async fn unknown_usage_quarantines_pool() {
        let (gateway, _, pool) = test_gateway(vec![MockProviderOutcome::Ok {
            content: "x".to_string(),
            input_tokens: None,
            output_tokens: None,
            cost_micros: None,
        }]);
        let before = pool.balance();
        let response = gateway
            .complete(&request(), &policy(), pool.as_ref())
            .await
            .unwrap();
        assert!(!response.usage.usage_known);
        assert!(pool.quarantined());
        // Unknown usage conservatively commits the request ceiling:
        // the attempt may have spent up to the ceiling.
        assert_eq!(pool.balance(), before - 1000);

        // No new spend while quarantined.
        let (gateway2, _, _) = test_gateway(vec![]);
        let err = gateway2
            .complete(&request(), &policy(), pool.as_ref())
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayError::BudgetDenied(_)));

        // Reconciliation reverses the ceiling debit, books the actual,
        // and lifts the quarantine -- never double-counting.
        pool.reconcile(7);
        assert!(!pool.quarantined());
        assert_eq!(pool.balance(), before - 7);
    }

    #[tokio::test]
    async fn missing_cost_is_unknown_usage_not_zero_cost() {
        // Tokens reported but no cost: usage is unknown, not zero.
        // Booking this as zero would under-bill the spend pool, so the
        // ceiling is conservatively committed instead.
        let (gateway, _, pool) = test_gateway(vec![MockProviderOutcome::Ok {
            content: "x".to_string(),
            input_tokens: Some(10),
            output_tokens: Some(5),
            cost_micros: None,
        }]);
        let before = pool.balance();
        let response = gateway
            .complete(&request(), &policy(), pool.as_ref())
            .await
            .unwrap();
        assert!(!response.usage.usage_known);
        // The usage record carries the conservative ceiling debit,
        // flagged as an estimate rather than a bill.
        assert_eq!(response.usage.cost_micros, 1000);
        assert!(pool.quarantined());
        assert_eq!(pool.balance(), before - 1000);

        // Reconciliation books the true cost and lifts the quarantine.
        pool.reconcile(9);
        assert!(!pool.quarantined());
        assert_eq!(pool.balance(), before - 9);
    }

    #[tokio::test]
    async fn provider_timeout_quarantines_without_retry() {
        let config = GatewayConfig {
            max_attempts: 3,
            ..GatewayConfig::default()
        };
        let vault = Arc::new(CredentialVault::new());
        vault.insert("acme", SecretString::new("sk-test"));
        let mut gateway = ModelGateway::new(config, vault);
        let adapter = Arc::new(MockProviderAdapter::new(
            "acme",
            vec![MockProviderOutcome::Timeout],
        ));
        gateway.register_adapter(adapter.clone());
        let pool = MemorySpendPool::new(1_000_000);

        let err = gateway
            .complete(&request(), &policy(), &pool)
            .await
            .unwrap_err();
        assert!(
            matches!(err, GatewayError::ProviderFailed { attempts: 1, ref last } if last == "provider timed out"),
            "unexpected error: {err:?}"
        );
        // No retry: the timed-out attempt may already have spent on the
        // provider side, and a retry could double-spend. The ceiling is
        // conservatively committed.
        assert_eq!(adapter.calls(), 1);
        assert!(pool.quarantined());
        assert_eq!(pool.balance(), 1_000_000 - 1000);

        // The host reconciles the true spend out of band: the ceiling
        // debit is reversed, the actual booked, never double-counted.
        pool.reconcile(500);
        assert!(!pool.quarantined());
        assert_eq!(pool.balance(), 1_000_000 - 500);
    }

    #[tokio::test]
    async fn gateway_attempt_timeout_quarantines_without_retry() {
        let config = GatewayConfig {
            attempt_timeout: Duration::from_millis(50),
            max_attempts: 3,
            ..GatewayConfig::default()
        };
        let vault = Arc::new(CredentialVault::new());
        vault.insert("acme", SecretString::new("sk-test"));
        let mut gateway = ModelGateway::new(config, vault);
        let adapter = Arc::new(MockProviderAdapter::new(
            "acme",
            vec![MockProviderOutcome::Hang],
        ));
        gateway.register_adapter(adapter.clone());
        let pool = MemorySpendPool::new(1_000_000);

        let err = gateway
            .complete(&request(), &policy(), &pool)
            .await
            .unwrap_err();
        assert!(
            matches!(err, GatewayError::ProviderFailed { attempts: 1, ref last } if last == "attempt timed out"),
            "unexpected error: {err:?}"
        );
        assert_eq!(adapter.calls(), 1);
        assert!(pool.quarantined());
    }

    #[tokio::test]
    async fn midflight_cancellation_quarantines_pool() {
        let (gateway, adapter, pool) = test_gateway(vec![MockProviderOutcome::Hang]);
        let req = request();
        let cancel = req.cancel.clone();
        let pool_for_task = Arc::clone(&pool);
        let handle = tokio::spawn(async move {
            gateway
                .complete(&req, &policy(), pool_for_task.as_ref())
                .await
        });
        // Wait for the attempt to start, then cancel mid-flight.
        for _ in 0..100 {
            if adapter.calls() >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(adapter.calls(), 1);
        cancel.cancel();
        let err = handle.await.unwrap().unwrap_err();
        assert!(matches!(err, GatewayError::Cancelled));
        // The cancelled attempt may have incurred provider spend:
        // conservatively commit the ceiling and quarantine the pool;
        // never retry a cancelled attempt.
        assert_eq!(adapter.calls(), 1);
        assert!(pool.quarantined());
        assert_eq!(pool.balance(), 1_000_000 - 1000);
    }

    #[tokio::test]
    async fn bounded_retry_then_gives_up() {
        let (gateway, adapter, pool) = test_gateway(vec![
            MockProviderOutcome::Transient("boom".to_string()),
            MockProviderOutcome::Transient("boom".to_string()),
            MockProviderOutcome::Transient("boom".to_string()),
        ]);
        let err = gateway
            .complete(&request(), &policy(), pool.as_ref())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GatewayError::ProviderFailed { attempts: 2, .. }
        ));
        assert_eq!(adapter.calls(), 2);
    }

    #[tokio::test]
    async fn hard_failure_does_not_retry() {
        let (gateway, adapter, pool) =
            test_gateway(vec![MockProviderOutcome::Hard("nope".to_string())]);
        let err = gateway
            .complete(&request(), &policy(), pool.as_ref())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GatewayError::ProviderFailed { attempts: 1, .. }
        ));
        assert_eq!(adapter.calls(), 1);
    }

    #[tokio::test]
    async fn outage_circuit_opens_after_threshold() {
        let config = GatewayConfig {
            outage_threshold: 2,
            outage_cooldown: Duration::from_secs(60),
            max_attempts: 1,
            ..GatewayConfig::default()
        };
        let vault = Arc::new(CredentialVault::new());
        vault.insert("acme", SecretString::new("sk-test"));
        let mut gateway = ModelGateway::new(config, vault);
        let adapter = Arc::new(MockProviderAdapter::new(
            "acme",
            vec![
                MockProviderOutcome::Hard("down".to_string()),
                MockProviderOutcome::Hard("down".to_string()),
                MockProviderOutcome::Hard("down".to_string()),
            ],
        ));
        gateway.register_adapter(adapter.clone());
        let pool = MemorySpendPool::new(1_000_000);

        for _ in 0..2 {
            let _ = gateway.complete(&request(), &policy(), &pool).await;
        }
        let err = gateway
            .complete(&request(), &policy(), &pool)
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayError::ProviderOutage(_)));
        assert_eq!(adapter.calls(), 2);
    }

    #[tokio::test]
    async fn cancellation_aborts_without_spend() {
        let (gateway, _, pool) = test_gateway(vec![MockProviderOutcome::Hang]);
        let req = request();
        req.cancel.cancel();
        let before = pool.balance();
        let err = gateway
            .complete(&req, &policy(), pool.as_ref())
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayError::Cancelled));
        assert_eq!(pool.balance(), before);
    }

    #[test]
    fn secret_is_redacted_in_debug() {
        let secret = SecretString::new("sk-live-123");
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("sk-live-123"));
    }
}
