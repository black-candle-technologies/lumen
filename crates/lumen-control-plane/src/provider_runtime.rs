use lumen_core::{
    identity::WorkspaceId,
    model::ModelInput,
    provider::{
        ModelProfile, ProviderAdapter, ProviderConfig, ProviderError, ProviderFuture, ProviderKind,
        validate_binding,
    },
};
use lumen_db::Database;
use lumen_integrations::{
    providers::{
        ProviderCredential, ProviderHttpOptions, anthropic::AnthropicAdapter,
        openai::OpenAiAdapter, openai_compatible::OpenAiCompatibleAdapter,
    },
    secrets::SecretStore,
};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

// Narrow hook implemented by the CLI's shared SecretRedactor.
// It is not exposed to models/plugins and must not log or serialize the value.
pub trait ProviderSecretObserver: Send + Sync {
    fn observe(&self, value: &str);
    fn contains_secret(&self, value: &str) -> bool;
}

#[derive(Clone)]
pub struct DatabaseProviderFactory {
    database: Database,
    store: Arc<dyn SecretStore>,
    observer: Arc<dyn ProviderSecretObserver>,
    http_client: Option<reqwest::Client>,
}
impl DatabaseProviderFactory {
    pub fn new(
        database: Database,
        store: Arc<dyn SecretStore>,
        observer: Arc<dyn ProviderSecretObserver>,
    ) -> Self {
        Self {
            database,
            store,
            observer,
            http_client: None,
        }
    }
    /// Trusted host injection for tests with a local CA and a fixed DNS mapping.
    /// The production CLI always uses `new` and never supplies a custom client.
    #[doc(hidden)]
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }
    pub fn lazy(
        self: &Arc<Self>,
        workspace: WorkspaceId,
        config: ProviderConfig,
        options: ProviderHttpOptions,
    ) -> Arc<dyn ProviderAdapter> {
        self.lazy_with_execution(workspace, config, options, None, None)
    }
    pub fn lazy_with_execution(
        self: &Arc<Self>,
        workspace: WorkspaceId,
        config: ProviderConfig,
        options: ProviderHttpOptions,
        generation: Option<lumen_core::model::ModelGenerationConfig>,
        usage_sink: Option<Arc<dyn lumen_core::provider::ProviderUsageSink>>,
    ) -> Arc<dyn ProviderAdapter> {
        Arc::new(RegistryAdapter {
            factory: Arc::clone(self),
            workspace,
            config,
            options,
            generation,
            usage_sink,
        })
    }
    async fn resolve_and_build(
        &self,
        workspace: WorkspaceId,
        p: &ProviderConfig,
        options: ProviderHttpOptions,
    ) -> Result<Arc<dyn ProviderAdapter>, ProviderError> {
        // Only provider-purpose references may supply authentication material.
        self.database
            .require_current_provider(workspace, p)
            .await
            .map_err(|_| ProviderError::configuration("provider unavailable or changed"))?;
        let key = match p.credential_secret_ref() {
            Some(id) => {
                self.database
                    .require_ready_provider_reference(workspace, p, id)
                    .await
                    .map_err(|_| ProviderError::configuration("provider credential unavailable"))?;
                let account = format!("provider:{workspace}:{id}");
                let bytes = Zeroizing::new(self.store.resolve(&account).await.map_err(|_| {
                    ProviderError::configuration("provider credential unavailable")
                })?);
                let key = ProviderCredential::from_keyring(bytes)?;
                key.with_exposed_str(|value| self.observer.observe(value));
                Some(key)
            }
            None if p.endpoint_class() == lumen_core::egress::EndpointClass::Local => None,
            None => return Err(ProviderError::configuration("remote credential required")),
        };
        match p.kind() {
            ProviderKind::OpenAi => {
                let mut adapter = OpenAiAdapter::new_with_options(
                    p.clone(),
                    key.ok_or_else(|| ProviderError::configuration("credential required"))?,
                    options,
                )?;
                if let Some(client) = &self.http_client {
                    adapter = adapter.with_http_client(client.clone());
                }
                Ok(Arc::new(adapter))
            }
            ProviderKind::Anthropic => {
                let mut adapter = AnthropicAdapter::new_with_options(
                    p.clone(),
                    key.ok_or_else(|| ProviderError::configuration("credential required"))?,
                    options,
                )?;
                if let Some(client) = &self.http_client {
                    adapter = adapter.with_http_client(client.clone());
                }
                Ok(Arc::new(adapter))
            }
            ProviderKind::OpenAiCompatible => {
                let mut adapter =
                    OpenAiCompatibleAdapter::new_with_options(p.clone(), key, options)?;
                if let Some(client) = &self.http_client {
                    adapter = adapter.with_http_client(client.clone());
                }
                Ok(Arc::new(adapter))
            }
        }
    }
}

struct RegistryAdapter {
    factory: Arc<DatabaseProviderFactory>,
    workspace: WorkspaceId,
    config: ProviderConfig,
    options: ProviderHttpOptions,
    generation: Option<lumen_core::model::ModelGenerationConfig>,
    usage_sink: Option<Arc<dyn lumen_core::provider::ProviderUsageSink>>,
}
impl ProviderAdapter for RegistryAdapter {
    fn config(&self) -> &ProviderConfig {
        &self.config
    }
    fn generate<'a>(
        &'a self,
        profile: &'a ModelProfile,
        input: ModelInput,
        cancel: CancellationToken,
    ) -> ProviderFuture<'a> {
        Box::pin(async move {
            validate_binding(&self.config, profile)?;
            tokio::select! {
                biased;
                _ = cancel.cancelled() => Err(ProviderError::cancelled()),
                response = async {
                    if self.config.endpoint_class() == lumen_core::egress::EndpointClass::Remote {
                        // Workers retain their projection gates and pinned assignment. Recheck the
                        // exact egress mirror here as well, so later policy edits cannot authorize
                        // a different destination or let a queued worker use stale permission.
                        let snapshot = self.factory.database.registered_model_snapshot(
                            self.workspace, profile.id(), profile.revision()
                        ).await.map_err(|_|ProviderError::configuration("provider selection unavailable or changed"))?;
                        if snapshot.provider != self.config || snapshot.profile != *profile {
                            return Err(ProviderError::configuration("provider selection unavailable or changed"));
                        }
                        lumen_core::egress::select_model_provider(input.data_class(), [snapshot.route])
                            .map_err(|_|ProviderError::configuration("model egress denied"))?;
                    } else if self.factory.database.latest_model_profile(profile.id()).await
                        .map_err(|_|ProviderError::configuration("provider profile unavailable"))?.as_ref()!=Some(profile) {
                        return Err(ProviderError::configuration("provider profile unavailable or changed"));
                    }
                    let adapter = self.factory.resolve_and_build(
                        self.workspace, &self.config, self.options
                    ).await?;
                    let input=match &self.generation {Some(generation)=>input.with_generation(generation.clone()),None=>input};
                    let response = tokio::time::timeout(self.options.timeout, adapter.generate(profile, input, cancel.child_token())).await
                        .map_err(|_|ProviderError::transport("provider request timed out"))??;
                    if response_contains_secret(self.factory.observer.as_ref(), &response) {
                        return Err(ProviderError::protocol("provider response contains credential material"));
                    }
                    if let Some(sink)=&self.usage_sink {
                        sink.record(lumen_core::provider::ProviderUsageEvent::new(response.resolved_model.clone(),response.usage)?).await
                            .map_err(|_|ProviderError::protocol("provider usage recording failed"))?;
                    }
                    Ok(response)
                } => response,
            }
        })
    }
}

fn response_contains_secret(
    observer: &dyn ProviderSecretObserver,
    response: &lumen_core::provider::ProviderResponse,
) -> bool {
    use lumen_core::{action::CanonicalValue, model::ModelOutput};
    fn value(observer: &dyn ProviderSecretObserver, v: &CanonicalValue) -> bool {
        match v {
            CanonicalValue::String(s) => observer.contains_secret(s),
            CanonicalValue::Array(items) => items.iter().any(|v| value(observer, v)),
            CanonicalValue::Object(items) => items
                .iter()
                .any(|(k, v)| observer.contains_secret(k) || value(observer, v)),
            _ => false,
        }
    }
    observer.contains_secret(&response.resolved_model)
        || match &response.output {
            ModelOutput::FinalText(text) => observer.contains_secret(text),
            ModelOutput::Action(action) => {
                observer.contains_secret(action.kind())
                    || value(observer, &action.clone().into_arguments())
                    || action.tool_call().is_some_and(|call| {
                        observer.contains_secret(call.id())
                            || observer.contains_secret(call.name())
                            || value(observer, call.arguments())
                    })
            }
        }
}

use lumen_core::{
    action::RunId,
    approval::TimestampMillis,
    audit::{AuditEvent, AuditEventId, AuditEventKind, AuditOutcome},
    egress::{DataClass, EndpointClass},
    model::ModelError,
    provider::ModelProfileId,
};
use lumen_db::RegisteredModelSnapshot;
use serde_json::json;
pub struct RegisteredModelPort {
    pub database: Database,
    pub factory: Arc<DatabaseProviderFactory>,
    pub workspace: WorkspaceId,
    pub profile_id: ModelProfileId,
    pub profile_revision: u64,
    pub allow_remote: bool,
    pub options: ProviderHttpOptions,
    pub cancel: CancellationToken,
    pub usage_sink: Option<Arc<dyn lumen_core::provider::ProviderUsageSink>>,
    pub run_id: Option<RunId>, // planner has a separate correlation, not a fake run
}
impl lumen_core::model::ModelPort for RegisteredModelPort {
    fn generate(&self, input: ModelInput) -> lumen_core::model::ModelFuture<'_> {
        Box::pin(async move {
            let operation = async {
                let snapshot = self
                    .database
                    .registered_model_snapshot(
                        self.workspace,
                        &self.profile_id,
                        self.profile_revision,
                    )
                    .await
                    .map_err(|_| ModelError::new("registered provider selection unavailable"))?;
                if snapshot.provider.endpoint_class() == EndpointClass::Remote && !self.allow_remote
                {
                    return Err(ModelError::new("remote model use is disabled"));
                }
                let data_class = input.data_class();
                // Crucial: evaluate ONLY the route for the transport we will use.
                let decision =
                    lumen_core::egress::select_model_provider(data_class, [snapshot.route.clone()])
                        .map_err(|_| ModelError::new("model egress denied"));
                if let Err(error) = decision {
                    record_model_request_event(
                        &self.database,
                        self.workspace,
                        self.run_id,
                        &snapshot,
                        data_class,
                        "denied",
                    )
                    .await?;
                    return Err(error);
                }
                // Audit the authorization BEFORE touching keyring or network.
                // This is not yet a successful request / proof that egress occurred.
                record_model_request_event(
                    &self.database,
                    self.workspace,
                    self.run_id,
                    &snapshot,
                    data_class,
                    "authorized",
                )
                .await?;
                let adapter =
                    self.factory
                        .lazy(self.workspace, snapshot.provider.clone(), self.options);
                let response = adapter
                    .generate(&snapshot.profile, input, self.cancel.child_token())
                    .await;
                let phase = if response.is_ok() {
                    "completed"
                } else {
                    "failed_or_cancelled"
                };
                record_model_request_event(
                    &self.database,
                    self.workspace,
                    self.run_id,
                    &snapshot,
                    data_class,
                    phase,
                )
                .await?;
                if let (Some(sink), Ok(value)) = (&self.usage_sink, &response) {
                    sink.record(
                        lumen_core::provider::ProviderUsageEvent::new(
                            value.resolved_model.clone(),
                            value.usage,
                        )
                        .map_err(|_| ModelError::new("invalid provider usage"))?,
                    )
                    .await
                    .map_err(|_| ModelError::new("provider usage recording failed"))?;
                }
                response
                    .map(|value| value.output)
                    .map_err(|_| ModelError::new("provider request failed"))
            };
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => Err(ModelError::new("model request cancelled")),
                result = operation => result,
            }
        })
    }
}

async fn record_model_request_event(
    database: &Database,
    workspace: WorkspaceId,
    run_id: Option<RunId>,
    snapshot: &RegisteredModelSnapshot,
    class: DataClass,
    phase: &str,
) -> Result<(), ModelError> {
    let outcome = match phase {
        "authorized" => AuditOutcome::Pending,
        "denied" => AuditOutcome::Denied,
        "completed" => AuditOutcome::Success,
        _ => AuditOutcome::Failure,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let payload = json!({"run_id":run_id.map(|id|id.to_string()),"phase":phase,"provider_id":snapshot.provider.id().as_str(),"provider_revision":snapshot.provider.revision(),"profile_id":snapshot.profile.id().as_str(),"profile_revision":snapshot.profile.revision(),"egress_revision":snapshot.egress_revision,"workspace_policy_revision":snapshot.workspace_policy_revision,"data_class":class});
    database
        .append_audit_event(AuditEvent::new(
            AuditEventId::new(),
            TimestampMillis::new(u64::try_from(now).unwrap_or(u64::MAX)),
            AuditEventKind::ModelEgress,
            outcome,
            Some(workspace),
            serde_json::from_value(payload).expect("safe metadata"),
        ))
        .await
        .map_err(|_| ModelError::new("model request audit failed"))?;
    Ok(())
}
