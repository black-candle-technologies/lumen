use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use lumen_core::{
    action::{ActionKind, CanonicalValue},
    extension::{
        ExtensionFailure, ExtensionFailureClass, ExtensionInvocationLimits, ExtensionResponse,
        Sha256Digest,
    },
};
use lumen_extension_sdk::{
    FailureClass as WireFailureClass, InvocationRequest, InvocationResponse,
    Response as WireResponse, WireContractError,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;
use wasmtime::component::{
    Component, Linker,
    types::{ComponentItem, Type},
};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder, Trap};

const MAX_COMPONENT_INSTANCES: usize = 64;
const MAX_COMPONENT_MEMORIES: usize = 4;
const MAX_COMPONENT_TABLES: usize = 16;
const MAX_TABLE_ELEMENTS: usize = 100_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompilationMetadata {
    artifact_digest: Sha256Digest,
    target: String,
    engine_version: &'static str,
}

impl CompilationMetadata {
    pub const fn artifact_digest(&self) -> &Sha256Digest {
        &self.artifact_digest
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub const fn engine_version(&self) -> &'static str {
        self.engine_version
    }
}

struct CompiledComponent {
    engine: Engine,
    component: Component,
    invocation_lock: AsyncMutex<()>,
    metadata: CompilationMetadata,
}

#[derive(Clone, Default)]
pub struct WasmComponentHost {
    compiled: Arc<Mutex<BTreeMap<Sha256Digest, Arc<CompiledComponent>>>>,
}

impl WasmComponentHost {
    pub fn validate_component(
        &self,
        artifact_digest: Sha256Digest,
        bytes: Arc<[u8]>,
    ) -> Result<CompilationMetadata, WasmHostError> {
        verify_digest(&artifact_digest, &bytes)?;
        Ok(self
            .get_or_compile(artifact_digest, &bytes)?
            .metadata
            .clone())
    }

    pub fn compilation_metadata(&self) -> Vec<CompilationMetadata> {
        self.compiled
            .lock()
            .expect("WASM compilation cache lock poisoned")
            .values()
            .map(|component| component.metadata.clone())
            .collect()
    }

    pub async fn invoke(
        &self,
        artifact_digest: Sha256Digest,
        bytes: Arc<[u8]>,
        request: InvocationRequest,
        limits: ExtensionInvocationLimits,
        cancellation: CancellationToken,
    ) -> Result<ExtensionResponse, WasmHostError> {
        if cancellation.is_cancelled() {
            return Err(WasmHostError::Cancelled);
        }
        verify_digest(&artifact_digest, &bytes)?;
        let compiled = self.get_or_compile(artifact_digest, &bytes)?;
        let _invocation = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(WasmHostError::Cancelled),
            lock = compiled.invocation_lock.lock() => lock,
        };
        if cancellation.is_cancelled() {
            return Err(WasmHostError::Cancelled);
        }

        let encoded_request = request.encode().map_err(WasmHostError::from)?;
        let expected_request_id = request.request_id().to_owned();
        let expected_protocol = request.protocol_version();
        let engine = compiled.engine.clone();
        let component = compiled.component.clone();
        let interruption = Arc::new(AtomicU8::new(0));
        let interruption_task = {
            let engine = engine.clone();
            let interruption = Arc::clone(&interruption);
            let cancellation = cancellation.clone();
            let deadline = Duration::from_millis(limits.deadline_millis());
            tokio::spawn(async move {
                tokio::select! {
                    biased;
                    () = cancellation.cancelled() => interruption.store(2, Ordering::Release),
                    () = tokio::time::sleep(deadline) => interruption.store(1, Ordering::Release),
                }
                engine.increment_epoch();
            })
        };

        let worker = tokio::task::spawn_blocking(move || {
            execute_component(&engine, &component, &encoded_request, limits)
        });
        let execution = worker.await;
        interruption_task.abort();
        let execution = execution.map_err(|error| {
            WasmHostError::Host(format!("WASM execution worker failed: {error}"))
        })?;

        let encoded_response = match execution {
            Ok(response) => response,
            Err(ExecutionError::Instantiation(message)) => {
                return Err(WasmHostError::Instantiation(message));
            }
            Err(ExecutionError::ResourceExhaustion) => {
                return Err(WasmHostError::ResourceExhaustion);
            }
            Err(ExecutionError::Guest(error)) => {
                return Err(classify_guest_error(
                    error,
                    interruption.load(Ordering::Acquire),
                ));
            }
        };
        let response =
            InvocationResponse::decode_bounded(&encoded_response, limits.max_result_bytes())?
                .validate_for(expected_protocol, &expected_request_id)
                .map_err(WasmHostError::from)?;
        wire_response_to_core(response)
    }

    fn get_or_compile(
        &self,
        artifact_digest: Sha256Digest,
        bytes: &[u8],
    ) -> Result<Arc<CompiledComponent>, WasmHostError> {
        let mut cache = self
            .compiled
            .lock()
            .expect("WASM compilation cache lock poisoned");
        if let Some(compiled) = cache.get(&artifact_digest) {
            return Ok(Arc::clone(compiled));
        }

        let mut config = Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config).map_err(|error| {
            WasmHostError::Host(format!("failed to configure Wasmtime: {error}"))
        })?;
        let component = Component::new(&engine, bytes)
            .map_err(|error| WasmHostError::InvalidComponent(format!("{error:#}")))?;
        validate_world(&engine, &component)?;
        let metadata = CompilationMetadata {
            artifact_digest: artifact_digest.clone(),
            target: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
            engine_version: "46",
        };
        let compiled = Arc::new(CompiledComponent {
            engine,
            component,
            invocation_lock: AsyncMutex::new(()),
            metadata,
        });
        cache.insert(artifact_digest, Arc::clone(&compiled));
        Ok(compiled)
    }
}

fn execute_component(
    engine: &Engine,
    component: &Component,
    encoded_request: &str,
    limits: ExtensionInvocationLimits,
) -> Result<String, ExecutionError> {
    let memory_size = usize::try_from(limits.max_memory_bytes()).unwrap_or(usize::MAX);
    let state = HostState {
        limits: StoreLimitsBuilder::new()
            .memory_size(memory_size)
            .instances(MAX_COMPONENT_INSTANCES)
            .memories(MAX_COMPONENT_MEMORIES)
            .tables(MAX_COMPONENT_TABLES)
            .table_elements(MAX_TABLE_ELEMENTS)
            .trap_on_grow_failure(true)
            .build(),
    };
    let mut store = Store::new(engine, state);
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(limits.fuel())
        .map_err(ExecutionError::Guest)?;
    store.set_epoch_deadline(1);
    store.epoch_deadline_trap();

    // An empty linker is the authority boundary: no WASI or host capability is linked.
    let linker = Linker::<HostState>::new(engine);
    let instance = linker.instantiate(&mut store, component).map_err(|error| {
        let message = format!("{error:#}");
        if is_resource_error(&message) {
            ExecutionError::ResourceExhaustion
        } else {
            ExecutionError::Instantiation(message)
        }
    })?;
    let invoke = instance
        .get_typed_func::<(&str,), (String,)>(&mut store, "invoke")
        .map_err(|error| ExecutionError::Instantiation(error.to_string()))?;
    let (response,) = invoke
        .call(&mut store, (encoded_request,))
        .map_err(ExecutionError::Guest)?;
    Ok(response)
}

fn verify_digest(expected: &Sha256Digest, bytes: &[u8]) -> Result<(), WasmHostError> {
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != expected.as_str() {
        return Err(WasmHostError::ArtifactDigestMismatch);
    }
    Ok(())
}

fn wire_response_to_core(response: WireResponse) -> Result<ExtensionResponse, WasmHostError> {
    match response {
        WireResponse::Result { value } => Ok(ExtensionResponse::result(canonical_value(value)?)),
        WireResponse::Proposal { kind, arguments } => Ok(ExtensionResponse::proposal(
            ActionKind::new(kind).map_err(|_| WasmHostError::InvalidResponse)?,
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
                .map_err(|_| WasmHostError::InvalidResponse)?;
            Ok(ExtensionResponse::failure(failure))
        }
    }
}

fn canonical_value(value: serde_json::Value) -> Result<CanonicalValue, WasmHostError> {
    serde_json::from_value(value).map_err(|_| WasmHostError::InvalidResponse)
}

fn validate_world(engine: &Engine, component: &Component) -> Result<(), WasmHostError> {
    let component_type = component.component_type();
    if component_type.imports(engine).next().is_some() {
        return Err(WasmHostError::InvalidComponent(
            "the Lumen extension world permits no imports".to_owned(),
        ));
    }
    let mut exports = component_type.exports(engine);
    let Some(("invoke", export)) = exports.next() else {
        return Err(WasmHostError::InvalidComponent(
            "the Lumen extension world requires an invoke export".to_owned(),
        ));
    };
    if exports.next().is_some() {
        return Err(WasmHostError::InvalidComponent(
            "the Lumen extension world permits only the invoke export".to_owned(),
        ));
    }
    let ComponentItem::ComponentFunc(function) = export.ty else {
        return Err(WasmHostError::InvalidComponent(
            "the invoke export must be a component function".to_owned(),
        ));
    };
    let params = function.params().collect::<Vec<_>>();
    let results = function.results().collect::<Vec<_>>();
    if function.async_()
        || !matches!(params.as_slice(), [("request", Type::String)])
        || !matches!(results.as_slice(), [Type::String])
    {
        return Err(WasmHostError::InvalidComponent(
            "invoke must have the synchronous signature func(request: string) -> string".to_owned(),
        ));
    }
    Ok(())
}

fn classify_guest_error(error: wasmtime::Error, interruption: u8) -> WasmHostError {
    if let Some(trap) = error.downcast_ref::<Trap>() {
        return match trap {
            Trap::OutOfFuel => WasmHostError::ResourceExhaustion,
            Trap::Interrupt if interruption == 2 => WasmHostError::Cancelled,
            Trap::Interrupt if interruption == 1 => WasmHostError::DeadlineExceeded,
            _ => WasmHostError::Trap(error.to_string()),
        };
    }
    let message = error.to_string();
    if is_resource_error(&message) {
        WasmHostError::ResourceExhaustion
    } else {
        WasmHostError::Trap(message)
    }
}

fn is_resource_error(message: &str) -> bool {
    message.contains("resource limit")
        || message.contains("memory limit")
        || message.contains("memory minimum size")
        || message.contains("table minimum size")
        || message.contains("forcing trap when growing memory")
        || message.contains("forcing trap when growing table")
        || message.contains("instance limit")
}

struct HostState {
    limits: StoreLimits,
}

enum ExecutionError {
    Instantiation(String),
    ResourceExhaustion,
    Guest(wasmtime::Error),
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WasmHostError {
    #[error("extension artifact digest did not match the approved digest")]
    ArtifactDigestMismatch,
    #[error("extension artifact is not a valid component: {0}")]
    InvalidComponent(String),
    #[error("extension component could not be instantiated: {0}")]
    Instantiation(String),
    #[error("extension component trapped: {0}")]
    Trap(String),
    #[error("extension component exhausted a resource limit")]
    ResourceExhaustion,
    #[error("extension component exceeded its deadline")]
    DeadlineExceeded,
    #[error("extension invocation was cancelled")]
    Cancelled,
    #[error("extension response exceeded its configured limit")]
    ResponseTooLarge,
    #[error("extension response used a different protocol version")]
    ProtocolMismatch,
    #[error("extension response used a different request ID")]
    RequestMismatch,
    #[error("extension response was malformed")]
    InvalidResponse,
    #[error("extension host failed: {0}")]
    Host(String),
}

impl From<WireContractError> for WasmHostError {
    fn from(error: WireContractError) -> Self {
        match error {
            WireContractError::ResponseTooLarge => Self::ResponseTooLarge,
            WireContractError::ProtocolMismatch => Self::ProtocolMismatch,
            WireContractError::RequestMismatch => Self::RequestMismatch,
            WireContractError::InvalidRequestId
            | WireContractError::InvalidComponentId
            | WireContractError::InvalidDeadline
            | WireContractError::InvalidFailure
            | WireContractError::InvalidJson => Self::InvalidResponse,
        }
    }
}
