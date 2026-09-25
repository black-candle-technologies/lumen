//! Mediated tool catalog (3B).
//!
//! Only BCT tools that call the kernel are registered here. Pi's built-in
//! effectful tools stay disabled at spawn time (`--no-builtin-tools`), and
//! the session supervisor terminates any session that emits a
//! `tool_execution_start` for a tool not in this catalog -- there is no
//! direct fallback path.
//!
//! Rules enforced in this module:
//! - Tool schemas are versioned and pinned; [`Catalog::tool_ref`] always
//!   returns the pinned `name@version`, never a floating version.
//! - Argument decoding is strict: a hand-rolled JSON Schema validator
//!   rejects unknown fields, wrong types, and out-of-range values before
//!   anything reaches the kernel.
//! - Deny and pending-approval results are rendered exactly once. The
//!   pipeline performs a single kernel `decide` per tool request and never
//!   retries a denial or polls a pending approval behind Pi's back.
//! - Every action carries a stable tool/version identifier into the
//!   [`ActionEnvelope`](crate::kernel_client::ActionEnvelope).

use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::kernel_client::{
    ACTION_ENVELOPE_VERSION, ActionEnvelope, AuditEvent, AuditRef, Decision, EffectClass,
    KernelClient, Obligation, ResourceSet, ToolRef, deadline_rfc3339, now_ms, rfc3339_to_ms,
    sha256_hex,
};

/// Bounded retries for the post-commit `tool_committed` audit write.
/// If all attempts fail the pipeline returns [`ToolOutcome::Uncertain`]
/// instead of `Completed`: a completion that is not durably recorded
/// must never be reported as success.
const COMMIT_AUDIT_RETRIES: u32 = 3;
/// Delay between post-commit audit retries (transient store hiccups).
const COMMIT_AUDIT_RETRY_DELAY: Duration = Duration::from_millis(50);

/// A typed tool request as emitted by Pi (mirrors the PiBridge v1
/// `PiToolRequest` shape; arguments are raw until [`Catalog::decode`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PiToolRequest {
    /// Pi-side call identifier, echoed back in the tool result.
    pub id: String,
    /// Requested tool name as Pi knows it.
    pub tool: String,
    /// Raw tool arguments; the host canonicalizes and re-validates.
    pub arguments: serde_json::Value,
}

/// How a decoded tool call projects onto kernel resources/effects.
/// Kept as data (not closures) so the projection is inspectable and the
/// same for every host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionKind {
    /// `{path}` -> paths=[path], effects=[Read]
    FsRead,
    /// `{path, content}` -> paths=[path], effects=[Write]
    FsWrite,
    /// `{command, cwd?, timeout_ms?}` -> effects=[Execute]
    ShellRun,
    /// `{url, method?, max_bytes?}` -> hosts=[scheme://host:port],
    /// effects=[Network]. The destination is projected -- never the full
    /// URL -- so kernel policy rules match destinations.
    HttpFetch,
}

/// A registered BCT tool: pinned version, strict schema, declared effects.
#[derive(Debug, Clone)]
pub struct ToolDef {
    pub name: String,
    pub version: String,
    pub description: String,
    /// JSON Schema (subset) for arguments; `additionalProperties` must be
    /// false at the top level so decoding is strict.
    pub parameters_schema: serde_json::Value,
    pub effects: Vec<EffectClass>,
    pub projection: ProjectionKind,
}

impl ToolDef {
    pub fn tool_ref(&self) -> ToolRef {
        ToolRef {
            name: self.name.clone(),
            version: self.version.clone(),
        }
    }
}

/// Strictly-decoded tool arguments: every field passed schema validation.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedArgs {
    fields: BTreeMap<String, serde_json::Value>,
}

impl DecodedArgs {
    pub fn get(&self, name: &str) -> Option<&serde_json::Value> {
        self.fields.get(name)
    }

    pub fn get_str(&self, name: &str) -> Option<&str> {
        self.fields.get(name).and_then(|v| v.as_str())
    }

    pub fn get_u64(&self, name: &str) -> Option<u64> {
        self.fields.get(name).and_then(|v| v.as_u64())
    }

    pub fn fields(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.fields
    }
}

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("unknown tool: {0}")]
    UnknownTool(String),
    #[error("argument decoding failed for tool {tool}: {reason}")]
    Decode { tool: String, reason: String },
    #[error("duplicate tool registration: {0}")]
    Duplicate(String),
}

/// The mediated tool catalog.
#[derive(Debug, Default)]
pub struct Catalog {
    tools: HashMap<String, ToolDef>,
}

impl Catalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, def: ToolDef) -> Result<(), CatalogError> {
        if self.tools.contains_key(&def.name) {
            return Err(CatalogError::Duplicate(def.name));
        }
        self.tools.insert(def.name.clone(), def);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&ToolDef> {
        self.tools.get(name)
    }

    pub fn contains(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    /// Stable tool/version identifier for `name`. The version is the pinned
    /// catalog version, never negotiated with Pi.
    pub fn tool_ref(&self, name: &str) -> Result<ToolRef, CatalogError> {
        self.get(name)
            .map(ToolDef::tool_ref)
            .ok_or_else(|| CatalogError::UnknownTool(name.to_string()))
    }

    /// Strictly decode raw arguments against the tool's pinned schema.
    pub fn decode(
        &self,
        name: &str,
        args: &serde_json::Value,
    ) -> Result<DecodedArgs, CatalogError> {
        let def = self
            .get(name)
            .ok_or_else(|| CatalogError::UnknownTool(name.to_string()))?;
        validate_against_schema(args, &def.parameters_schema, "$").map_err(|reason| {
            CatalogError::Decode {
                tool: name.to_string(),
                reason,
            }
        })?;
        let fields = args
            .as_object()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        Ok(DecodedArgs { fields })
    }

    /// Project decoded arguments onto kernel resources and effects.
    pub fn project(
        &self,
        name: &str,
        args: &DecodedArgs,
    ) -> Result<(ResourceSet, Vec<EffectClass>), CatalogError> {
        let def = self
            .get(name)
            .ok_or_else(|| CatalogError::UnknownTool(name.to_string()))?;
        let mut resources = ResourceSet::default();
        match def.projection {
            ProjectionKind::FsRead | ProjectionKind::FsWrite => {
                let path = args.get_str("path").ok_or_else(|| CatalogError::Decode {
                    tool: name.to_string(),
                    reason: "missing validated field 'path'".to_string(),
                })?;
                if !path.starts_with('/') {
                    return Err(CatalogError::Decode {
                        tool: name.to_string(),
                        reason: "path must be absolute".to_string(),
                    });
                }
                resources.paths.push(path.to_string());
            }
            ProjectionKind::ShellRun => {
                if let Some(cwd) = args.get_str("cwd") {
                    resources.paths.push(cwd.to_string());
                }
            }
            ProjectionKind::HttpFetch => {
                let url = args.get_str("url").ok_or_else(|| CatalogError::Decode {
                    tool: name.to_string(),
                    reason: "missing validated field 'url'".to_string(),
                })?;
                // Project the destination, not the full URL: kernel
                // policy rules match `scheme://host:port` destinations,
                // and a rule for a destination must cover every path on
                // it.
                let dest = project_http_dest(url).map_err(|reason| CatalogError::Decode {
                    tool: name.to_string(),
                    reason,
                })?;
                resources.hosts.push(dest);
            }
        }
        Ok((resources, def.effects.clone()))
    }
}

/// Project an HTTP fetch URL onto the kernel's network resource shape:
/// `scheme://host:port`.
///
/// Deliberately hand-written rather than via the `url` crate: the
/// projection must be fail-closed, and WHATWG parsing is more liberal
/// than this policy wants (it would silently accept an empty port or
/// strip userinfo instead of rejecting the URL). Every ambiguity below
/// is an explicit rejection, not a normalization.
///
/// Policy rules match destinations, so the path, query, and fragment
/// must not leak into the projected host: a rule allowing
/// `https://example.com:443` has to cover `https://example.com/anything`.
/// This also matches what `kernel_local::parse_network_dest` accepts --
/// anything else fails that conversion, fail closed.
fn project_http_dest(url: &str) -> Result<String, String> {
    let scheme_end = url
        .find("://")
        .ok_or_else(|| "url must be absolute with scheme".to_string())?;
    let scheme = &url[..scheme_end];
    if scheme != "https" && scheme != "http" {
        return Err("url scheme must be http or https".to_string());
    }
    let after_scheme = &url[scheme_end + 3..];
    // The authority ends at the first path, query, or fragment
    // delimiter; none of those belong in the projected destination.
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    // Credentials in the URL cannot be expressed in the projected
    // destination: fail closed rather than silently dropping them.
    if authority.contains('@') {
        return Err("url must not contain userinfo".to_string());
    }
    let (host, port): (&str, u16) = if let Some(bracketed) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal, e.g. `[::1]:8443`.
        let end = bracketed
            .find(']')
            .ok_or_else(|| "unclosed IPv6 bracket in url".to_string())?;
        let host = &authority[..end + 2]; // keep the brackets
        let rest = &authority[end + 2..];
        let port = match rest.strip_prefix(':') {
            Some(p) if !p.is_empty() => p
                .parse::<u16>()
                .map_err(|_| "url port out of range".to_string())?,
            Some(_) => return Err("empty port in url".to_string()),
            None if rest.is_empty() => default_http_port(scheme),
            None => return Err("unexpected characters after IPv6 host".to_string()),
        };
        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') && !p.is_empty() => {
                let port = p
                    .parse::<u16>()
                    .map_err(|_| "url port out of range".to_string())?;
                (h, port)
            }
            // Any other colon means an unbracketed IPv6 literal or a
            // malformed authority: fail closed rather than misparse it.
            _ if authority.contains(':') => {
                return Err("IPv6 host must be bracketed".to_string());
            }
            _ => (authority, default_http_port(scheme)),
        }
    };
    if host.is_empty() {
        return Err("url must have a host".to_string());
    }
    // Hostnames are case-insensitive: normalize so policy matching is
    // stable regardless of how Pi cased the URL.
    Ok(format!("{scheme}://{}:{port}", host.to_lowercase()))
}

fn default_http_port(scheme: &str) -> u16 {
    if scheme == "https" { 443 } else { 80 }
}

/// Build the default v1 BCT tool catalog: filesystem read/write, shell,
/// and HTTP fetch, all pinned at 1.0.0.
pub fn default_catalog() -> Catalog {
    let mut catalog = Catalog::new();
    let defs = [
        ToolDef {
            name: "bct.fs.read".to_string(),
            version: "1.0.0".to_string(),
            description: "Read a file inside leased roots.".to_string(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["path"],
                "properties": {
                    "path": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576}
                }
            }),
            effects: vec![EffectClass::Read],
            projection: ProjectionKind::FsRead,
        },
        ToolDef {
            name: "bct.fs.write".to_string(),
            version: "1.0.0".to_string(),
            description: "Write a file inside leased roots.".to_string(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["path", "content"],
                "properties": {
                    "path": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "content": {"type": "string", "maxLength": 1048576},
                    "mode": {"type": "string", "enum": ["create", "overwrite", "append"]}
                }
            }),
            effects: vec![EffectClass::Write],
            projection: ProjectionKind::FsWrite,
        },
        ToolDef {
            name: "bct.shell.run".to_string(),
            version: "1.0.0".to_string(),
            description: "Run a command in the sandbox.".to_string(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["command"],
                "properties": {
                    "command": {"type": "string", "minLength": 1, "maxLength": 32768},
                    "cwd": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "timeout_ms": {"type": "integer", "minimum": 100, "maximum": 300000}
                }
            }),
            effects: vec![EffectClass::Execute],
            projection: ProjectionKind::ShellRun,
        },
        ToolDef {
            name: "bct.http.fetch".to_string(),
            version: "1.0.0".to_string(),
            description: "Fetch a URL through the host egress proxy.".to_string(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["url"],
                "properties": {
                    "url": {"type": "string", "minLength": 8, "maxLength": 2048},
                    "method": {"type": "string", "enum": ["GET", "HEAD"]},
                    "max_bytes": {"type": "integer", "minimum": 1, "maximum": 10485760}
                }
            }),
            effects: vec![EffectClass::Network],
            projection: ProjectionKind::HttpFetch,
        },
    ];
    for def in defs {
        catalog
            .register(def)
            .expect("default catalog has unique tools");
    }
    catalog
}

/// Strict JSON Schema validator (subset): objects, strings, integers,
/// numbers, booleans, arrays, null; `properties`, `required`,
/// `additionalProperties: false`, `enum`, `const`, `minLength`,
/// `maxLength`, `minimum`, `maximum`, `items`, `minItems`, `maxItems`.
/// Anything outside the subset in the *schema* is rejected at validation
/// time (fail closed on schema authoring errors too).
fn validate_against_schema(
    value: &serde_json::Value,
    schema: &serde_json::Value,
    path: &str,
) -> Result<(), String> {
    let schema_obj = schema
        .as_object()
        .ok_or_else(|| format!("{path}: schema must be an object"))?;
    // Reject unknown schema keywords so a typoed schema fails loudly.
    const KNOWN: &[&str] = &[
        "type",
        "properties",
        "required",
        "additionalProperties",
        "enum",
        "const",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "items",
        "minItems",
        "maxItems",
    ];
    for key in schema_obj.keys() {
        if !KNOWN.contains(&key.as_str()) {
            return Err(format!("{path}: unknown schema keyword '{key}'"));
        }
    }

    if let Some(expected) = schema_obj.get("type").and_then(|v| v.as_str()) {
        let ok = match expected {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "number" => value.is_number(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            other => return Err(format!("{path}: unknown type '{other}'")),
        };
        if !ok {
            return Err(format!("{path}: expected type {expected}"));
        }
    }
    if let Some(enum_values) = schema_obj.get("enum").and_then(|v| v.as_array())
        && !enum_values.contains(value)
    {
        return Err(format!("{path}: value not in enum"));
    }
    if let Some(const_value) = schema_obj.get("const")
        && value != const_value
    {
        return Err(format!("{path}: value does not match const"));
    }
    if let Some(s) = value.as_str() {
        if let Some(min) = schema_obj.get("minLength").and_then(|v| v.as_u64())
            && (s.chars().count() as u64) < min
        {
            return Err(format!("{path}: string shorter than minLength {min}"));
        }
        if let Some(max) = schema_obj.get("maxLength").and_then(|v| v.as_u64())
            && (s.chars().count() as u64) > max
        {
            return Err(format!("{path}: string longer than maxLength {max}"));
        }
    }
    if let Some(n) = value.as_f64() {
        if let Some(min) = schema_obj.get("minimum").and_then(|v| v.as_f64())
            && n < min
        {
            return Err(format!("{path}: {n} below minimum {min}"));
        }
        if let Some(max) = schema_obj.get("maximum").and_then(|v| v.as_f64())
            && n > max
        {
            return Err(format!("{path}: {n} above maximum {max}"));
        }
    }
    if let Some(obj) = value.as_object() {
        if let Some(required) = schema_obj.get("required").and_then(|v| v.as_array()) {
            for req in required {
                let name = req
                    .as_str()
                    .ok_or_else(|| format!("{path}: required entry must be a string"))?;
                if !obj.contains_key(name) {
                    return Err(format!("{path}: missing required property '{name}'"));
                }
            }
        }
        let properties = schema_obj.get("properties").and_then(|v| v.as_object());
        let additional = schema_obj
            .get("additionalProperties")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        for (key, val) in obj {
            match properties.and_then(|p| p.get(key)) {
                Some(prop_schema) => {
                    validate_against_schema(val, prop_schema, &format!("{path}.{key}"))?
                }
                None if !additional => {
                    return Err(format!("{path}: unknown property '{key}'"));
                }
                None => {}
            }
        }
    }
    if let Some(arr) = value.as_array() {
        if let Some(min) = schema_obj.get("minItems").and_then(|v| v.as_u64())
            && (arr.len() as u64) < min
        {
            return Err(format!("{path}: fewer than minItems {min}"));
        }
        if let Some(max) = schema_obj.get("maxItems").and_then(|v| v.as_u64())
            && (arr.len() as u64) > max
        {
            return Err(format!("{path}: more than maxItems {max}"));
        }
        if let Some(items) = schema_obj.get("items") {
            for (i, item) in arr.iter().enumerate() {
                validate_against_schema(item, items, &format!("{path}[{i}]"))?;
            }
        }
    }
    Ok(())
}

/// Resource usage reported by the sandbox for one action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_ms: u64,
    pub memory_bytes_max: u64,
    pub egress_bytes: u64,
}

/// Outcome of a sandbox run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandboxOutcome {
    pub exit_code: i32,
    /// Truncated text output (bounded by the sandbox; never the full stream).
    pub output_tail: String,
    /// Digest of the complete output, for audit.
    pub output_digest: String,
    pub usage: ResourceUsage,
    /// Digest of files exported from the sandbox, if any.
    #[serde(default)]
    pub export_digest: Option<String>,
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("sandbox unavailable: {0}")]
    Unavailable(String),
    #[error("sandbox run failed: {0}")]
    Failed(String),
    #[error("sandbox run timed out")]
    Timeout,
}

/// Boxed future for [`SandboxRunner`] (object-safe seam).
pub type SandboxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, SandboxError>> + Send + 'a>>;

/// A staged sandbox execution: the action has run, but its effects are
/// not yet visible outside the sandbox.
///
/// The host pipeline commits a staged execution only AFTER the audit
/// write for the action succeeds. If the audit write fails, the staged
/// execution is dropped without committing: effects never land, and the
/// pipeline reports the effect as not committed. Dropping a staged
/// execution that was never committed must discard its effects (abort).
///
/// A real Phase-2 implementation stages effects (e.g. an overlayfs upper
/// layer that is not yet merged, buffered network egress) and makes them
/// visible only in `commit`.
pub trait StagedExecution: Send {
    /// The observed outcome: exit code, output, usage.
    fn outcome(&self) -> &SandboxOutcome;

    /// Make the staged effects visible. Consumes the handle: each staged
    /// execution commits at most once.
    fn commit(self: Box<Self>) -> SandboxFuture<'static, ()>;
}

/// Sandbox execution seam. Phase 2 (sandboxd / Firecracker) wires a real
/// implementation; the host pipeline only ever calls through this trait.
pub trait SandboxRunner: Send + Sync {
    /// Stage one action under the given lease. No effects may become
    /// visible before the returned handle is committed.
    fn stage<'a>(
        &'a self,
        envelope: &'a ActionEnvelope,
        lease_id: &'a str,
        obligations: &'a [Obligation],
    ) -> SandboxFuture<'a, Box<dyn StagedExecution>>;
}

/// Mock sandbox for host tests: returns a canned outcome and records
/// stage/commit/abort calls so tests can prove the audit-before-commit
/// ordering.
#[derive(Debug, Default, Clone)]
pub struct MockSandboxRunner {
    inner: Arc<MockSandboxState>,
}

#[derive(Debug, Default)]
struct MockSandboxState {
    calls: std::sync::Mutex<Vec<String>>,
    staged: Arc<std::sync::Mutex<u32>>,
    committed: Arc<std::sync::Mutex<u32>>,
    aborted: Arc<std::sync::Mutex<u32>>,
    fail: std::sync::Mutex<bool>,
}

impl MockSandboxRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fail_next(&self, fail: bool) {
        *self.inner.fail.lock().unwrap() = fail;
    }

    pub fn call_count(&self) -> usize {
        self.inner.calls.lock().unwrap().len()
    }

    pub fn staged_count(&self) -> u32 {
        *self.inner.staged.lock().unwrap()
    }

    pub fn committed_count(&self) -> u32 {
        *self.inner.committed.lock().unwrap()
    }

    /// Staged executions dropped without commit.
    pub fn aborted_count(&self) -> u32 {
        *self.inner.aborted.lock().unwrap()
    }
}

/// The mock's staged execution. Commit flips the outcome to visible
/// (recorded); dropping without commit records an abort.
pub struct MockStagedExecution {
    outcome: SandboxOutcome,
    committed: std::sync::Mutex<bool>,
    on_commit: Arc<dyn Fn() + Send + Sync>,
    on_abort: Arc<dyn Fn() + Send + Sync>,
}

impl StagedExecution for MockStagedExecution {
    fn outcome(&self) -> &SandboxOutcome {
        &self.outcome
    }

    fn commit(self: Box<Self>) -> SandboxFuture<'static, ()> {
        Box::pin(async move {
            *self.committed.lock().unwrap() = true;
            (self.on_commit)();
            Ok(())
        })
    }
}

impl Drop for MockStagedExecution {
    fn drop(&mut self) {
        if !*self.committed.lock().unwrap() {
            (self.on_abort)();
        }
    }
}

impl SandboxRunner for MockSandboxRunner {
    fn stage<'a>(
        &'a self,
        envelope: &'a ActionEnvelope,
        lease_id: &'a str,
        _obligations: &'a [Obligation],
    ) -> SandboxFuture<'a, Box<dyn StagedExecution>> {
        let state = Arc::clone(&self.inner);
        Box::pin(async move {
            if *state.fail.lock().unwrap() {
                return Err(SandboxError::Failed("mock sandbox down".to_string()));
            }
            let digest = envelope
                .digest()
                .map_err(|e| SandboxError::Failed(e.to_string()))?;
            state
                .calls
                .lock()
                .unwrap()
                .push(format!("{}:{}", envelope.tool.name, lease_id));
            *state.staged.lock().unwrap() += 1;
            let committed_flag = Arc::clone(&state.committed);
            let aborted_flag = Arc::clone(&state.aborted);
            Ok(Box::new(MockStagedExecution {
                outcome: SandboxOutcome {
                    exit_code: 0,
                    output_tail: "mock-ok".to_string(),
                    output_digest: sha256_hex(format!("{digest}:output").as_bytes()),
                    usage: ResourceUsage {
                        cpu_ms: 12,
                        memory_bytes_max: 4096,
                        egress_bytes: 0,
                    },
                    export_digest: None,
                },
                committed: std::sync::Mutex::new(false),
                on_commit: Arc::new(move || {
                    *committed_flag.lock().unwrap() += 1;
                }),
                on_abort: Arc::new(move || {
                    *aborted_flag.lock().unwrap() += 1;
                }),
            }) as Box<dyn StagedExecution>)
        })
    }
}

/// Test double whose staged executions always fail at commit. Stages
/// normally (so the pipeline reaches the commit step), then the commit
/// itself errors: proves the pipeline never records completion for an
/// uncommitted effect.
#[derive(Debug, Default, Clone)]
pub struct FailCommitSandbox {
    inner: MockSandboxRunner,
}

impl FailCommitSandbox {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn staged_count(&self) -> u32 {
        self.inner.staged_count()
    }

    pub fn committed_count(&self) -> u32 {
        self.inner.committed_count()
    }
}

struct FailCommitStaged {
    outcome: SandboxOutcome,
}

impl StagedExecution for FailCommitStaged {
    fn outcome(&self) -> &SandboxOutcome {
        &self.outcome
    }

    fn commit(self: Box<Self>) -> SandboxFuture<'static, ()> {
        Box::pin(async move { Err(SandboxError::Failed("mock commit failed".to_string())) })
    }
}

impl SandboxRunner for FailCommitSandbox {
    fn stage<'a>(
        &'a self,
        envelope: &'a ActionEnvelope,
        lease_id: &'a str,
        obligations: &'a [Obligation],
    ) -> SandboxFuture<'a, Box<dyn StagedExecution>> {
        let inner = self.inner.clone();
        Box::pin(async move {
            let staged = inner.stage(envelope, lease_id, obligations).await?;
            let outcome = staged.outcome().clone();
            // Drop the inner staged handle uncommitted; the abort is
            // recorded on the inner mock, not here.
            drop(staged);
            Ok(Box::new(FailCommitStaged { outcome }) as Box<dyn StagedExecution>)
        })
    }
}

/// Hard deadline for starting an action after the envelope is built.
/// The envelope must not be minted already-expired: a bounded future
/// deadline keeps replay windows small and makes stale envelopes the
/// kernel's reject, not the host's surprise.
pub const ACTION_START_DEADLINE_SECS: u64 = 60;

/// The host-visible result of one Pi tool request.
///
/// Deny and pending outcomes carry the kernel's reason verbatim and are
/// rendered to Pi exactly once: the pipeline never re-decides or retries
/// behind the caller's back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ToolOutcome {
    Completed {
        result: serde_json::Value,
        usage: ResourceUsage,
        audit_ref: AuditRef,
    },
    Denied {
        reason: String,
    },
    PendingApproval {
        approval_request_id: String,
        reason: String,
    },
    InvalidRequest {
        reason: String,
    },
    /// Fail-closed fault: kernel unavailable, sandbox error, or audit
    /// write failure. The effect is NOT committed.
    Fault {
        reason: String,
    },
    /// The effect committed but the `tool_committed` completion record
    /// could not be written durably. This is NOT success: the hash
    /// chain holds the `tool_staged` intention but no completion, so
    /// the caller must not treat the action as audited-complete.
    /// Recover via the `action_digest`: the durable intention record
    /// plus `staged_audit_ref` identify the gap for reconciliation
    /// (re-append the completion record), after which the action may
    /// be acknowledged as complete.
    Uncertain {
        result: serde_json::Value,
        usage: ResourceUsage,
        reason: String,
        action_digest: String,
        staged_audit_ref: AuditRef,
    },
}

/// The vertical slice: Pi typed tool request -> kernel lease check ->
/// sandbox run -> host returns result + usage + audit reference.
///
/// Constructed with the catalog, kernel, and sandbox seams; the
/// coordinator wires the real implementations at integration.
pub struct ToolPipeline<K: KernelClient + ?Sized, S: SandboxRunner + ?Sized> {
    catalog: Arc<Catalog>,
    kernel: Arc<K>,
    sandbox: Arc<S>,
}

impl<K: KernelClient + ?Sized, S: SandboxRunner + ?Sized> ToolPipeline<K, S> {
    pub fn new(catalog: Arc<Catalog>, kernel: Arc<K>, sandbox: Arc<S>) -> Self {
        Self {
            catalog,
            kernel,
            sandbox,
        }
    }

    /// Build the canonical envelope for one Pi tool request without
    /// executing it. The host is the envelope authority: resources and
    /// effects come from the host projection, never from Pi.
    ///
    /// Exposed so tests (and the VHL one-shot flow) can retain the exact
    /// envelope the human approved and re-present it verbatim after the
    /// one-shot lease is minted: one-shot leases are bound to the exact
    /// approved action digest, so a freshly built envelope (new nonce)
    /// would not match. The caller sets `lease_chain` on the returned
    /// envelope before re-presenting it via [`Self::execute_envelope`].
    pub fn build_envelope(
        &self,
        request: &PiToolRequest,
        session_subject: &str,
        lease_chain: &[String],
    ) -> Result<ActionEnvelope, String> {
        // 1. Strict argument decoding. Unknown tools and malformed
        //    arguments never reach the kernel.
        let args = self
            .catalog
            .decode(&request.tool, &request.arguments)
            .map_err(|e| e.to_string())?;
        let (resources, effects) = self
            .catalog
            .project(&request.tool, &args)
            .map_err(|e| e.to_string())?;
        let tool_ref = self
            .catalog
            .tool_ref(&request.tool)
            .map_err(|e| e.to_string())?;

        // 2. Build the canonical envelope.
        Ok(ActionEnvelope {
            protocol_version: ACTION_ENVELOPE_VERSION,
            action_id: Uuid::new_v4().to_string(),
            session_id: session_subject.to_string(),
            tool: tool_ref,
            arguments: serde_json::to_value(args.fields()).unwrap_or(serde_json::Value::Null),
            input_hashes: Vec::new(),
            resources,
            lease_chain: lease_chain.to_vec(),
            nonce: Uuid::new_v4().to_string(),
            expires_at: deadline_rfc3339(ACTION_START_DEADLINE_SECS),
            expected_effects: effects,
        })
    }

    /// Handle one Pi tool request. Exactly one kernel `decide` per call;
    /// deny/pending are terminal renders, never retried.
    pub async fn handle(
        &self,
        request: &PiToolRequest,
        session_subject: &str,
        lease_chain: &[String],
    ) -> ToolOutcome {
        let envelope = match self.build_envelope(request, session_subject, lease_chain) {
            Ok(envelope) => envelope,
            Err(reason) => {
                return ToolOutcome::InvalidRequest { reason };
            }
        };
        self.execute_envelope(&envelope, session_subject).await
    }

    /// Execute a caller-supplied envelope: the path the BCT extension's
    /// kernel channel uses. The envelope is re-validated from scratch
    /// and the host recomputes the resource/effect projection from the
    /// strictly decoded arguments: the extension's declaration must
    /// match the host projection exactly, or the request is rejected.
    /// The extension is never trusted about what an action touches.
    pub async fn execute_envelope(
        &self,
        envelope: &ActionEnvelope,
        session_subject: &str,
    ) -> ToolOutcome {
        // 1. Structural validation: version, UUID shape, timestamp shape.
        if let Err(e) = envelope.validate() {
            return ToolOutcome::InvalidRequest {
                reason: format!("envelope invalid: {e}"),
            };
        }
        // The envelope must be bound to the calling session: the
        // extension cannot mint actions for another subject.
        if envelope.session_id != session_subject {
            return ToolOutcome::InvalidRequest {
                reason: "envelope session does not match calling session".to_string(),
            };
        }
        // The action must not already be expired.
        if is_expired(&envelope.expires_at) {
            return ToolOutcome::InvalidRequest {
                reason: "envelope expired".to_string(),
            };
        }
        // 2. Strict argument decoding against the pinned catalog, then
        //    host-side projection. Declared resources/effects must equal
        //    the projection: a lying extension fails closed here.
        let args = match self
            .catalog
            .decode(&envelope.tool.name, &envelope.arguments)
        {
            Ok(args) => args,
            Err(e) => {
                return ToolOutcome::InvalidRequest {
                    reason: format!("arguments rejected: {e}"),
                };
            }
        };
        let (resources, effects) = match self.catalog.project(&envelope.tool.name, &args) {
            Ok(projected) => projected,
            Err(e) => {
                return ToolOutcome::InvalidRequest {
                    reason: format!("projection failed: {e}"),
                };
            }
        };
        if envelope.resources != resources || envelope.expected_effects != effects {
            return ToolOutcome::InvalidRequest {
                reason: "envelope resources/effects do not match host projection".to_string(),
            };
        }
        // 3. The tool version must equal the catalog pin.
        match self.catalog.tool_ref(&envelope.tool.name) {
            Ok(pinned) if pinned.version == envelope.tool.version => {}
            Ok(pinned) => {
                return ToolOutcome::InvalidRequest {
                    reason: format!(
                        "tool version mismatch for {}: pinned {}, got {}",
                        envelope.tool.name, pinned.version, envelope.tool.version
                    ),
                };
            }
            Err(e) => {
                return ToolOutcome::InvalidRequest {
                    reason: e.to_string(),
                };
            }
        }

        let digest = match envelope.digest() {
            Ok(digest) => digest,
            Err(e) => {
                return ToolOutcome::Fault {
                    reason: format!("envelope digest failed: {e}"),
                };
            }
        };

        // Now the envelope is trusted as far as the host can check it:
        // exactly one kernel decision, bound to this envelope.
        decide_execute_audit(self, envelope, &digest, session_subject).await
    }
}

/// True when an RFC 3339 timestamp is at or past the current time.
/// Unparseable input counts as expired: fail closed.
fn is_expired(expires_at: &str) -> bool {
    match rfc3339_to_ms(expires_at) {
        Some(ms) => ms <= now_ms(),
        None => true,
    }
}

/// The shared tail of [`ToolPipeline::handle`] and
/// [`ToolPipeline::execute_envelope`]: one kernel decision, bound to the
/// envelope, then stage -> audit -> commit for allows.
async fn decide_execute_audit<K: KernelClient + ?Sized, S: SandboxRunner + ?Sized>(
    pipeline: &ToolPipeline<K, S>,
    envelope: &ActionEnvelope,
    digest: &str,
    session_subject: &str,
) -> ToolOutcome {
    // Exactly one kernel decision.
    let decision = match pipeline.kernel.decide(envelope).await {
        Ok(decision) => decision,
        Err(e) => {
            return ToolOutcome::Fault {
                reason: format!("kernel decide failed: {e}"),
            };
        }
    };
    // Bind the decision to this envelope: substitution fails closed.
    if let Err(e) = decision.bind(envelope) {
        return ToolOutcome::Fault {
            reason: format!("decision binding failed: {e}"),
        };
    }

    match decision.decision {
        Decision::Deny { reason } => {
            // Terminal render: no retry, no re-decide.
            ToolOutcome::Denied { reason }
        }
        Decision::PendingApproval {
            approval_request_id,
            reason,
        } => {
            // Terminal render: the caller re-submits explicitly after
            // approval (phase 4 one-shot lease path). No polling here.
            ToolOutcome::PendingApproval {
                approval_request_id,
                reason,
            }
        }
        Decision::Allow {
            lease_id,
            obligations,
        } => {
            // Stage the sandbox execution. No effects become
            // visible yet: the staged handle holds them.
            let staged = match pipeline
                .sandbox
                .stage(envelope, &lease_id, &obligations)
                .await
            {
                Ok(staged) => staged,
                Err(e) => {
                    return ToolOutcome::Fault {
                        reason: format!("sandbox stage failed: {e}"),
                    };
                }
            };
            let outcome = staged.outcome().clone();
            // Audit append BEFORE commit: a durable intention record
            // with honest semantics. It claims the execution was
            // *staged and authorized for commit* -- never that it
            // completed. If this write fails, the staged execution is
            // dropped uncommitted: the effect never lands and is
            // reported as not committed. Fail closed.
            let staged_ref = match pipeline
                .kernel
                .append_audit(&AuditEvent {
                    kind: "tool_staged".to_string(),
                    session_id: session_subject.to_string(),
                    action_digest: Some(digest.to_string()),
                    payload: serde_json::json!({
                        "tool": envelope.tool.name,
                        "tool_version": envelope.tool.version,
                        "lease_id": lease_id,
                        "expected_effects": envelope.expected_effects,
                    }),
                })
                .await
            {
                Ok(audit_ref) => audit_ref,
                Err(e) => {
                    drop(staged);
                    return ToolOutcome::Fault {
                        reason: format!("audit write failed; effect not committed: {e}"),
                    };
                }
            };
            // The intention is durable: commit the staged effects.
            if let Err(e) = staged.commit().await {
                // No completion is recorded: the audit log holds the
                // honest `tool_staged` intention and no `tool_committed`
                // claim. The caller sees a Fault, never a success.
                return ToolOutcome::Fault {
                    reason: format!("sandbox commit failed: {e}"),
                };
            }
            // Commit landed: completion must be durably recorded before
            // the action is reported as complete. The audit write is
            // retried a bounded number of times (transient store
            // hiccups); readers dedupe `tool_committed` by action
            // digest, so a retry that follows a lost acknowledgement is
            // detectable, not silently double-counted.
            let committed_event = AuditEvent {
                kind: "tool_committed".to_string(),
                session_id: session_subject.to_string(),
                action_digest: Some(digest.to_string()),
                payload: serde_json::json!({
                    "tool": envelope.tool.name,
                    "tool_version": envelope.tool.version,
                    "lease_id": lease_id,
                    "exit_code": outcome.exit_code,
                    "output_digest": outcome.output_digest,
                    "usage": outcome.usage,
                }),
            };
            let mut append_err = String::new();
            let mut audit_ref = None;
            for attempt in 0..COMMIT_AUDIT_RETRIES {
                match pipeline.kernel.append_audit(&committed_event).await {
                    Ok(r) => {
                        audit_ref = Some(r);
                        break;
                    }
                    Err(e) => {
                        append_err = e.to_string();
                        if attempt + 1 < COMMIT_AUDIT_RETRIES {
                            tokio::time::sleep(COMMIT_AUDIT_RETRY_DELAY).await;
                        }
                    }
                }
            }
            match audit_ref {
                Some(audit_ref) => ToolOutcome::Completed {
                    result: serde_json::json!({
                        "exit_code": outcome.exit_code,
                        "output_tail": outcome.output_tail,
                    }),
                    usage: outcome.usage,
                    audit_ref,
                },
                None => {
                    // The effect is committed but the completion record
                    // is not durable. This is NOT success: return the
                    // recoverable uncertain state instead. The durable
                    // `tool_staged` intention (staged_ref) plus the
                    // action digest identify the audit gap for
                    // reconciliation; only after the completion record
                    // lands may the action be acknowledged as complete.
                    ToolOutcome::Uncertain {
                        result: serde_json::json!({
                            "exit_code": outcome.exit_code,
                            "output_tail": outcome.output_tail,
                        }),
                        usage: outcome.usage,
                        reason: format!(
                            "tool_committed audit write failed after {COMMIT_AUDIT_RETRIES} attempts: {append_err}; effect may have landed but is not audit-confirmed"
                        ),
                        action_digest: digest.to_string(),
                        staged_audit_ref: staged_ref,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_client::{MockKernelClient, MockVerdict};

    fn request(tool: &str, arguments: serde_json::Value) -> PiToolRequest {
        PiToolRequest {
            id: "call-1".to_string(),
            tool: tool.to_string(),
            arguments,
        }
    }

    #[test]
    fn project_http_dest_projects_scheme_host_port() {
        // Path, query, and fragment are stripped: the policy matches
        // destinations, not URLs.
        assert_eq!(
            project_http_dest("https://example.com/a/b?x=1#frag").unwrap(),
            "https://example.com:443"
        );
        // Host case is normalized for stable policy matching.
        assert_eq!(
            project_http_dest("https://EXAMPLE.com/").unwrap(),
            "https://example.com:443"
        );
        // Explicit ports are preserved, including non-default ones.
        assert_eq!(
            project_http_dest("http://example.com:8080/x").unwrap(),
            "http://example.com:8080"
        );
        // Bracketed IPv6 literals work, with and without a port.
        assert_eq!(
            project_http_dest("https://[::1]:8443/").unwrap(),
            "https://[::1]:8443"
        );
        assert_eq!(
            project_http_dest("http://[::1]/").unwrap(),
            "http://[::1]:80"
        );
    }

    #[test]
    fn project_http_dest_fails_closed() {
        // Credentials must never be silently dropped from the URL.
        assert!(project_http_dest("https://user:pass@example.com/").is_err());
        assert!(project_http_dest("https://user@example.com/").is_err());
        // Unbracketed IPv6 is ambiguous: reject, don't misparse.
        assert!(project_http_dest("https://::1/").is_err());
        assert!(project_http_dest("https://::1:8443/").is_err());
        // Unclosed bracket.
        assert!(project_http_dest("https://[::1/").is_err());
        // Empty or out-of-range ports are rejected, not defaulted.
        assert!(project_http_dest("https://example.com:/").is_err());
        assert!(project_http_dest("https://example.com:99999/").is_err());
        // Wrong or missing scheme.
        assert!(project_http_dest("ftp://example.com/").is_err());
        assert!(project_http_dest("example.com/").is_err());
        // Missing host.
        assert!(project_http_dest("https:///path").is_err());
    }

    #[test]
    fn default_catalog_pins_versions() {
        let catalog = default_catalog();
        let tool_ref = catalog.tool_ref("bct.fs.read").unwrap();
        assert_eq!(tool_ref.name, "bct.fs.read");
        assert_eq!(tool_ref.version, "1.0.0");
        assert!(catalog.tool_ref("bash").is_err());
    }

    #[test]
    fn strict_decoding_rejects_unknown_fields_and_types() {
        let catalog = default_catalog();
        // Unknown field.
        let bad = serde_json::json!({"path": "/tmp/x", "evil": true});
        assert!(catalog.decode("bct.fs.read", &bad).is_err());
        // Wrong type.
        let bad = serde_json::json!({"path": 42});
        assert!(catalog.decode("bct.fs.read", &bad).is_err());
        // Missing required.
        let bad = serde_json::json!({});
        assert!(catalog.decode("bct.fs.read", &bad).is_err());
        // Out of range.
        let bad = serde_json::json!({"path": "/tmp/x", "max_bytes": 1 << 30});
        assert!(catalog.decode("bct.fs.read", &bad).is_err());
        // Enum violation.
        let bad = serde_json::json!({"url": "https://example.com", "method": "POST"});
        assert!(catalog.decode("bct.http.fetch", &bad).is_err());
        // Good.
        let good = serde_json::json!({"path": "/tmp/x"});
        assert!(catalog.decode("bct.fs.read", &good).is_ok());
    }

    #[test]
    fn projection_maps_resources_and_effects() {
        let catalog = default_catalog();
        let args = catalog
            .decode("bct.fs.read", &serde_json::json!({"path": "/tmp/x"}))
            .unwrap();
        let (resources, effects) = catalog.project("bct.fs.read", &args).unwrap();
        assert_eq!(resources.paths, vec!["/tmp/x".to_string()]);
        assert_eq!(effects, vec![EffectClass::Read]);

        let args = catalog
            .decode(
                "bct.http.fetch",
                &serde_json::json!({"url": "https://example.com/x"}),
            )
            .unwrap();
        let (resources, effects) = catalog.project("bct.http.fetch", &args).unwrap();
        // The full URL is never projected: policy matches destinations.
        assert_eq!(resources.hosts, vec!["https://example.com:443".to_string()]);
        assert_eq!(effects, vec![EffectClass::Network]);

        // Relative paths rejected even though the schema passed.
        let args = catalog
            .decode("bct.fs.read", &serde_json::json!({"path": "relative/x"}))
            .unwrap();
        assert!(catalog.project("bct.fs.read", &args).is_err());
    }

    #[test]
    fn http_fetch_projects_destination_not_full_url() {
        let catalog = default_catalog();
        let cases = [
            // Path, query, and fragment are stripped: a policy rule for
            // the destination covers every path on it.
            (
                "https://example.com/a/b?x=1#frag",
                "https://example.com:443",
            ),
            ("http://example.com/", "http://example.com:80"),
            ("https://example.com", "https://example.com:443"),
            // Explicit ports are preserved.
            ("https://example.com:8443/x", "https://example.com:8443"),
            ("http://example.com:8080", "http://example.com:8080"),
            // Bracketed IPv6 literals.
            ("https://[::1]:8443/x", "https://[::1]:8443"),
            ("https://[::1]/x", "https://[::1]:443"),
            // Host case is normalized for stable policy matching.
            ("https://EXAMPLE.com/x", "https://example.com:443"),
        ];
        for (url, expected) in cases {
            let args = catalog
                .decode("bct.http.fetch", &serde_json::json!({"url": url}))
                .unwrap();
            let (resources, _) = catalog.project("bct.http.fetch", &args).unwrap();
            assert_eq!(
                resources.hosts,
                vec![expected.to_string()],
                "wrong projection for url: {url}"
            );
        }
    }

    #[test]
    fn http_fetch_rejects_unprojectable_urls() {
        let catalog = default_catalog();
        for url in [
            "https://user:pass@example.com/x", // userinfo not expressible
            "https://example.com:/x",          // empty port
            "https://[::1/x",                  // unclosed IPv6 bracket
            "https://::1/x",                   // unbracketed IPv6 literal
            "https://example.com:99999/x",     // port out of range
            "https:///x",                      // empty host
        ] {
            let args = catalog
                .decode("bct.http.fetch", &serde_json::json!({"url": url}))
                .unwrap();
            assert!(
                catalog.project("bct.http.fetch", &args).is_err(),
                "url should be rejected: {url}"
            );
        }
    }

    #[tokio::test]
    async fn vertical_slice_allow_path() {
        let catalog = Arc::new(default_catalog());
        let kernel = Arc::new(MockKernelClient::new().with_verdict(MockVerdict::Allow));
        let sandbox = Arc::new(MockSandboxRunner::new());
        let pipeline = ToolPipeline::new(catalog, kernel.clone(), sandbox.clone());

        let outcome = pipeline
            .handle(
                &request("bct.fs.read", serde_json::json!({"path": "/tmp/x"})),
                "ed25519:subject",
                &["lease-1".to_string()],
            )
            .await;
        match outcome {
            ToolOutcome::Completed {
                result,
                usage,
                audit_ref,
            } => {
                assert_eq!(result["exit_code"], 0);
                assert_eq!(usage.cpu_ms, 12);
                assert!(!audit_ref.event_id.is_empty());
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(sandbox.call_count(), 1);
        assert_eq!(kernel.decisions_made(), 1);
        // Two honest audit events: the pre-commit intention and the
        // post-commit completion. No single event ever claims
        // completion before the commit lands.
        assert_eq!(kernel.audit_log().len(), 2);
        let log = kernel.audit_log();
        let kinds: Vec<&str> = log.iter().map(|(event, _)| event.kind.as_str()).collect();
        assert_eq!(kinds, vec!["tool_staged", "tool_committed"]);
        // Staged exactly once and committed only after the audit write.
        assert_eq!(sandbox.staged_count(), 1);
        assert_eq!(sandbox.committed_count(), 1);
        assert_eq!(sandbox.aborted_count(), 0);
    }

    #[tokio::test]
    async fn deny_renders_once_without_hidden_retry() {
        let catalog = Arc::new(default_catalog());
        let kernel = Arc::new(
            MockKernelClient::new()
                .with_verdict(MockVerdict::Deny)
                .with_deny_reason("not leased"),
        );
        let sandbox = Arc::new(MockSandboxRunner::new());
        let pipeline = ToolPipeline::new(catalog, kernel.clone(), sandbox.clone());

        let outcome = pipeline
            .handle(
                &request("bct.shell.run", serde_json::json!({"command": "rm -rf /"})),
                "ed25519:subject",
                &[],
            )
            .await;
        assert!(matches!(
            outcome,
            ToolOutcome::Denied { reason } if reason == "not leased"
        ));
        // Exactly one decide, zero sandbox runs: no hidden retry.
        assert_eq!(kernel.decisions_made(), 1);
        assert_eq!(sandbox.call_count(), 0);
    }

    #[tokio::test]
    async fn pending_renders_without_polling() {
        let catalog = Arc::new(default_catalog());
        let kernel = Arc::new(MockKernelClient::new().with_verdict(MockVerdict::PendingApproval));
        let sandbox = Arc::new(MockSandboxRunner::new());
        let pipeline = ToolPipeline::new(catalog, kernel.clone(), sandbox.clone());

        let outcome = pipeline
            .handle(
                &request(
                    "bct.fs.write",
                    serde_json::json!({"path": "/tmp/x", "content": "hi"}),
                ),
                "ed25519:subject",
                &[],
            )
            .await;
        assert!(matches!(outcome, ToolOutcome::PendingApproval { .. }));
        assert_eq!(kernel.decisions_made(), 1);
        assert_eq!(sandbox.call_count(), 0);
    }

    #[tokio::test]
    async fn invalid_tool_never_reaches_kernel() {
        let catalog = Arc::new(default_catalog());
        let kernel = Arc::new(MockKernelClient::new().with_verdict(MockVerdict::Allow));
        let sandbox = Arc::new(MockSandboxRunner::new());
        let pipeline = ToolPipeline::new(catalog, kernel.clone(), sandbox.clone());

        let outcome = pipeline
            .handle(
                &request("bash", serde_json::json!({"command": "id"})),
                "ed25519:subject",
                &[],
            )
            .await;
        assert!(matches!(outcome, ToolOutcome::InvalidRequest { .. }));
        assert_eq!(kernel.decisions_made(), 0);
        assert_eq!(sandbox.call_count(), 0);
    }

    #[tokio::test]
    async fn audit_failure_marks_effect_uncommitted() {
        let catalog = Arc::new(default_catalog());
        let kernel = Arc::new(MockKernelClient::new().with_verdict(MockVerdict::Allow));
        kernel.fail_audit(true);
        let sandbox = Arc::new(MockSandboxRunner::new());
        let pipeline = ToolPipeline::new(catalog, kernel.clone(), sandbox.clone());

        let outcome = pipeline
            .handle(
                &request("bct.fs.read", serde_json::json!({"path": "/tmp/x"})),
                "ed25519:subject",
                &[],
            )
            .await;
        match outcome {
            ToolOutcome::Fault { reason } => {
                assert!(reason.contains("not committed"));
            }
            other => panic!("expected Fault, got {other:?}"),
        }
        // The action was staged but never committed: dropping the staged
        // handle on audit failure aborts the effects.
        assert_eq!(sandbox.staged_count(), 1);
        assert_eq!(sandbox.committed_count(), 0);
        assert_eq!(sandbox.aborted_count(), 1);
    }

    #[tokio::test]
    async fn commit_audit_failure_returns_uncertain_not_completed() {
        let catalog = Arc::new(default_catalog());
        let kernel = Arc::new(MockKernelClient::new().with_verdict(MockVerdict::Allow));
        // The pre-commit `tool_staged` intention lands durably; the
        // post-commit `tool_committed` record fails on every attempt.
        kernel.fail_audit_after_appends(1);
        let sandbox = Arc::new(MockSandboxRunner::new());
        let pipeline = ToolPipeline::new(catalog, kernel.clone(), sandbox.clone());

        let outcome = pipeline
            .handle(
                &request("bct.fs.read", serde_json::json!({"path": "/tmp/x"})),
                "ed25519:subject",
                &[],
            )
            .await;
        // Stage succeeded, the intention was durably recorded, and the
        // commit happened.
        assert_eq!(sandbox.staged_count(), 1);
        assert_eq!(sandbox.committed_count(), 1);
        assert_eq!(sandbox.aborted_count(), 0);
        let log = kernel.audit_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].0.kind, "tool_staged");
        // But the completion record is missing, so the outcome is
        // Uncertain — never Completed (a lie) and never Fault (the
        // effect was committed, so "not committed" would be the lie).
        match outcome {
            ToolOutcome::Uncertain {
                reason,
                action_digest,
                staged_audit_ref,
                result,
                usage,
            } => {
                assert!(
                    reason.contains("tool_committed"),
                    "reason must name the missing record: {reason}"
                );
                assert!(!action_digest.is_empty());
                // The staged audit ref survives for reconciliation.
                assert_eq!(staged_audit_ref, log[0].1);
                // No claim of completion travels with the outcome.
                assert_eq!(result["exit_code"], 0);
                assert_eq!(usage.cpu_ms, 12);
            }
            other => panic!("expected Uncertain, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn commit_audit_retry_recovers_before_uncertain() {
        let catalog = Arc::new(default_catalog());
        let kernel = Arc::new(MockKernelClient::new().with_verdict(MockVerdict::Allow));
        // Two transient failures, then the store recovers: the bounded
        // retry lands the completion record, so the outcome is honestly
        // Completed.
        kernel.fail_next_audit_appends_for_kind("tool_committed", 2);
        let sandbox = Arc::new(MockSandboxRunner::new());
        let pipeline = ToolPipeline::new(catalog, kernel.clone(), sandbox.clone());

        let outcome = pipeline
            .handle(
                &request("bct.fs.read", serde_json::json!({"path": "/tmp/x"})),
                "ed25519:subject",
                &[],
            )
            .await;
        // tool_staged, then the retried tool_committed.
        let log = kernel.audit_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].0.kind, "tool_committed");
        assert!(
            matches!(outcome, ToolOutcome::Completed { .. }),
            "expected Completed after retry recovery, got {outcome:?}"
        );
    }

    #[test]
    fn minted_action_deadline_is_genuinely_in_the_future() {
        // The envelope deadline minted by `handle` must parse as RFC
        // 3339 and land strictly after now: an already-expired envelope
        // would be rejected by `execute_envelope`, so a broken mint
        // would deny every action.
        let deadline = deadline_rfc3339(ACTION_START_DEADLINE_SECS);
        let deadline_ms = rfc3339_to_ms(&deadline).expect("deadline must parse");
        let now = now_ms();
        assert!(
            deadline_ms > now,
            "deadline {deadline} is not in the future"
        );
        // Bounded: the mint must not hand out far-future deadlines that
        // widen the replay window.
        assert!(
            deadline_ms - now <= (ACTION_START_DEADLINE_SECS as i64 + 5) * 1000,
            "deadline {deadline} is too far out"
        );
        assert!(!is_expired(&deadline));
        assert!(is_expired("2000-01-01T00:00:00Z"));
        // Unparseable input counts as expired: fail closed.
        assert!(is_expired("not-a-timestamp"));
    }

    #[tokio::test]
    async fn commit_failure_records_no_completion_claim() {
        let catalog = Arc::new(default_catalog());
        let kernel = Arc::new(MockKernelClient::new().with_verdict(MockVerdict::Allow));
        let sandbox = Arc::new(FailCommitSandbox::new());
        let pipeline = ToolPipeline::new(catalog, kernel.clone(), sandbox.clone());

        let outcome = pipeline
            .handle(
                &request("bct.fs.read", serde_json::json!({"path": "/tmp/x"})),
                "ed25519:subject",
                &[],
            )
            .await;
        match outcome {
            ToolOutcome::Fault { reason } => {
                assert!(reason.contains("commit failed"), "got: {reason}");
            }
            other => panic!("expected Fault, got {other:?}"),
        }
        // The honest intention event is durable; no completion event
        // exists because nothing completed. The audit log must never
        // claim an effect landed when it did not.
        assert_eq!(sandbox.staged_count(), 1);
        assert_eq!(sandbox.committed_count(), 0);
        let log = kernel.audit_log();
        let kinds: Vec<&str> = log.iter().map(|(event, _)| event.kind.as_str()).collect();
        assert_eq!(kinds, vec!["tool_staged"]);
    }

    #[tokio::test]
    async fn sandbox_failure_is_fault_not_success() {
        let catalog = Arc::new(default_catalog());
        let kernel = Arc::new(MockKernelClient::new().with_verdict(MockVerdict::Allow));
        let sandbox = Arc::new(MockSandboxRunner::new());
        sandbox.fail_next(true);
        let pipeline = ToolPipeline::new(catalog, kernel.clone(), sandbox.clone());

        let outcome = pipeline
            .handle(
                &request("bct.fs.read", serde_json::json!({"path": "/tmp/x"})),
                "ed25519:subject",
                &[],
            )
            .await;
        assert!(matches!(outcome, ToolOutcome::Fault { .. }));
        // Stage itself failed: nothing staged, nothing committed.
        assert_eq!(sandbox.staged_count(), 0);
        assert_eq!(sandbox.committed_count(), 0);
        assert_eq!(sandbox.aborted_count(), 0);
    }
}
