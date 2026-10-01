//! Development-only deny probe for a real confined Pi RPC request.
//! There is deliberately no effect executor, privileged command, or allow path.
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use lumen_core::budget::{Budget, BudgetDimension};
use lumen_core::canonical::{CanonicalPath, PathGrant, PathRights, RealFsResolver, ResourceScope};
use lumen_core::lease::{LeaseLimits, RootLeaseParams};
use lumen_db::Database;
use lumen_db::lease::KernelAuditQuery;
use lumen_server::pi_tool_bridge::PiToolBridge;
use lumen_server::{
    ActionEnvelope, AuthorityDb, AuthorityKernelClient, AuthorityKernelConfig, Catalog,
    EffectClass, Obligation, ProjectionKind, SandboxError, SandboxFuture, SandboxRunner,
    SessionIdentityAuthority, StagedExecution, ToolDef, ToolOutcome, ToolPipeline, now_ms,
};

struct NoExecution;
impl SandboxRunner for NoExecution {
    fn stage<'a>(
        &'a self,
        _: &'a ActionEnvelope,
        _: &'a str,
        _: &'a [Obligation],
    ) -> SandboxFuture<'a, Box<dyn StagedExecution>> {
        Box::pin(async {
            Err(SandboxError::Unavailable(
                "deny probe has no executor".into(),
            ))
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return Err("usage: phase0_kernel_probe NEW_DATABASE EMPTY_LEASED_DIRECTORY".into());
    }
    let db_path = PathBuf::from(&args[1]);
    let leased_root = PathBuf::from(&args[2]);
    if db_path.exists() || !leased_root.is_dir() || leased_root.read_dir()?.next().is_some() {
        return Err("probe requires a new database and an empty leased directory".into());
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let mut config = AuthorityKernelConfig::test_config();
    config.db = AuthorityDb::Path(db_path.clone());
    let workspace = config.workspace;
    let kernel = Arc::new(AuthorityKernelClient::open(config).await?);
    let session = kernel.start_session_identity(None).await?;
    let mut scope = ResourceScope::default();
    scope.tools.insert("bct.read_file".into(), "^1.0".parse()?);
    scope.paths.push(PathGrant {
        root: CanonicalPath::parse(
            leased_root.to_str().ok_or("non-UTF8 path")?,
            &RealFsResolver,
            false,
        )?,
        rights: PathRights::READ,
    });
    scope.effects.push(lumen_core::canonical::EffectClass::Read);
    let now = now_ms();
    let lease = kernel
        .issue_root_lease(RootLeaseParams {
            lease_id: uuid::Uuid::new_v4().to_string(),
            subject: session.subject.clone(),
            scope,
            limits: LeaseLimits {
                not_before_ms: now,
                expires_at_ms: now + 30_000,
                budget: Budget::new().set(BudgetDimension::Executions, 1),
                max_executions: Some(1),
                single_use: true,
            },
            depth_limit: 1,
            lease_nonce: uuid::Uuid::new_v4().to_string(),
            issued_at_ms: now,
        })
        .await?;
    let mut catalog = Catalog::new();
    catalog.register(ToolDef {
        name: "bct.read_file".into(),
        version: "1.0.0".into(),
        description: "Deny-only Phase 0 probe".into(),
        parameters_schema: serde_json::json!({"type":"object","additionalProperties":false,
            "required":["path","max_bytes"],"properties":{"path":{"type":"string"},
            "max_bytes":{"type":"integer","minimum":1,"maximum":1048576}}}),
        effects: vec![EffectClass::Read],
        projection: ProjectionKind::FsRead,
    })?;
    let pipeline = ToolPipeline::new(Arc::new(catalog), kernel.clone(), Arc::new(NoExecution));
    let bridge = PiToolBridge::new(session.subject.clone(), vec![lease.lease_id]);
    let dispatch = bridge.dispatch(&pipeline, &bytes).await;
    // Destroy the identity even when dispatch fails. No private key leaves the kernel.
    kernel.destroy_session_identity(&session.subject).await?;
    let reply = dispatch?;
    // A signed single-use root is not a VHL action grant. This probe never
    // approves it; verify that the kernel rejects the absent action binding.
    // The requested file is also outside scope, but this run makes no claim
    // that path-subset evaluation was the first failing check.
    if !matches!(&reply.outcome, ToolOutcome::Denied { reason }
        if reason == "scope_exceeded: one-shot lease is not bound to the presented action")
    {
        return Err("probe did not receive the expected unapproved one-shot denial".into());
    }
    kernel.verify_kernel_audit().await?;
    let db = Database::connect(&db_path).await?;
    let events = db
        .kernel_audit_events(&workspace, &KernelAuditQuery::default())
        .await?;
    let checkpoints = db.kernel_audit_checkpoints(&workspace).await?;
    let public_keys: Vec<_> = db.kernel_key_generations(&workspace).await?.into_iter()
        .filter(|key| key.role == "host")
        .map(|key| serde_json::json!({"key_id":key.key_id,"verifying_key_hex":key.verifying_key_hex}))
        .collect();
    if events.is_empty() || checkpoints.is_empty() {
        return Err("missing durable audit evidence".into());
    }
    println!(
        "{}",
        serde_json::json!({"reply":reply,"events":events,"checkpoints":checkpoints,"host_public_keys":public_keys,
        "session_destroyed":true,"audit_verified":true,"execution_available":false})
    );
    db.close().await;
    Ok(())
}
