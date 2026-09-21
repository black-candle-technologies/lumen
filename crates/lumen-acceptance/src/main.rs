use lumen_core::{
    action::CanonicalValue,
    egress::{DataClass, ProviderId},
    model::{ModelInput, ModelMessage, ModelRole},
    provider::{
        LocalRuntimeKind, ModelCapabilities, ModelCapability, ModelProfile, ModelProfileId,
        ModelTrustZone, ProviderAdapter, ProviderConfig, ProviderKind,
    },
    secret::SecretRefId,
};
use lumen_integrations::providers::{
    anthropic::AnthropicAdapter, openai::OpenAiAdapter,
    openai_compatible::LocalOpenAiCompatibleAdapter,
};
use serde::Serialize;
use std::{
    env, fs,
    path::PathBuf,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Pass,
    Fail,
    Skipped,
}
#[derive(Debug, Serialize)]
struct Case {
    name: String,
    status: Status,
    duration_millis: u64,
    detail: String,
}
#[derive(Debug, Serialize)]
struct Report {
    schema: u16,
    commit: String,
    dirty: bool,
    os: String,
    arch: String,
    rustc: String,
    cargo: String,
    started_at_millis: u64,
    cases: Vec<Case>,
}
#[tokio::main]
async fn main() {
    let started = epoch();
    let commit = output("git", &["rev-parse", "HEAD"]).unwrap_or_else(|_| "unknown".into());
    let dirty = output("git", &["status", "--porcelain"]).map_or(true, |v| !v.trim().is_empty());
    let rustc = output("rustc", &["--version"]).unwrap_or_else(|e| e);
    let cargo = output("cargo", &["--version"]).unwrap_or_else(|e| e);
    let mut cases = Vec::new();
    cases.push(if dirty {
        Case {
            name: "git_clean".into(),
            status: Status::Fail,
            duration_millis: 0,
            detail: "working tree is dirty".into(),
        }
    } else {
        Case {
            name: "git_clean".into(),
            status: Status::Pass,
            duration_millis: 0,
            detail: "clean".into(),
        }
    });
    for (name, program, args) in commands() {
        cases.push(run(name, program, &args));
    }
    cases.push(live_openai().await);
    cases.push(live_anthropic().await);
    cases.push(
        live_local(
            "ollama",
            LocalRuntimeKind::Ollama,
            "LUMEN_ACCEPT_OLLAMA_ENDPOINT",
            "LUMEN_ACCEPT_OLLAMA_MODEL",
        )
        .await,
    );
    cases.push(
        live_local(
            "llamacpp",
            LocalRuntimeKind::LlamaCpp,
            "LUMEN_ACCEPT_LLAMACPP_ENDPOINT",
            "LUMEN_ACCEPT_LLAMACPP_MODEL",
        )
        .await,
    );
    cases.push(
        live_local(
            "vllm",
            LocalRuntimeKind::Vllm,
            "LUMEN_ACCEPT_VLLM_ENDPOINT",
            "LUMEN_ACCEPT_VLLM_MODEL",
        )
        .await,
    );
    if env::var("LUMEN_ACCEPT_REQUIRE_LIVE").ok().as_deref() == Some("1") {
        for c in &mut cases {
            if c.name.starts_with("live_") && matches!(c.status, Status::Skipped) {
                c.status = Status::Fail;
                c.detail = "live provider was required but not configured".into();
            }
        }
    }
    let report = Report {
        schema: 1,
        commit,
        dirty,
        os: env::consts::OS.into(),
        arch: env::consts::ARCH.into(),
        rustc,
        cargo,
        started_at_millis: started,
        cases,
    };
    let dir = PathBuf::from(
        env::var("LUMEN_ACCEPTANCE_OUT").unwrap_or_else(|_| "target/m6h-acceptance".into()),
    );
    fs::create_dir_all(&dir).expect("create acceptance output");
    let stem = format!("{}-{}-{}", report.commit, report.os, report.arch);
    fs::write(
        dir.join(format!("{stem}.json")),
        serde_json::to_vec_pretty(&report).expect("json"),
    )
    .expect("write json");
    fs::write(dir.join(format!("{stem}.md")), markdown(&report)).expect("write markdown");
    for c in &report.cases {
        println!("{} {:?} {}", c.name, c.status, c.detail)
    }
    if report
        .cases
        .iter()
        .any(|c| matches!(c.status, Status::Fail))
    {
        std::process::exit(1)
    }
}
fn commands() -> Vec<(&'static str, &'static str, Vec<&'static str>)> {
    vec![
        (
            "core_trust_gate",
            "cargo",
            vec![
                "test",
                "-p",
                "lumen-core",
                "trust_gate",
                "--",
                "--nocapture",
            ],
        ),
        (
            "db_gate",
            "cargo",
            vec!["test", "-p", "lumen-db", "trust_gate", "--", "--nocapture"],
        ),
        (
            "worker_runtime",
            "cargo",
            vec!["test", "-p", "lumen-worker-runtime", "--", "--nocapture"],
        ),
        (
            "control_plane",
            "cargo",
            vec!["test", "-p", "lumen-control-plane", "--", "--nocapture"],
        ),
        (
            "server",
            "cargo",
            vec!["test", "-p", "lumen-server", "--", "--nocapture"],
        ),
        ("workspace", "cargo", vec!["test", "--workspace"]),
        (
            "clippy",
            "cargo",
            vec![
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
        ),
        ("fmt", "cargo", vec!["fmt", "--all", "--", "--check"]),
        ("web_test", npm(), vec!["--prefix", "apps/web", "test"]),
        (
            "web_check",
            npm(),
            vec!["--prefix", "apps/web", "run", "check"],
        ),
    ]
}
fn npm() -> &'static str {
    if cfg!(windows) { "npm.cmd" } else { "npm" }
}
fn run(name: &str, program: &str, args: &[&str]) -> Case {
    let start = Instant::now();
    match Command::new(program).args(args).output() {
        Ok(v) if v.status.success() => Case {
            name: name.into(),
            status: Status::Pass,
            duration_millis: ms(start.elapsed()),
            detail: bounded(&String::from_utf8_lossy(&v.stdout)),
        },
        Ok(v) => Case {
            name: name.into(),
            status: Status::Fail,
            duration_millis: ms(start.elapsed()),
            detail: bounded(&format!(
                "{}\n{}",
                String::from_utf8_lossy(&v.stdout),
                String::from_utf8_lossy(&v.stderr)
            )),
        },
        Err(e) => Case {
            name: name.into(),
            status: Status::Fail,
            duration_millis: ms(start.elapsed()),
            detail: e.to_string(),
        },
    }
}
async fn live_openai() -> Case {
    let Some(key) = env::var("LUMEN_ACCEPT_OPENAI_KEY").ok() else {
        return skipped("live_openai", "LUMEN_ACCEPT_OPENAI_KEY not set");
    };
    let Some(model) = env::var("LUMEN_ACCEPT_OPENAI_MODEL").ok() else {
        return skipped("live_openai", "LUMEN_ACCEPT_OPENAI_MODEL not set");
    };
    let endpoint = env::var("LUMEN_ACCEPT_OPENAI_ENDPOINT")
        .unwrap_or_else(|_| "https://api.openai.com/v1/".into());
    live_remote("live_openai", ProviderKind::OpenAi, &endpoint, &model, key).await
}
async fn live_anthropic() -> Case {
    let Some(key) = env::var("LUMEN_ACCEPT_ANTHROPIC_KEY").ok() else {
        return skipped("live_anthropic", "LUMEN_ACCEPT_ANTHROPIC_KEY not set");
    };
    let Some(model) = env::var("LUMEN_ACCEPT_ANTHROPIC_MODEL").ok() else {
        return skipped("live_anthropic", "LUMEN_ACCEPT_ANTHROPIC_MODEL not set");
    };
    let endpoint = env::var("LUMEN_ACCEPT_ANTHROPIC_ENDPOINT")
        .unwrap_or_else(|_| "https://api.anthropic.com/v1/".into());
    live_remote(
        "live_anthropic",
        ProviderKind::Anthropic,
        &endpoint,
        &model,
        key,
    )
    .await
}
async fn live_remote(
    name: &str,
    kind: ProviderKind,
    endpoint: &str,
    model: &str,
    key: String,
) -> Case {
    let start = Instant::now();
    let pid = match ProviderId::parse(format!("accept-{name}")) {
        Ok(v) => v,
        Err(e) => return fail(name, start, e.to_string()),
    };
    let config =
        match ProviderConfig::remote(pid.clone(), 1, kind, endpoint, true, SecretRefId::new()) {
            Ok(v) => v,
            Err(e) => return fail(name, start, e.to_string()),
        };
    let profile = match ModelProfile::new(
        ModelProfileId::parse(format!("{name}-model")).expect("static id"),
        1,
        pid,
        1,
        model,
        true,
        ModelCapabilities::new([ModelCapability::Text]),
        262_144,
        ModelTrustZone::RemoteApproved,
        1,
        0,
    ) {
        Ok(v) => v,
        Err(e) => return fail(name, start, e.to_string()),
    };
    let adapter: Box<dyn ProviderAdapter> = match kind {
        ProviderKind::OpenAi => match OpenAiAdapter::new(config, key) {
            Ok(v) => Box::new(v),
            Err(e) => return fail(name, start, e.to_string()),
        },
        ProviderKind::Anthropic => match AnthropicAdapter::new(config, key) {
            Ok(v) => Box::new(v),
            Err(e) => return fail(name, start, e.to_string()),
        },
        ProviderKind::OpenAiCompatible => {
            return fail(name, start, "invalid remote acceptance kind".into());
        }
    };
    smoke(name, start, adapter.as_ref(), &profile).await
}
async fn live_local(
    name: &str,
    runtime: LocalRuntimeKind,
    endpoint_env: &str,
    model_env: &str,
) -> Case {
    let Some(model) = env::var(model_env).ok() else {
        return skipped(&format!("live_{name}"), &format!("{model_env} not set"));
    };
    let endpoint = env::var(endpoint_env).unwrap_or_else(|_| match runtime {
        LocalRuntimeKind::Ollama => "http://127.0.0.1:11434/v1/".into(),
        LocalRuntimeKind::LlamaCpp => "http://127.0.0.1:8080/v1/".into(),
        LocalRuntimeKind::Vllm => "http://127.0.0.1:8000/v1/".into(),
    });
    let start = Instant::now();
    let case = format!("live_{name}");
    let pid = ProviderId::parse(format!("accept-{name}")).expect("static id");
    let key = env::var(format!("LUMEN_ACCEPT_{}_KEY", name.to_ascii_uppercase())).ok();
    let config = match ProviderConfig::local_openai_compatible(
        pid.clone(),
        1,
        &endpoint,
        runtime,
        true,
        key.as_ref().map(|_| SecretRefId::new()),
    ) {
        Ok(v) => v,
        Err(e) => return fail(&case, start, e.to_string()),
    };
    let profile = ModelProfile::new(
        ModelProfileId::parse(format!("{name}-model")).expect("static id"),
        1,
        pid,
        1,
        model,
        true,
        ModelCapabilities::new([ModelCapability::Text]),
        65_536,
        ModelTrustZone::LocalRestricted,
        1,
        0,
    )
    .expect("acceptance profile");
    let adapter = match LocalOpenAiCompatibleAdapter::new(config, key) {
        Ok(v) => v,
        Err(e) => return fail(&case, start, e.to_string()),
    };
    smoke(&case, start, &adapter, &profile).await
}
async fn smoke(
    name: &str,
    start: Instant,
    adapter: &dyn ProviderAdapter,
    profile: &ModelProfile,
) -> Case {
    let input = ModelInput::new(vec![ModelMessage::new(
        ModelRole::User,
        CanonicalValue::from("Reply with OK."),
    )])
    .with_data_class(DataClass::Public);
    match tokio::time::timeout(
        Duration::from_secs(120),
        adapter.generate(profile, input, CancellationToken::new()),
    )
    .await
    {
        Ok(Ok(r)) => Case {
            name: name.into(),
            status: Status::Pass,
            duration_millis: ms(start.elapsed()),
            detail: format!(
                "resolved_model={} input_tokens={:?} output_tokens={:?}",
                r.resolved_model, r.usage.input_tokens, r.usage.output_tokens
            ),
        },
        Ok(Err(e)) => fail(name, start, e.to_string()),
        Err(_) => fail(name, start, "provider smoke timed out".into()),
    }
}
fn skipped(name: &str, detail: &str) -> Case {
    Case {
        name: name.into(),
        status: Status::Skipped,
        duration_millis: 0,
        detail: detail.into(),
    }
}
fn fail(name: &str, start: Instant, detail: String) -> Case {
    Case {
        name: name.into(),
        status: Status::Fail,
        duration_millis: ms(start.elapsed()),
        detail: bounded(&detail),
    }
}
fn output(p: &str, a: &[&str]) -> Result<String, String> {
    let v = Command::new(p)
        .args(a)
        .output()
        .map_err(|e| e.to_string())?;
    if !v.status.success() {
        return Err(bounded(&String::from_utf8_lossy(&v.stderr)));
    }
    Ok(String::from_utf8_lossy(&v.stdout).trim().to_owned())
}
fn bounded(v: &str) -> String {
    v.chars().take(2000).collect()
}
fn ms(v: Duration) -> u64 {
    u64::try_from(v.as_millis()).unwrap_or(u64::MAX)
}
fn epoch() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}
fn markdown(r: &Report) -> String {
    let mut s = format!(
        "# Lumen M6H acceptance\n\n- commit: `{}`\n- platform: `{}/{}`\n- rustc: `{}`\n- cargo: `{}`\n- dirty: `{}`\n\n| Case | Status | ms | Detail |\n|---|---|---:|---|\n",
        r.commit, r.os, r.arch, r.rustc, r.cargo, r.dirty
    );
    for c in &r.cases {
        s.push_str(&format!(
            "| {} | {:?} | {} | {} |\n",
            c.name,
            c.status,
            c.duration_millis,
            c.detail.replace('|', "\\|").replace('\n', " ")
        ));
    }
    s
}
