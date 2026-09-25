//! Deterministic support-bundle export with redaction and a secret scan.
//!
//! `lumen support-bundle --out <dir>` writes a self-contained diagnostic
//! bundle: health report, audit trail, pending approvals, plugin admissions,
//! and the (redacted) configuration. Every file is written with sorted keys
//! so the same database state always produces the same bytes.
//!
//! Before the bundle is accepted, every exported file is scanned for
//! secret-shaped material (private keys, provider tokens, the configured
//! bearer token value, high-entropy strings). If the scan finds anything,
//! the export is deleted and the command fails closed: no bundle leaves the
//! machine with secrets in it.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use lumen_db::Database;
use thiserror::Error;
use uuid::Uuid;

use crate::{config::Config, health};

#[derive(Debug, Error)]
pub enum SupportBundleError {
    #[error(transparent)]
    Database(#[from] lumen_db::RepositoryError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("support bundle output already exists: {0}")]
    OutputExists(String),
    #[error(
        "secret scan found {hits} secret-shaped value(s) in the export ({locations}); \
         the bundle was deleted and nothing was written"
    )]
    SecretsFound { hits: usize, locations: String },
    #[error("{0}")]
    Refused(String),
}

pub struct SupportBundleReport {
    pub path: PathBuf,
    pub files: usize,
    pub audit_events: usize,
    pub redactions: usize,
    pub scanned_bytes: u64,
}

pub async fn export_bundle(
    config: &Config,
    database: &Database,
    config_path: &Path,
    out: &Path,
    audit_only: bool,
) -> Result<SupportBundleReport, SupportBundleError> {
    if out.exists() {
        return Err(SupportBundleError::OutputExists(out.display().to_string()));
    }
    // Build under a temp sibling, then the scan gates the final directory.
    // If the scan fails we delete everything: no partial bundle survives.
    let staging = out.with_extension(format!("staging-{}", Uuid::new_v4().simple()));
    create_staging_dir(&staging)?;
    let result = build_and_scan(config, database, config_path, &staging, out, audit_only).await;
    match result {
        Ok(report) => {
            fs::rename(&staging, out)?;
            Ok(report)
        }
        Err(error) => {
            let _ = fs::remove_dir_all(&staging);
            Err(error)
        }
    }
}

/// Create the staging directory with owner-only permissions. The bundle can
/// contain audit trails and configuration; it must not be world-readable
/// while being assembled.
fn create_staging_dir(staging: &Path) -> Result<(), SupportBundleError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(staging)?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(staging)?;
    }
    Ok(())
}

async fn build_and_scan(
    config: &Config,
    database: &Database,
    config_path: &Path,
    staging: &Path,
    out: &Path,
    audit_only: bool,
) -> Result<SupportBundleReport, SupportBundleError> {
    let mut redactions = 0usize;
    let workspace_id = config.workspace_id();
    let now = crate::runtime::now().as_u64();

    // manifest.json — bundle identity and provenance.
    let manifest = BTreeMap::from([
        ("bundle_version".to_owned(), serde_json::json!(1)),
        ("created_at".to_owned(), serde_json::json!(now)),
        (
            "lumen_version".to_owned(),
            serde_json::json!(env!("CARGO_PKG_VERSION")),
        ),
        ("audit_only".to_owned(), serde_json::json!(audit_only)),
    ]);
    write_json(staging.join("manifest.json"), &manifest)?;

    // health.json — always included; it never carries secrets.
    let health_report = health::collect(config, database)
        .await
        .map_err(|e| SupportBundleError::Refused(format!("health collection failed: {e}")))?;
    write_json(staging.join("health.json"), &health_report)?;

    // audit.jsonl — full hash-chained trail. Payloads are kernel-redacted at
    // write time; the scan below is defense in depth.
    let mut audit_events = 0usize;
    let mut audit_out = String::new();
    let mut after: i64 = -1;
    loop {
        let batch = database
            .list_audit_records(workspace_id, after, 500)
            .await?;
        if batch.is_empty() {
            break;
        }
        for record in &batch {
            after = after.max(record.sequence());
            audit_events += 1;
            let entry = BTreeMap::from([
                ("sequence".to_owned(), serde_json::json!(record.sequence())),
                (
                    "event_id".to_owned(),
                    serde_json::json!(record.event().id().to_string()),
                ),
                (
                    "timestamp".to_owned(),
                    serde_json::json!(record.event().timestamp().as_u64()),
                ),
                (
                    "kind".to_owned(),
                    serde_json::json!(record.event().kind().as_str()),
                ),
                (
                    "outcome".to_owned(),
                    serde_json::to_value(record.event().outcome())?,
                ),
                (
                    "previous_hash".to_owned(),
                    serde_json::json!(record.previous_hash().to_string()),
                ),
                (
                    "event_hash".to_owned(),
                    serde_json::json!(record.hash().to_string()),
                ),
                (
                    "payload".to_owned(),
                    redact_value(record.event().payload(), &mut redactions),
                ),
            ]);
            audit_out.push_str(&serde_json::to_string(&entry)?);
            audit_out.push('\n');
        }
    }
    fs::write(staging.join("audit.jsonl"), audit_out)?;

    if !audit_only {
        // approvals.jsonl — pending approvals with exact normalized arguments.
        let now_ts = crate::runtime::now();
        let pending = database
            .list_pending_approvals(workspace_id, now_ts)
            .await?;
        let mut approvals_out = String::new();
        for approval in &pending {
            let entry = BTreeMap::from([
                (
                    "approval_id".to_owned(),
                    serde_json::json!(approval.approval_id().to_string()),
                ),
                (
                    "run_id".to_owned(),
                    serde_json::json!(approval.run_id().to_string()),
                ),
                ("kind".to_owned(), serde_json::json!(approval.kind())),
                (
                    "fingerprint".to_owned(),
                    serde_json::json!(approval.fingerprint()),
                ),
                (
                    "created_at".to_owned(),
                    serde_json::json!(approval.created_at().as_u64()),
                ),
                (
                    "expires_at".to_owned(),
                    serde_json::json!(approval.expires_at().as_u64()),
                ),
                (
                    "arguments".to_owned(),
                    redact_canonical(approval.arguments(), &mut redactions),
                ),
                (
                    "capabilities".to_owned(),
                    serde_json::json!(approval.capabilities()),
                ),
            ]);
            approvals_out.push_str(&serde_json::to_string(&entry)?);
            approvals_out.push('\n');
        }
        fs::write(staging.join("approvals.jsonl"), approvals_out)?;

        // plugins/admissions.jsonl — admission records (digests and review
        // status; no secret material by construction).
        let admissions = crate::plugin_admission::list(config)
            .map_err(|e| SupportBundleError::Refused(format!("admission listing failed: {e}")))?;
        let mut admissions_out = String::new();
        for summary in &admissions {
            admissions_out.push_str(&serde_json::to_string(summary)?);
            admissions_out.push('\n');
        }
        let plugins_dir = staging.join("plugins");
        fs::create_dir_all(&plugins_dir)?;
        fs::write(plugins_dir.join("admissions.jsonl"), admissions_out)?;

        // config.redacted.toml — the operator config with secret-shaped
        // values replaced.
        let redacted_config = match fs::read_to_string(config_path) {
            Ok(text) => redact_config_text(&text, &mut redactions),
            Err(_) => "# config file was not readable at bundle time\n".to_owned(),
        };
        fs::write(staging.join("config.redacted.toml"), redacted_config)?;
    }

    // The scan gates the export. Any hit deletes the whole staging tree.
    let scan = scan_for_secrets(staging, config)?;
    if !scan.hits.is_empty() {
        let locations = scan
            .hits
            .iter()
            .map(|hit| format!("{}:{}", hit.file, hit.pattern))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(SupportBundleError::SecretsFound {
            hits: scan.hits.len(),
            locations,
        });
    }

    let files = count_files(staging)?;
    Ok(SupportBundleReport {
        path: out.to_path_buf(),
        files,
        audit_events,
        redactions,
        scanned_bytes: scan.bytes,
    })
}

fn write_json(path: PathBuf, value: &impl serde::Serialize) -> Result<(), SupportBundleError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

fn count_files(dir: &Path) -> Result<usize, SupportBundleError> {
    let mut count = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            count += count_files(&entry.path())?;
        } else if file_type.is_file() {
            count += 1;
        }
    }
    Ok(count)
}

/// Redact secret-shaped keys inside a canonical audit payload.
fn redact_value(
    value: &lumen_core::action::CanonicalValue,
    redactions: &mut usize,
) -> serde_json::Value {
    let json: serde_json::Value =
        serde_json::from_slice(&serde_json::to_vec(value).unwrap_or_default())
            .unwrap_or(serde_json::Value::Null);
    redact_json(json, redactions)
}

fn redact_canonical(
    value: &lumen_core::action::CanonicalValue,
    redactions: &mut usize,
) -> serde_json::Value {
    redact_value(value, redactions)
}

fn redact_json(value: serde_json::Value, redactions: &mut usize) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let redacted = map
                .into_iter()
                .map(|(key, val)| {
                    if is_secret_key(&key) {
                        *redactions += 1;
                        (key, serde_json::Value::String("[REDACTED]".into()))
                    } else {
                        (key, redact_json(val, redactions))
                    }
                })
                .collect();
            serde_json::Value::Object(redacted)
        }
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .into_iter()
                .map(|v| redact_json(v, redactions))
                .collect(),
        ),
        serde_json::Value::String(text) => {
            if looks_like_secret(&text) {
                *redactions += 1;
                serde_json::Value::String("[REDACTED]".into())
            } else {
                serde_json::Value::String(text)
            }
        }
        other => other,
    }
}

fn is_secret_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    lower.contains("secret")
        || lower.contains("password")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower.contains("private_key")
        || lower.contains("privatekey")
        || lower.contains("bearer")
        || lower == "token"
        || lower.ends_with("_token")
        || lower.ends_with("-token")
}

fn redact_config_text(text: &str, redactions: &mut usize) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let trimmed = line.trim_start();
        let is_kv = trimmed.contains('=') && !trimmed.starts_with('#') && !trimmed.starts_with('[');
        if is_kv {
            let key = trimmed
                .split(['=', ' '])
                .next()
                .unwrap_or("")
                .trim_matches('"');
            if is_secret_key(key) {
                *redactions += 1;
                let indent_len = line.len() - trimmed.len();
                out.push_str(&line[..indent_len]);
                out.push_str(&format!("{key} = \"[REDACTED]\""));
                out.push('\n');
                continue;
            }
        }
        // Bearer tokens embedded in URLs or query strings.
        let mut redacted_line = line.to_owned();
        for marker in ["?token=", "&token=", "?api_key=", "&api_key="] {
            if let Some(start) = redacted_line.find(marker) {
                let value_start = start + marker.len();
                let value_end = redacted_line[value_start..]
                    .find(['&', '"', '\''])
                    .map(|i| value_start + i)
                    .unwrap_or(redacted_line.len());
                if value_end > value_start {
                    *redactions += 1;
                    redacted_line.replace_range(value_start..value_end, "[REDACTED]");
                }
            }
        }
        out.push_str(&redacted_line);
        out.push('\n');
    }
    out
}

#[derive(Debug)]
struct SecretHit {
    file: String,
    pattern: &'static str,
}

struct SecretScan {
    hits: Vec<SecretHit>,
    bytes: u64,
}

/// Scan every exported file for secret-shaped material.
///
/// Patterns cover PEM private keys, well-known provider token prefixes, the
/// configured bearer-token value, and high-entropy strings that are not
/// plausible content digests (64 lowercase hex chars are expected throughout
/// the bundle and are excluded).
fn scan_for_secrets(dir: &Path, config: &Config) -> Result<SecretScan, SupportBundleError> {
    let mut hits = Vec::new();
    let mut bytes = 0u64;
    let bearer_value = std::env::var(&config.authentication.token_environment).ok();
    scan_dir(dir, dir, &mut hits, &mut bytes, bearer_value.as_deref())?;
    Ok(SecretScan { hits, bytes })
}

fn scan_dir(
    root: &Path,
    dir: &Path,
    hits: &mut Vec<SecretHit>,
    bytes: &mut u64,
    bearer_value: Option<&str>,
) -> Result<(), SupportBundleError> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            scan_dir(root, &path, hits, bytes, bearer_value)?;
        } else if file_type.is_file() {
            let rel = path
                .strip_prefix(root)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| path.display().to_string());
            let content = fs::read(&path)?;
            *bytes += content.len() as u64;
            let text = String::from_utf8_lossy(&content);
            scan_text(&rel, &text, hits, bearer_value);
        }
    }
    Ok(())
}

fn scan_text(file: &str, text: &str, hits: &mut Vec<SecretHit>, bearer_value: Option<&str>) {
    let mut push = |pattern: &'static str| {
        // Avoid duplicate hits for the same file+pattern.
        if !hits.iter().any(|h| h.file == file && h.pattern == pattern) {
            hits.push(SecretHit {
                file: file.to_owned(),
                pattern,
            });
        }
    };
    const PREFIXES: &[(&str, &str)] = &[
        ("-----BEGIN PRIVATE KEY-----", "pem-private-key"),
        ("-----BEGIN RSA PRIVATE KEY-----", "pem-private-key"),
        ("-----BEGIN EC PRIVATE KEY-----", "pem-private-key"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "openssh-private-key"),
        ("sk-ant-", "anthropic-key"),
        ("sk-", "generic-sk-key"),
        ("ghp_", "github-pat"),
        ("gho_", "github-oauth"),
        ("xoxb-", "slack-token"),
        ("xoxp-", "slack-token"),
        ("AKIA", "aws-access-key"),
    ];
    for (prefix, pattern) in PREFIXES {
        if text.contains(prefix) {
            // "sk-" alone is too broad without a length check.
            if *prefix == "sk-" {
                if has_prefixed_token(text, "sk-", 20) {
                    push(pattern);
                }
            } else {
                push(pattern);
            }
        }
    }
    if let Some(value) = bearer_value
        && !value.is_empty()
        && text.contains(value)
    {
        push("bearer-token-value");
    }
    if has_high_entropy_token(text) {
        push("high-entropy-token");
    }
}

fn has_prefixed_token(text: &str, prefix: &str, min_len: usize) -> bool {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .any(|token| token.starts_with(prefix) && token.len() >= prefix.len() + min_len)
}

/// Shannon-entropy heuristic for long opaque strings. 64-char lowercase hex
/// digests (the bundle's content pins) are excluded; anything else at 32+
/// chars with entropy above 4.2 bits/char is flagged.
fn has_high_entropy_token(text: &str) -> bool {
    // Split on whitespace and structural characters, but keep secret-like
    // punctuation inside tokens: real credentials often contain symbols.
    text.split(|c: char| {
        !(c.is_ascii_alphanumeric()
            || matches!(
                c,
                '_' | '-'
                    | '.'
                    | '~'
                    | '#'
                    | '$'
                    | '@'
                    | '&'
                    | '*'
                    | '!'
                    | '('
                    | ')'
                    | '%'
                    | '^'
                    | '+'
                    | '='
            ))
    })
    .filter(|token| token.len() >= 32)
    .any(|token| {
        if token.len() == 64
            && token
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return false;
        }
        shannon_entropy(token) > 4.2
    })
}

fn shannon_entropy(token: &str) -> f64 {
    let mut counts = [0u32; 256];
    for byte in token.bytes() {
        counts[byte as usize] += 1;
    }
    let len = token.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

fn looks_like_secret(text: &str) -> bool {
    if text == "[REDACTED]" || text.len() < 32 {
        return false;
    }
    if text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return false;
    }
    // UUIDs and plain identifiers are not secrets.
    if Uuid::parse_str(text).is_ok() {
        return false;
    }
    shannon_entropy(text) > 4.2
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=_-.~".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn staging_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().expect("tempdir");
        let staging = directory.path().join("staging");
        create_staging_dir(&staging).expect("create staging dir");
        let mode = fs::metadata(&staging)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn config_redaction_replaces_secret_values() {
        let mut redactions = 0;
        let redacted = redact_config_text(
            "[model]\nendpoint = \"https://example.com\"\napi_key = \"sk-abc123\"\n# comment\n",
            &mut redactions,
        );
        assert!(!redacted.contains("sk-abc123"));
        assert!(redacted.contains("[REDACTED]"));
        assert_eq!(redactions, 1);
    }

    #[test]
    fn content_digests_do_not_trip_the_scanner() {
        let digest = "a".repeat(64);
        let mut hits = Vec::new();
        scan_text(
            "audit.jsonl",
            &format!("\"package_digest\": \"{digest}\""),
            &mut hits,
            None,
        );
        assert!(hits.is_empty(), "digest flagged: {hits:?}");
    }

    #[test]
    fn scanner_flags_private_keys_and_bearer_values() {
        let mut hits = Vec::new();
        scan_text(
            "notes.txt",
            "-----BEGIN PRIVATE KEY-----\nMIIE...",
            &mut hits,
            None,
        );
        assert!(hits.iter().any(|h| h.pattern == "pem-private-key"));
        let mut hits = Vec::new();
        scan_text(
            "env.txt",
            "token=hunter2-secret-value",
            &mut hits,
            Some("hunter2-secret-value"),
        );
        assert!(hits.iter().any(|h| h.pattern == "bearer-token-value"));
    }

    #[test]
    fn scanner_flags_high_entropy_tokens() {
        let mut hits = Vec::new();
        scan_text(
            "leak.json",
            r#"{"session":"xK9#mQ2$vL8@nP4&wR6*tY1!uI3(oP5)"}"#,
            &mut hits,
            None,
        );
        assert!(hits.iter().any(|h| h.pattern == "high-entropy-token"));
    }

    #[test]
    fn uuids_are_not_flagged() {
        let mut hits = Vec::new();
        scan_text(
            "ids.json",
            r#"{"id":"26db5a31-94f0-4e92-a9c9-4cdf19d71c31"}"#,
            &mut hits,
            None,
        );
        assert!(!hits.iter().any(|h| h.pattern == "high-entropy-token"));
    }
}
