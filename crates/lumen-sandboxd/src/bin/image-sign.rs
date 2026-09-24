//! lumen-image-sign: sign and verify guest image manifests.
//!
//! Signatures are embedded in the manifest's `signatures[]` array —
//! `{key_id, signature}` with a hex key id and a hex 64-byte Ed25519
//! signature over [`ImageManifest::canonical_bytes`]. This is the exact
//! format `provenance::ImageManifest::verify` checks when sandboxd
//! resolves an image, so the signer and the verifier can never disagree
//! (no second canonicalizer).
//!
//! Usage:
//!   lumen-image-sign sign   --manifest M --key signing.key [--out O]
//!   lumen-image-sign verify --manifest M --key verify.key
//!
//! Keys are Ed25519 seeds/public keys as 64-char hex or 32 raw bytes
//! (see `provenance::load_signing_key` / `load_verifying_key`). PEM is
//! not accepted.
//!
//! `sign` writes the signed manifest back to `--manifest` in place, or to
//! `--out` when given, and prints the image digest (`sha256:<hex>`) to
//! stdout. `verify` exits 0 on a valid signature from the given key.

use std::path::{Path, PathBuf};

use lumen_sandboxd::SandboxdError;
use lumen_sandboxd::provenance::{ImageManifest, load_signing_key, load_verifying_key};

fn usage() -> ! {
    eprintln!(
        "usage: lumen-image-sign sign --manifest M --key signing.key [--out O]\n       lumen-image-sign verify --manifest M --key verify.key"
    );
    std::process::exit(2);
}

fn flag_value(args: &[String], i: usize, flag: &str) -> PathBuf {
    match args.get(i) {
        Some(v) => PathBuf::from(v),
        None => {
            eprintln!("missing value for {flag}");
            usage();
        }
    }
}

fn read_manifest(path: &Path) -> Result<ImageManifest, SandboxdError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        SandboxdError::State(format!("cannot read manifest {}: {e}", path.display()))
    })?;
    serde_json::from_str(&text).map_err(SandboxdError::Json)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("lumen-image-sign: error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), SandboxdError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = match args.first() {
        Some(m) => m.clone(),
        None => usage(),
    };
    let mut manifest: Option<PathBuf> = None;
    let mut key: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                manifest = Some(flag_value(&args, i, "--manifest"));
            }
            "--key" => {
                i += 1;
                key = Some(flag_value(&args, i, "--key"));
            }
            "--out" => {
                i += 1;
                out = Some(flag_value(&args, i, "--out"));
            }
            other => {
                eprintln!("unknown arg: {other}");
                usage();
            }
        }
        i += 1;
    }
    let Some(manifest) = manifest else {
        eprintln!("missing --manifest");
        usage();
    };
    let Some(key) = key else {
        eprintln!("missing --key");
        usage();
    };

    match mode.as_str() {
        "sign" => {
            let signing_key = load_signing_key(&key)?;
            let mut m = read_manifest(&manifest)?;
            m.sign(&signing_key)?;
            let digest = m.image_digest()?;
            let text = serde_json::to_string_pretty(&m).map_err(SandboxdError::Json)?;
            let dest = out.unwrap_or(manifest);
            std::fs::write(&dest, format!("{text}\n")).map_err(|e| {
                SandboxdError::State(format!("cannot write {}: {e}", dest.display()))
            })?;
            println!("signed {digest}");
            Ok(())
        }
        "verify" => {
            if out.is_some() {
                return Err(SandboxdError::State(
                    "--out is only valid for sign".to_string(),
                ));
            }
            let vk = load_verifying_key(&key)?;
            let m = read_manifest(&manifest)?;
            m.verify(&[vk])?;
            println!("signature OK");
            Ok(())
        }
        other => {
            eprintln!("unknown mode: {other}");
            usage();
        }
    }
}
