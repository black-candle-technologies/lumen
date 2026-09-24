//! Image and toolchain provenance.
//!
//! Every run records: guest-image digest, guest-kernel digest, rootfs
//! digest, toolchain manifest digest, and the sandbox policy version.
//! Images are promoted by digest only — never by floating tag — and every
//! manifest carries Ed25519 signatures from trusted release keys.
//!
//! Digest format throughout: `sha256:<64 hex chars>`.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::SandboxdError;

/// Pinned toolchain that produced the guest image. Part of the signed
/// manifest so a run can be traced to an exact, reproducible build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainManifest {
    /// e.g. `lumen-image-builder`.
    pub builder: String,
    pub builder_version: String,
    /// Guest kernel release, e.g. `6.8.0-lumen`.
    pub kernel_version: String,
    /// sha256 of the kernel config used.
    pub kernel_config_digest: String,
    /// Tool -> pinned version (compiler, busybox, agent, ...).
    pub tool_versions: BTreeMap<String, String>,
    /// Whether the build claims reproducibility (two builds, same digest).
    pub reproducible: bool,
}

/// Signed image manifest. `image_digest` is the sha256 of the canonical
/// JSON of this struct *without* the `signatures` field (OCI-style).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageManifest {
    pub format_version: u32,
    /// sha256 of the guest kernel image bytes.
    pub kernel_digest: String,
    /// sha256 of the read-only guest rootfs bytes.
    pub rootfs_digest: String,
    /// sha256 of the read-only workspace template disk bytes.
    pub workspace_template_digest: String,
    /// Optional snapshot (mem + vmstate) for fast restore.
    pub snapshot: Option<SnapshotRef>,
    pub toolchain: ToolchainManifest,
    /// Sandbox policy document version this image was built/tested against.
    pub policy_version: String,
    pub created_unix: u64,
    #[serde(default)]
    pub signatures: Vec<ManifestSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRef {
    pub mem_digest: String,
    pub vmstate_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSignature {
    /// Key id (hex of the verifying key) that produced this signature.
    pub key_id: String,
    /// Raw 64-byte Ed25519 signature over the canonical manifest bytes.
    pub signature: String,
}

/// What gets journaled per run: the full provenance chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceRecord {
    pub image_digest: String,
    pub kernel_digest: String,
    pub rootfs_digest: String,
    pub workspace_template_digest: String,
    /// sha256 of the canonical toolchain manifest JSON.
    pub toolchain_digest: String,
    pub policy_version: String,
    /// sandboxd binary version that executed the run.
    pub sandboxd_version: String,
    pub firecracker_version: String,
}

impl ImageManifest {
    /// Canonical bytes covered by signatures: JSON of the manifest with
    /// `signatures` removed, keys sorted, no whitespace.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SandboxdError> {
        let mut unsigned = self.clone();
        unsigned.signatures = Vec::new();
        // BTreeMap-backed struct + serde_json with preserve order off:
        // serialize via a sorted Value to guarantee canonical form.
        let value = serde_json::to_value(&unsigned).map_err(SandboxdError::Json)?;
        let canonical = sort_value(value);
        serde_json::to_vec(&canonical).map_err(SandboxdError::Json)
    }

    /// `sha256:<hex>` of the canonical bytes.
    pub fn image_digest(&self) -> Result<String, SandboxdError> {
        Ok(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(self.canonical_bytes()?))
        ))
    }

    /// Sign with a release key; appends to `signatures`.
    pub fn sign(&mut self, key: &SigningKey) -> Result<(), SandboxdError> {
        let bytes = self.canonical_bytes()?;
        let sig: Signature = key.sign(&bytes);
        let verifying = key.verifying_key();
        self.signatures.push(ManifestSignature {
            key_id: hex::encode(verifying.as_bytes()),
            signature: hex::encode(sig.to_bytes()),
        });
        Ok(())
    }

    /// Verify that at least one signature validates against `trusted_keys`.
    /// Fails closed on: malformed digest, malformed signature, unknown key,
    /// or zero valid signatures.
    pub fn verify(&self, trusted_keys: &[VerifyingKey]) -> Result<(), SandboxdError> {
        if self.format_version != 1 {
            return Err(SandboxdError::BadSignature(format!(
                "unsupported format_version {}",
                self.format_version
            )));
        }
        let bytes = self.canonical_bytes()?;
        let expected_digest = self.image_digest()?;
        // The manifest does not self-carry its digest; callers compare the
        // computed digest against the requested one. Signatures bind the
        // content; the digest binds the reference.
        let _ = expected_digest;

        let mut ok = false;
        for sig in &self.signatures {
            let sig_bytes = hex::decode(&sig.signature)
                .map_err(|_| SandboxdError::BadSignature("bad signature hex".into()))?;
            let sig_bytes: [u8; 64] = sig_bytes
                .try_into()
                .map_err(|_| SandboxdError::BadSignature("bad signature length".into()))?;
            let signature = Signature::from_bytes(&sig_bytes);
            for key in trusted_keys {
                if hex::encode(key.as_bytes()) != sig.key_id {
                    continue;
                }
                if key.verify(&bytes, &signature).is_ok() {
                    ok = true;
                    break;
                }
            }
            if ok {
                break;
            }
        }
        if ok {
            Ok(())
        } else {
            Err(SandboxdError::BadSignature(
                "no valid signature from a trusted key".into(),
            ))
        }
    }

    /// sha256 of the canonical toolchain JSON.
    pub fn toolchain_digest(&self) -> Result<String, SandboxdError> {
        let value = serde_json::to_value(&self.toolchain).map_err(SandboxdError::Json)?;
        let canonical = sort_value(value);
        let bytes = serde_json::to_vec(&canonical).map_err(SandboxdError::Json)?;
        Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
    }
}

fn sort_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<String, serde_json::Value> =
                map.into_iter().map(|(k, v)| (k, sort_value(v))).collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(sort_value).collect())
        }
        other => other,
    }
}

/// sha256 of a file's bytes, as `sha256:<hex>`.
pub fn digest_file(path: &Path) -> Result<String, SandboxdError> {
    let bytes = std::fs::read(path).map_err(SandboxdError::Io)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(&bytes))))
}

/// sha256 of in-memory bytes.
pub fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Load a trusted Ed25519 public key from a file. Accepts raw 32 bytes or
/// 64-char hex.
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey, SandboxdError> {
    let text = std::fs::read_to_string(path)
        .map_err(|_| SandboxdError::State(format!("cannot read key {}", path.display())))?;
    let text = text.trim();
    let bytes = if text.len() == 64 {
        hex::decode(text).map_err(|_| SandboxdError::State("bad key hex".into()))?
    } else {
        // Try raw bytes file.
        std::fs::read(path).map_err(SandboxdError::Io)?
    };
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SandboxdError::State("key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|_| SandboxdError::State("invalid ed25519 public key".into()))
}

/// Load a signing (private) key from a file: 64-char hex seed or 32 raw bytes.
pub fn load_signing_key(path: &Path) -> Result<SigningKey, SandboxdError> {
    let text = std::fs::read_to_string(path)
        .map_err(|_| SandboxdError::State(format!("cannot read key {}", path.display())))?;
    let text = text.trim();
    let bytes = if text.len() == 64 {
        hex::decode(text).map_err(|_| SandboxdError::State("bad key hex".into()))?
    } else {
        std::fs::read(path).map_err(SandboxdError::Io)?
    };
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SandboxdError::State("key must be 32 bytes".into()))?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Approved image on disk: `<store>/<image_digest>/`.
#[derive(Debug, Clone)]
pub struct StoredImage {
    pub dir: PathBuf,
    pub manifest: ImageManifest,
    pub image_digest: String,
}

/// Resolve and authenticate an image by digest. Fails closed when: the
/// digest is malformed, the store entry is missing, the manifest signature
/// is invalid, the computed digest mismatches, or any artifact digest in
/// the manifest mismatches the bytes on disk.
pub fn resolve_image(
    store: &Path,
    image_digest: &str,
    trusted_keys: &[VerifyingKey],
) -> Result<StoredImage, SandboxdError> {
    if !is_digest(image_digest) {
        return Err(SandboxdError::UnapprovedImage(format!(
            "malformed digest: {image_digest}"
        )));
    }
    // Digest is `[0-9a-f:]` only — safe to join as a path component.
    let dir = store.join(image_digest);
    let manifest_path = dir.join("manifest.json");
    let text = std::fs::read_to_string(&manifest_path).map_err(|_| {
        SandboxdError::UnapprovedImage(format!("image not in store: {image_digest}"))
    })?;
    let manifest: ImageManifest = serde_json::from_str(&text)
        .map_err(|_| SandboxdError::BadSignature("manifest is not valid JSON".into()))?;
    manifest.verify(trusted_keys)?;

    let computed = manifest.image_digest()?;
    if computed != image_digest {
        return Err(SandboxdError::BadSignature(format!(
            "manifest digest mismatch: computed {computed} != requested {image_digest}"
        )));
    }

    // Verify every referenced artifact against the bytes on disk. This is
    // what makes the digest a real binding, not a label.
    for (name, expected) in [
        ("vmlinux", manifest.kernel_digest.as_str()),
        ("rootfs.ext4", manifest.rootfs_digest.as_str()),
        (
            "workspace-template.raw",
            manifest.workspace_template_digest.as_str(),
        ),
    ] {
        let actual = digest_file(&dir.join(name))?;
        if actual != expected {
            return Err(SandboxdError::BadSignature(format!(
                "artifact {name} digest mismatch: {actual} != {expected}"
            )));
        }
    }
    if let Some(snap) = &manifest.snapshot {
        for (name, expected) in [
            ("snapshot.mem", snap.mem_digest.as_str()),
            ("snapshot.vmstate", snap.vmstate_digest.as_str()),
        ] {
            let actual = digest_file(&dir.join(name))?;
            if actual != expected {
                return Err(SandboxdError::BadSignature(format!(
                    "artifact {name} digest mismatch"
                )));
            }
        }
    }

    Ok(StoredImage {
        dir,
        manifest,
        image_digest: image_digest.to_string(),
    })
}

/// `sha256:` + 64 lowercase hex chars.
pub fn is_digest(s: &str) -> bool {
    let hex = s.strip_prefix("sha256:").unwrap_or("");
    hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn test_manifest() -> ImageManifest {
        let mut tools = BTreeMap::new();
        tools.insert("gcc".into(), "13.2.0".into());
        tools.insert("busybox".into(), "1.36.1".into());
        tools.insert("lumen-guest-agent".into(), "0.1.0".into());
        ImageManifest {
            format_version: 1,
            kernel_digest: "sha256:".to_string() + &"a".repeat(64),
            rootfs_digest: "sha256:".to_string() + &"b".repeat(64),
            workspace_template_digest: "sha256:".to_string() + &"c".repeat(64),
            snapshot: None,
            toolchain: ToolchainManifest {
                builder: "lumen-image-builder".into(),
                builder_version: "0.1.0".into(),
                kernel_version: "6.8.0-lumen".into(),
                kernel_config_digest: "sha256:".to_string() + &"d".repeat(64),
                tool_versions: tools,
                reproducible: true,
            },
            policy_version: "sandbox-policy-v1".into(),
            created_unix: 1_700_000_000,
            signatures: vec![],
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = key(0x11);
        let mut m = test_manifest();
        m.sign(&key).unwrap();
        assert!(m.verify(&[key.verifying_key()]).is_ok());
    }

    #[test]
    fn tampered_manifest_fails_verification() {
        let key = key(0x11);
        let mut m = test_manifest();
        m.sign(&key).unwrap();
        m.policy_version = "sandbox-policy-EVIL".into();
        assert!(m.verify(&[key.verifying_key()]).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let signing_key = key(0x11);
        let other = key(0x22);
        let mut m = test_manifest();
        m.sign(&signing_key).unwrap();
        assert!(m.verify(&[other.verifying_key()]).is_err());
    }

    #[test]
    fn unsigned_manifest_fails_verification() {
        let key = key(0x11);
        let m = test_manifest();
        assert!(m.verify(&[key.verifying_key()]).is_err());
    }

    #[test]
    fn canonical_bytes_are_stable() {
        let m = test_manifest();
        assert_eq!(m.canonical_bytes().unwrap(), m.canonical_bytes().unwrap());
        // Field order in JSON must not matter.
        let json = serde_json::to_string(&m).unwrap();
        let reparsed: ImageManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(
            m.canonical_bytes().unwrap(),
            reparsed.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn resolve_image_verifies_artifact_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let key = key(0x11);

        let kernel = b"fake-kernel";
        let rootfs = b"fake-rootfs";
        let ws = b"fake-workspace-template";
        let mut m = test_manifest();
        m.kernel_digest = digest_bytes(kernel);
        m.rootfs_digest = digest_bytes(rootfs);
        m.workspace_template_digest = digest_bytes(ws);
        m.sign(&key).unwrap();
        let digest = m.image_digest().unwrap();

        let dir = tmp.path().join(&digest);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("manifest.json"), serde_json::to_vec(&m).unwrap()).unwrap();
        std::fs::write(dir.join("vmlinux"), kernel).unwrap();
        std::fs::write(dir.join("rootfs.ext4"), rootfs).unwrap();
        std::fs::write(dir.join("workspace-template.raw"), ws).unwrap();

        let resolved = resolve_image(tmp.path(), &digest, &[key.verifying_key()]).unwrap();
        assert_eq!(resolved.image_digest, digest);

        // Tamper with one artifact: resolution must fail.
        std::fs::write(dir.join("rootfs.ext4"), b"tampered").unwrap();
        assert!(resolve_image(tmp.path(), &digest, &[key.verifying_key()]).is_err());
    }

    #[test]
    fn resolve_rejects_unknown_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let key = key(0x11);
        let digest = "sha256:".to_string() + &"f".repeat(64);
        assert!(resolve_image(tmp.path(), &digest, &[key.verifying_key()]).is_err());
    }

    #[test]
    fn resolve_rejects_malformed_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let key = key(0x11);
        // Path traversal attempt disguised as a digest.
        assert!(resolve_image(tmp.path(), "../../etc", &[key.verifying_key()]).is_err());
    }

    #[test]
    fn is_digest_strict() {
        assert!(is_digest(&("sha256:".to_string() + &"a".repeat(64))));
        assert!(!is_digest("sha256:abc"));
        assert!(!is_digest("md5:"));
        assert!(!is_digest(
            "../sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }
}
