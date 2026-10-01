//! Phase 1 boundary regressions: typed scope v2, strict resource decode.
use lumen_core::canonical::{
    AccountRef, CanonicalPath, HostPattern, ModelClass, NetworkDestination, PathGrant,
    PathResolver, PathRights, PortSet, ResourceScope, SecretRef, ToolName,
};
use proptest::prelude::*;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::{
    io,
    path::{Path, PathBuf},
};

struct Identity;
impl PathResolver for Identity {
    fn resolve(&self, path: &Path) -> io::Result<PathBuf> {
        Ok(path.to_owned())
    }
}
fn path_scope(path: &str, folded: bool) -> ResourceScope {
    let mut scope = ResourceScope::default();
    scope.paths.push(PathGrant {
        root: CanonicalPath::parse(path, &Identity, folded).unwrap(),
        rights: PathRights::READ,
    });
    scope
}
fn reject<T: DeserializeOwned>(values: &[Value]) {
    for value in values {
        assert!(
            serde_json::from_value::<T>(value.clone()).is_err(),
            "accepted {value}"
        );
    }
}

#[test]
fn path_views_and_account_delimiters_cannot_collide() {
    let a = path_scope("/scope/path~fold", false);
    let b = path_scope("/scope/path", true);
    assert_ne!(
        a.paths[0].root.canonical_form(),
        b.paths[0].root.canonical_form()
    );
    assert_ne!(a.canonical_digest().unwrap(), b.canonical_digest().unwrap());
    let mut a = ResourceScope::default();
    let mut b = ResourceScope::default();
    let aa = AccountRef::parse("a:b", "c").unwrap();
    let bb = AccountRef::parse("a", "b:c").unwrap();
    assert_ne!(aa.canonical_form(), bb.canonical_form());
    a.accounts.insert(aa);
    b.accounts.insert(bb);
    assert_ne!(a.canonical_digest().unwrap(), b.canonical_digest().unwrap());
}

#[test]
fn unknown_nested_authority_fields_are_rejected() {
    let scope = path_scope("/workspace", false);
    let wire = serde_json::to_value(scope).unwrap();
    for pointer in ["", "/paths/0", "/paths/0/root", "/paths/0/rights"] {
        let mut changed = wire.clone();
        changed
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("future_authority".into(), json!(true));
        reject::<ResourceScope>(&[changed]);
    }
    let net = NetworkDestination::parse("https://example.com", &["GET"]).unwrap();
    let wire = serde_json::to_value(net).unwrap();
    for pointer in ["", "/ports"] {
        let mut changed = wire.clone();
        changed
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("future_authority".into(), json!(true));
        reject::<NetworkDestination>(&[changed]);
    }
    assert!(
        serde_json::from_str::<ResourceScope>(r#"{"tools":{"fs.read":"=1.0.0","fs.read":"*"}}"#)
            .is_err()
    );
    assert!(
        serde_json::from_str::<ResourceScope>(r#"{"models":{"p":["local"],"p":["remote"]}}"#)
            .is_err()
    );
}

#[test]
fn decoded_identifiers_and_components_cannot_bypass_validation() {
    reject::<ToolName>(&[json!("INVALID/TOOL"), json!("fs..read"), json!("")]);
    reject::<SecretRef>(&[json!("bad secret"), json!(""), json!("a\n")]);
    reject::<CanonicalPath>(&[
        json!({"components":["..","etc"],"case_folded":false}),
        json!({"components":["a/b"],"case_folded":false}),
        json!({"components":[""],"case_folded":false}),
        json!({"components":["A"],"case_folded":true}),
    ]);
    reject::<AccountRef>(&[
        json!({"provider":"P","account_id":"a"}),
        json!({"provider":"p","account_id":"a/b"}),
    ]);
    reject::<ModelClass>(&[json!({"provider":"p","class":"local,remote"})]);
    reject::<ResourceScope>(&[
        json!({"tools":{"BAD":"*"}}),
        json!({"secrets":["bad secret"]}),
        json!({"models":{"p":["a,b"]}}),
    ]);
}

#[test]
fn network_normalizes_input_but_rejects_noncanonical_signed_values() {
    assert_eq!(
        HostPattern::parse("192.0.2.7/24").unwrap(),
        HostPattern::parse("192.0.2.0/24").unwrap()
    );
    assert_eq!(
        HostPattern::parse("EXAMPLE.COM.").unwrap(),
        HostPattern::parse("example.com").unwrap()
    );
    assert_eq!(
        NetworkDestination::parse("https://EXAMPLE.COM.:443", &["get"]).unwrap(),
        NetworkDestination::parse("https://example.com", &["GET"]).unwrap()
    );
    for input in [
        "name@evil.example",
        "example.com/path",
        "example.com:443",
        "*.com",
        "-bad.example",
    ] {
        assert!(HostPattern::parse(input).is_err(), "accepted host {input}");
    }
    assert!(NetworkDestination::parse("https://user:password@example.com", &[]).is_err());
    assert!(NetworkDestination::parse("https://example.com", &["GET,POST"]).is_err());
    assert!(
        NetworkDestination::parse_canonical_form("net:https://dnswild:*.com:ports:443").is_err()
    );
    reject::<HostPattern>(&[
        json!({"DnsName":"EXAMPLE.COM"}),
        json!({"DnsName":"127.0.0.1"}),
        json!({"DnsWildcard":"com"}),
        json!({"IpRange":"192.0.2.7/24"}),
    ]);
    reject::<PortSet>(&[
        json!({"ranges":[[443,443]],"any":true}),
        json!({"ranges":[[443,80]],"any":false}),
        json!({"ranges":[[80,80],[81,81]],"any":false}),
    ]);
}

#[cfg(target_os = "linux")]
#[test]
fn actual_symlink_resolution_never_replaces_non_utf8_bytes() {
    use lumen_core::canonical::RealFsResolver;
    use std::{
        ffi::OsString,
        fs,
        os::unix::{
            ffi::OsStringExt,
            fs::{MetadataExt, symlink},
        },
    };
    let root = std::env::temp_dir().join(format!("lumen-scope-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    let bad = root.join(OsString::from_vec(b"name_\xff".to_vec()));
    let replacement = root.join("name_\u{fffd}");
    fs::create_dir(&bad).unwrap();
    fs::create_dir(&replacement).unwrap();
    assert_ne!(
        fs::metadata(&bad).unwrap().ino(),
        fs::metadata(&replacement).unwrap().ino()
    );
    let alias = root.join("alias");
    symlink(&bad, &alias).unwrap();
    assert!(CanonicalPath::parse(alias.to_str().unwrap(), &RealFsResolver, false).is_err());
    assert!(CanonicalPath::parse(replacement.to_str().unwrap(), &RealFsResolver, false).is_ok());
    fs::remove_file(&alias).unwrap();
    symlink(&replacement, &alias).unwrap();
    assert_eq!(
        CanonicalPath::parse(alias.to_str().unwrap(), &RealFsResolver, false).unwrap(),
        CanonicalPath::parse(replacement.to_str().unwrap(), &RealFsResolver, false).unwrap()
    );
}

proptest! {
    #[test]
    fn generated_path_views_have_distinct_encodings(name in "[a-z]{1,24}") {
        let a=path_scope(&format!("/p/{name}~fold"),false);
        let b=path_scope(&format!("/p/{name}"),true);
        prop_assert_ne!(a.canonical_digest().unwrap(),b.canonical_digest().unwrap());
    }
    #[test]
    fn scope_sets_ignore_order_and_identical_duplicates(names in prop::collection::vec("[a-z]{1,12}",1..30)) {
        let mut a=ResourceScope::default();
        for name in names { a.paths.extend(path_scope(&format!("/p/{name}"),false).paths); }
        let mut b=a.clone(); b.paths.reverse(); b.paths.extend(a.paths.clone());
        prop_assert_eq!(a.canonical_digest().unwrap(),b.canonical_digest().unwrap());
        let decoded:ResourceScope=serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        prop_assert_eq!(a.canonical_digest().unwrap(),decoded.canonical_digest().unwrap());
    }
}

#[test]
fn invalid_rust_scope_is_refused_before_nonce_or_budget_mutation() {
    use lumen_core::{
        budget::{Budget, BudgetDimension, BudgetLedger},
        lease::{KernelKeys, LeaseLimits, RootLeaseParams, SessionRegistry, mint_root_lease},
        nonce::NonceStore,
    };
    let keys = KernelKeys::generate();
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let mut sessions = SessionRegistry::new();
    sessions.register("session".into(), None, key.verifying_key(), 0);
    let ledger = BudgetLedger::new();
    let nonces = NonceStore::new();
    let params = |scope| RootLeaseParams {
        lease_id: "lease".into(),
        subject: "session".into(),
        scope,
        limits: LeaseLimits {
            not_before_ms: 0,
            expires_at_ms: 1000,
            budget: Budget::new().set(BudgetDimension::Executions, 2),
            max_executions: Some(2),
            single_use: false,
        },
        depth_limit: 3,
        lease_nonce: "one-nonce".into(),
        issued_at_ms: 10,
    };
    let mut bad = ResourceScope::default();
    bad.tools
        .insert("INVALID/TOOL".into(), "*".parse().unwrap());
    assert!(mint_root_lease(params(bad), &keys, &sessions, &ledger, &nonces, 10).is_err());
    // Reusing both id and nonce succeeds only if the rejected request touched
    // neither replay state nor the budget ledger.
    let valid = path_scope("/workspace", false);
    let minted = mint_root_lease(params(valid), &keys, &sessions, &ledger, &nonces, 10).unwrap();
    minted.verify_signature(&keys.issuer_verifying()).unwrap();
    assert_eq!(minted.protocol_version, 3);
    for version in [0, 1, 2, 4, u32::MAX] {
        let mut wire = serde_json::to_value(&minted).unwrap();
        wire["protocol_version"] = json!(version);
        reject::<lumen_core::lease::LeaseDocument>(&[wire]);
        let mut direct = minted.clone();
        direct.protocol_version = version;
        assert!(direct.verify_signature(&keys.issuer_verifying()).is_err());
        assert!(direct.sign(&key).is_err());
    }
}

#[test]
fn independently_encoded_v2_scope_and_v3_lease_fixtures_are_frozen() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use lumen_core::{
        lease::LeaseDocument,
        pi_boundary::{canonical_digest, canonical_json},
    };
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/resource_scope.v2.json")).unwrap();
    let scope: ResourceScope = serde_json::from_value(fixture["scope"].clone()).unwrap();
    assert_eq!(scope.canonical_value().unwrap(), fixture["canonical"]);
    assert_eq!(scope.canonical_digest().unwrap(), fixture["digest"]);
    for (version, raw) in [
        (2, include_str!("fixtures/lease.legacy-v2.json")),
        (3, include_str!("fixtures/lease.v3.json")),
    ] {
        let fixture: Value = serde_json::from_str(raw).unwrap();
        let mut signing = fixture["document"].clone();
        let sig = signing
            .as_object_mut()
            .unwrap()
            .remove("signature")
            .unwrap();
        let bytes = canonical_json(&signing).unwrap();
        assert_eq!(
            canonical_digest(&signing).unwrap(),
            fixture["signing_digest"]
        );
        let key = VerifyingKey::from_bytes(
            &hex::decode(fixture["test_public_key"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let signature =
            Signature::from_slice(&hex::decode(sig.as_str().unwrap()).unwrap()).unwrap();
        // Both signatures are cryptographically valid. Version rejection is
        // an independent authority check, not a broken-signature accident.
        key.verify(&bytes, &signature).unwrap();
        if version == 2 {
            assert!(serde_json::from_value::<LeaseDocument>(fixture["document"].clone()).is_err());
        } else {
            let doc: LeaseDocument = serde_json::from_value(fixture["document"].clone()).unwrap();
            assert_eq!(doc.signing_bytes().unwrap(), bytes);
            assert_eq!(doc.digest().unwrap(), fixture["signing_digest"]);
            doc.verify_signature(&key).unwrap();
        }
    }
}

#[test]
fn budget_decoding_rejects_duplicate_unknown_and_negative_dimensions() {
    use lumen_core::budget::Budget;
    // Preserve the exact signed representation of legacy explicit zeros.
    let zero: Budget = serde_json::from_str(r#"{"tokens":0}"#).unwrap();
    assert_eq!(serde_json::to_value(zero).unwrap(), json!({"tokens":0}));
    for input in [
        r#"{"executions":1,"executions":100}"#,
        r#"{"future_budget":1}"#,
        r#"{"tokens":-1}"#,
    ] {
        assert!(
            serde_json::from_str::<Budget>(input).is_err(),
            "accepted {input}"
        );
    }
}

proptest! {
    #[test]
    fn explicitly_setting_a_budget_to_zero_removes_previous_authority(amount in 1u64..=u64::MAX) {
        use lumen_core::budget::{Budget,BudgetDimension};
        let budget=Budget::new().set(BudgetDimension::Executions,amount).set(BudgetDimension::Executions,0);
        prop_assert_eq!(budget.get(BudgetDimension::Executions),0);
        prop_assert_eq!(serde_json::to_value(budget).unwrap(),json!({}));
    }
}
