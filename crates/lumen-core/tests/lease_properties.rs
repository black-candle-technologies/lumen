//! Property tests for the six Phase 1 invariants.
//!
//! 1. Child scope is narrower — generated lease trees: no accepted counterexample.
//! 2. Fan-out cannot overspend — concurrent issuance/debit: parent cap holds atomically.
//! 3. Revocation is transitive — random ancestry graphs: all descendants invalid.
//! 4. Canonical forms are unique — path/URL mutation corpus: equivalent inputs hash alike.
//! 5. Replay is rejected — nonce and one-shot reuse: second use has no effect.
//! 6. Audit gaps are visible — delete/reorder/tamper events: verifier reports break.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    io,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use rand::rngs::OsRng;
use semver::{Version, VersionReq};
use serde_json::json;

use lumen_core::canonical::EffectClass;
use lumen_core::pi_boundary::{
    ACTION_ENVELOPE_VERSION, ActionEnvelope, EffectClasses, LeaseId, PathResource,
    PathRights as WirePathRights, ResourceSet, ToolRef,
};
use lumen_core::{
    budget::{Budget, BudgetDimension, BudgetLedger},
    canonical::{
        CanonicalPath, HostPattern, NetworkDestination, PathGrant, PathResolver, PathRights,
        PortSet, ResourceScope,
    },
    kernel_audit::{AuditStore, KernelAuditLog, MemoryAuditStore},
    lease::{
        AuthorizeParams, CanonicalAction, ChildLeaseParams, KernelKeys, LeaseDocument, LeaseError,
        LeaseLimits, OneShotGrant, RevocationIndex, RootLeaseParams, SessionRegistry,
        authorize_envelope, consume_single_use, mint_child_lease, mint_one_shot_lease,
        mint_root_lease, validate_chain,
    },
    nonce::NonceStore,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Fake resolver for integration tests: lexical links + `.`/`..` folding.
#[derive(Default, Clone)]
struct FakeResolver {
    map: HashMap<String, String>,
}

impl FakeResolver {
    fn link(mut self, from: &str, to: &str) -> Self {
        self.map.insert(from.to_string(), to.to_string());
        self
    }
}

impl PathResolver for FakeResolver {
    fn resolve(&self, path: &Path) -> io::Result<PathBuf> {
        let mut cur = path.to_string_lossy().to_string();
        // Longest-prefix link matching on component boundaries, like a real
        // symlink resolver (the exact-path-only version was a harness bug
        // caught by proptest: `/link/a` with `/link` -> `/a` must resolve).
        for _ in 0..16 {
            let mut hit: Option<(&str, &str)> = None;
            for (from, to) in &self.map {
                let matches = cur == *from
                    || cur
                        .strip_prefix(from.as_str())
                        .is_some_and(|rest| rest.starts_with('/'));
                if matches && hit.is_none_or(|(f, _)| from.len() > f.len()) {
                    hit = Some((from, to));
                }
            }
            match hit {
                Some((from, to)) => {
                    let rest = cur.strip_prefix(from).unwrap_or("");
                    cur = format!("{to}{rest}");
                }
                None => break,
            }
        }
        let mut out = PathBuf::new();
        for comp in Path::new(&cur).components() {
            match comp {
                Component::CurDir => {}
                Component::ParentDir => {
                    out.pop();
                }
                _ => out.push(comp.as_os_str()),
            }
        }
        Ok(out)
    }
}

fn test_keys(n: usize) -> (KernelKeys, Vec<SigningKey>) {
    let keys = KernelKeys::generate();
    let sks = (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect();
    (keys, sks)
}

fn test_sessions(sks: &[SigningKey]) -> SessionRegistry {
    let mut reg = SessionRegistry::new();
    for (i, sk) in sks.iter().enumerate() {
        let subject = format!("ed25519:session-{i}");
        let parent = if i == 0 {
            None
        } else {
            Some(format!("ed25519:session-{}", i - 1))
        };
        reg.register(subject, parent, sk.verifying_key());
    }
    reg
}

fn exec_budget(n: u64) -> Budget {
    Budget::new().set(BudgetDimension::Executions, n)
}

// ---------------------------------------------------------------------------
// Strategies: random scopes, narrowings, widenings
// ---------------------------------------------------------------------------

fn arb_segment() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z]{1,6}").unwrap()
}

fn arb_abs_path() -> impl Strategy<Value = String> {
    prop::collection::vec(arb_segment(), 1..4).prop_map(|segs| format!("/{}", segs.join("/")))
}

fn arb_tool_name() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "fs.read".to_string(),
        "fs.write".to_string(),
        "net.fetch".to_string(),
        "exec.run".to_string(),
        "secret.use".to_string(),
    ])
}

fn arb_version() -> impl Strategy<Value = Version> {
    (0u64..3, 0u64..6, 0u64..6).prop_map(|(a, b, c)| Version::new(a, b, c))
}

fn arb_effect() -> impl Strategy<Value = EffectClass> {
    prop::sample::select(vec![
        EffectClass::Read,
        EffectClass::Write,
        EffectClass::Network,
        EffectClass::Execute,
        EffectClass::SecretUse,
        EffectClass::MessageSend,
    ])
}

fn arb_host() -> impl Strategy<Value = HostPattern> {
    prop_oneof![
        prop::sample::select(vec!["example.com", "api.example.com", "internal.local"])
            .prop_map(|h| HostPattern::parse(h).unwrap()),
        prop::sample::select(vec!["example.com", "example.org"])
            .prop_map(|h| HostPattern::parse(&format!("*.{h}")).unwrap()),
        (1u8..254, 0u8..255)
            .prop_map(|(a, b)| HostPattern::parse(&format!("10.{a}.{b}.0/24")).unwrap()),
        (1u8..254).prop_map(|a| HostPattern::parse(&format!("192.168.{a}.10")).unwrap()),
    ]
}

fn arb_portset() -> impl Strategy<Value = PortSet> {
    prop_oneof![
        Just(PortSet::single(443)),
        Just(PortSet::single(80)),
        (1u16..1000, 1001u16..2000).prop_map(|(a, b)| PortSet::range(a.min(b), a.max(b)).unwrap()),
    ]
}

fn arb_destination() -> impl Strategy<Value = NetworkDestination> {
    (
        arb_host(),
        arb_portset(),
        prop::sample::select(vec!["https", "http"]),
    )
        .prop_map(|(host, ports, scheme)| NetworkDestination {
            scheme: scheme.to_string(),
            host,
            ports,
            methods: BTreeSet::new(),
        })
}

#[derive(Clone, Debug)]
struct ScopePair {
    parent: ResourceScope,
    child: ResourceScope,
}

/// Generate a parent scope plus a child built by *narrowing* it.
fn arb_narrowed_pair() -> impl Strategy<Value = ScopePair> {
    (
        prop::collection::vec((arb_tool_name(), arb_version()), 1..4),
        prop::collection::vec(arb_abs_path(), 1..3),
        prop::collection::vec(arb_destination(), 1..3),
        prop::collection::vec(prop::string::string_regex("[a-z]{1,8}").unwrap(), 0..4),
        prop::collection::vec(arb_effect(), 0..4),
        prop::collection::vec(arb_segment(), 0..3),
    )
        .prop_map(|(tools, paths, dests, secrets, effects, subsegs)| {
            let r = FakeResolver::default();
            let mut parent = ResourceScope::default();
            let mut child = ResourceScope::default();
            // Tools: child pins exact versions; parent reqs match them.
            for (name, ver) in &tools {
                child
                    .tools
                    .insert(name.clone(), VersionReq::parse(&format!("={ver}")).unwrap());
                parent.tools.insert(
                    name.clone(),
                    VersionReq::parse(&format!("^{}.{}.{}", ver.major, ver.minor, ver.patch))
                        .unwrap(),
                );
            }
            // Paths: child root is at-or-below the parent root, rights narrow.
            for (i, p) in paths.iter().enumerate() {
                let parent_root = CanonicalPath::parse(p, &r, false).unwrap();
                let child_root = if i < subsegs.len() && !subsegs[i].is_empty() {
                    CanonicalPath::parse(&format!("{}/{}", p, subsegs[i]), &r, false).unwrap()
                } else {
                    parent_root.clone()
                };
                let parent_rights = PathRights {
                    read: true,
                    write: i % 2 == 0,
                };
                let child_rights = PathRights {
                    read: true,
                    write: parent_rights.write && i % 3 == 0,
                };
                parent.paths.push(PathGrant {
                    root: parent_root,
                    rights: parent_rights,
                });
                child.paths.push(PathGrant {
                    root: child_root,
                    rights: child_rights,
                });
            }
            // Destinations: child narrows ports to a single port within the parent set.
            for d in &dests {
                parent.destinations.push(d.clone());
                let port = (1u16..65535).find(|p| d.ports.contains(*p)).unwrap_or(443);
                child.destinations.push(NetworkDestination {
                    scheme: d.scheme.clone(),
                    host: d.host.clone(),
                    ports: PortSet::single(port),
                    methods: BTreeSet::new(),
                });
            }
            // Secrets / effects: subsets.
            let psecrets: BTreeSet<String> = secrets.into_iter().collect();
            parent.secrets = psecrets.clone();
            child.secrets = psecrets.into_iter().step_by(2).collect();
            let mut peffects: Vec<EffectClass> = effects;
            peffects.sort_by_key(|e| format!("{e:?}"));
            peffects.dedup();
            parent.effects = peffects.clone();
            child.effects = peffects.into_iter().step_by(2).collect();
            ScopePair { parent, child }
        })
}

/// Widenings: each takes a narrowed pair and widens the child in exactly one
/// dimension. The subset proof must reject every one.
#[derive(Clone, Copy, Debug)]
enum Widen {
    ExtraTool,
    SiblingPath,
    ParentPath,
    ExtraWrite,
    ExtraSecret,
    ExtraEffect,
    WrongScheme,
    WiderHost,
}

fn arb_widen() -> impl Strategy<Value = Widen> {
    prop::sample::select(vec![
        Widen::ExtraTool,
        Widen::SiblingPath,
        Widen::ParentPath,
        Widen::ExtraWrite,
        Widen::ExtraSecret,
        Widen::ExtraEffect,
        Widen::WrongScheme,
        Widen::WiderHost,
    ])
}

fn apply_widen(pair: &ScopePair, widen: Widen) -> ResourceScope {
    let mut child = pair.child.clone();
    let r = FakeResolver::default();
    match widen {
        Widen::ExtraTool => {
            child
                .tools
                .insert("exec.run".to_string(), VersionReq::parse("=9.9.9").unwrap());
        }
        Widen::SiblingPath => {
            // `/data2` next to a `/data` root: the classic prefix trick.
            child.paths.push(PathGrant {
                root: CanonicalPath::parse("/data2", &r, false).unwrap(),
                rights: PathRights::READ,
            });
        }
        Widen::ParentPath => {
            if let Some(g) = pair.parent.paths.first() {
                let comps = g.root.components();
                let up = if comps.is_empty() {
                    "/".to_string()
                } else {
                    format!("/{}", comps[..comps.len() - 1].join("/"))
                };
                let root = CanonicalPath::parse(&up, &r, false).unwrap();
                child.paths.push(PathGrant {
                    root,
                    rights: PathRights::READ,
                });
            }
        }
        Widen::ExtraWrite => {
            for g in &mut child.paths {
                g.rights.write = true;
            }
            if child.paths.is_empty() {
                child.paths.push(PathGrant {
                    root: CanonicalPath::parse("/workspace", &r, false).unwrap(),
                    rights: PathRights {
                        read: true,
                        write: true,
                    },
                });
            }
        }
        Widen::ExtraSecret => {
            child.secrets.insert("not-granted-secret".to_string());
        }
        Widen::ExtraEffect => {
            for e in [
                EffectClass::Read,
                EffectClass::Write,
                EffectClass::Network,
                EffectClass::Execute,
                EffectClass::SecretUse,
                EffectClass::MessageSend,
            ] {
                if !pair.parent.effects.contains(&e) {
                    child.effects.push(e);
                    break;
                }
            }
        }
        Widen::WrongScheme => {
            // Scheme is part of the canonical destination: `ftp` can never be
            // covered by an http/https parent grant.
            for d in &mut child.destinations {
                d.scheme = "ftp".to_string();
            }
            if child.destinations.is_empty() {
                child.destinations.push(NetworkDestination {
                    scheme: "ftp".to_string(),
                    host: HostPattern::parse("example.com").unwrap(),
                    ports: PortSet::single(21),
                    methods: BTreeSet::new(),
                });
            }
        }
        Widen::WiderHost => {
            for d in &mut child.destinations {
                d.host = HostPattern::parse("10.0.0.0/8").unwrap();
            }
            if child.destinations.is_empty() {
                child.destinations.push(NetworkDestination {
                    scheme: "https".to_string(),
                    host: HostPattern::parse("10.0.0.0/8").unwrap(),
                    ports: PortSet::single(443),
                    methods: BTreeSet::new(),
                });
            }
        }
    }
    child
}

/// Conservative check: did this widening fail to actually widen (e.g. the
/// parent already granted the "wider" thing)? Such cases are skipped — a skip
/// is safe, a false accept is not.
fn widen_covers_parent(pair: &ScopePair, widen: Widen) -> bool {
    match widen {
        Widen::ExtraTool => pair.parent.tools.contains_key("exec.run"),
        Widen::ExtraWrite => pair.parent.paths.iter().any(|g| g.rights.write),
        Widen::ExtraEffect => [
            EffectClass::Read,
            EffectClass::Write,
            EffectClass::Network,
            EffectClass::Execute,
            EffectClass::SecretUse,
            EffectClass::MessageSend,
        ]
        .iter()
        .all(|e| pair.parent.effects.contains(e)),
        Widen::SiblingPath => pair
            .parent
            .paths
            .iter()
            .any(|g| g.root.canonical_form() == "/data2"),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Invariant 1: child scope is narrower — no accepted counterexample
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn narrowed_child_always_accepted(pair in arb_narrowed_pair()) {
        prop_assert!(pair.child.is_subset_of(&pair.parent).is_ok(),
            "narrowed child rejected: {:?}", pair);
    }

    #[test]
    fn widened_child_always_rejected(pair in arb_narrowed_pair(), widen in arb_widen()) {
        let child = apply_widen(&pair, widen);
        if widen_covers_parent(&pair, widen) {
            return Ok(());
        }
        let accepted = child.is_subset_of(&pair.parent).is_ok();
        prop_assert!(!accepted, "widened child {:?} accepted: {:?}", widen, pair);
    }
}

// ---------------------------------------------------------------------------
// Invariant 2: fan-out cannot overspend (concurrent issuance/debit)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn fanout_cannot_overspend(
        cap in 100u64..10_000,
        children in prop::collection::vec((1u64..500, 0u64..500), 2..12),
    ) {
        let ledger = Arc::new(BudgetLedger::new());
        let caps = Budget::new()
            .set(BudgetDimension::SpendMicros, cap)
            .set(BudgetDimension::Tokens, cap);
        ledger.register_lease("parent", &caps).unwrap();

        // Each child: (max_reserve, debit_attempt), hammered from threads.
        let handles: Vec<_> = children.into_iter().enumerate().map(|(i, (max, debit))| {
            let ledger = Arc::clone(&ledger);
            std::thread::spawn(move || {
                let child_id = format!("child-{i}");
                let want = Budget::new()
                    .set(BudgetDimension::SpendMicros, max)
                    .set(BudgetDimension::Tokens, max);
                let Ok(res) = ledger.reserve("parent", &child_id, &want, 1) else {
                    return; // reservation refused: fine, cap held
                };
                let actual = Budget::new()
                    .set(BudgetDimension::SpendMicros, debit.min(max))
                    .set(BudgetDimension::Tokens, debit.min(max));
                let _ = ledger.debit(&res.id, &actual, &format!("key-{i}"), 2);
            })
        }).collect();
        for h in handles { h.join().unwrap(); }

        // The parent cap holds atomically, in every dimension.
        ledger.check_invariants().unwrap();
        let (cap_b, reserved_out, exec_held, consumed) = ledger.account_summary("parent").unwrap();
        let remaining = ledger.remaining("parent").unwrap();
        for dim in [BudgetDimension::SpendMicros, BudgetDimension::Tokens] {
            prop_assert_eq!(cap_b.get(dim), cap);
            // Conservation: every micro is accounted for.
            let total = remaining.get(dim)
                .checked_add(reserved_out.get(dim)).unwrap()
                .checked_add(exec_held.get(dim)).unwrap()
                .checked_add(consumed.get(dim)).unwrap();
            prop_assert_eq!(total, cap, "budget not conserved");
        }
    }
}

// ---------------------------------------------------------------------------
// Invariant 3: revocation is transitive (random ancestry graphs)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn revocation_is_transitive(
        shape in prop::collection::vec(0usize..4, 1..8),
        revoke_at in 0usize..8,
    ) {
        // shape[i] = raw index of node (i+1)'s parent; node 0 is always a root.
        let n = shape.len() + 1;
        let (keys, sks) = test_keys(n);
        let sessions = test_sessions(&sks);
        let ledger = BudgetLedger::new();
        let nonces = NonceStore::new();
        let r = FakeResolver::default();

        // Budgets sized by subtree: the reservation model requires
        // budget(parent) >= sum(budget(children)), so each node's cap is
        // 100 executions times its subtree size (children always have
        // higher indices than their parents, so reverse order accumulates).
        let mut parent_of = vec![0usize; n];
        for (i, raw) in shape.iter().enumerate() {
            parent_of[i + 1] = raw % (i + 1);
        }
        let mut subtree = vec![1usize; n];
        for j in (1..n).rev() {
            let p = parent_of[j];
            subtree[p] += subtree[j];
        }
        let budget_for = |i: usize| exec_budget(100 * subtree[i] as u64);

        // One shared scope so minting never fails on subset.
        let mut scope = ResourceScope::default();
        scope.tools.insert("fs.read".to_string(), VersionReq::parse("=1.0.0").unwrap());
        scope.paths.push(PathGrant {
            root: CanonicalPath::parse("/workspace", &r, false).unwrap(),
            rights: PathRights::READ,
        });
        scope.effects.push(EffectClass::Read);

        let mut docs: Vec<LeaseDocument> = Vec::new();
        let root = mint_root_lease(
            RootLeaseParams {
                lease_id: "lease-0".to_string(),
                subject: "ed25519:session-0".to_string(),
                scope: scope.clone(),
                limits: LeaseLimits {
                    not_before_ms: 0, expires_at_ms: 1_000_000,
                    budget: budget_for(0), max_executions: None, single_use: false,
                },
                depth_limit: 16,
                lease_nonce: "root-nonce".to_string(),
                issued_at_ms: 1,
            },
            &keys, &sessions, &ledger, &nonces, 1,
        ).unwrap();
        docs.push(root);
        for (i, _parent_raw) in shape.iter().enumerate() {
            let idx = i + 1;
            let parent_idx = parent_of[idx]; // always a valid earlier node
            let parent = docs[parent_idx].clone();
            let child = mint_child_lease(
                &parent,
                ChildLeaseParams {
                    lease_id: format!("lease-{idx}"),
                    subject: format!("ed25519:session-{idx}"),
                    scope: scope.clone(),
                    limits: LeaseLimits {
                        not_before_ms: 0, expires_at_ms: 1_000_000,
                        budget: budget_for(idx), max_executions: None, single_use: false,
                    },
                    depth_limit: 16,
                    lease_nonce: format!("nonce-{idx}"),
                    issued_at_ms: 2,
                },
                &sks[parent_idx],
                &sessions, &RevocationIndex::new(), &ledger, &nonces, 2,
            ).unwrap();
            docs.push(child);
        }

        let mut map = HashMap::new();
        for d in &docs { map.insert(d.lease_id.clone(), d.clone()); }
        let revoke_idx = revoke_at % n;
        let mut revocations = RevocationIndex::new();
        revocations.revoke(&format!("lease-{revoke_idx}"));

        // Descendants of the revoked node (including itself) are invalid;
        // every other node still validates.
        for (i, doc) in docs.iter().enumerate() {
            let mut chain_ids = vec![doc.lease_id.clone()];
            let mut cur = doc.lease_id.clone();
            while let Some(p) = map.get(&cur).and_then(|d| d.parent_id.clone()) {
                chain_ids.push(p.clone());
                cur = p;
            }
            let one_shot = HashSet::new();
            let result = validate_chain(&map, &chain_ids, &revocations, &sessions, &keys, &one_shot, 10);
            let mut cur_idx = i;
            let mut is_descendant = false;
            loop {
                if cur_idx == revoke_idx { is_descendant = true; break; }
                if cur_idx == 0 { break; }
                cur_idx = shape[cur_idx - 1] % cur_idx;
            }
            if is_descendant {
                prop_assert!(result.is_err(), "revoked descendant lease-{} still valid", i);
            } else {
                prop_assert!(result.is_ok(), "unrelated lease-{} invalidated: {:?}", i, result);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Invariant 4: canonical forms are unique (path/URL mutation corpus)
// ---------------------------------------------------------------------------

fn arb_path_mutation() -> impl Strategy<Value = (String, String, bool)> {
    // (input_a, input_b, equivalent?)
    prop_oneof![
        // trailing slash, dot segments: equivalent
        arb_abs_path().prop_map(|p| (p.clone(), format!("{p}/"), true)),
        (arb_abs_path(), arb_segment()).prop_map(|(p, s)| (
            p.clone(),
            format!("{p}/./{s}/../"),
            true
        )),
        // sibling with shared prefix: NOT equivalent (the prefix trick)
        arb_abs_path().prop_map(|p| (p.clone(), format!("{p}2"), false)),
        // parent dir: NOT equivalent
        prop::collection::vec(arb_segment(), 2..4).prop_map(|segs| {
            let full = format!("/{}", segs.join("/"));
            let parent = format!("/{}", segs[..segs.len() - 1].join("/"));
            (full, parent, false)
        }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn canonical_paths_unique((a, b, equivalent) in arb_path_mutation()) {
        let r = FakeResolver::default();
        let ca = CanonicalPath::parse(&a, &r, false).unwrap();
        let cb = CanonicalPath::parse(&b, &r, false).unwrap();
        prop_assert_eq!(ca.canonical_form() == cb.canonical_form(), equivalent,
            "a={} b={}", a, b);
        // Digest-level uniqueness too.
        let mut sa = ResourceScope::default();
        sa.paths.push(PathGrant { root: ca, rights: PathRights::READ });
        let mut sb = ResourceScope::default();
        sb.paths.push(PathGrant { root: cb, rights: PathRights::READ });
        prop_assert_eq!(
            sa.canonical_digest().unwrap() == sb.canonical_digest().unwrap(),
            equivalent,
        );
    }

    #[test]
    fn canonical_urls_unique(
        host in prop::sample::select(vec!["Example.COM", "example.com", "EXAMPLE.com."]),
        port in prop::sample::select(vec![None, Some(443), Some(8443)]),
    ) {
        // Case, trailing dot, and default-port variants are equivalent.
        let expected = !matches!(port, Some(8443));
        let url_b = match port {
            None => format!("https://{host}/x"),
            Some(p) => format!("https://{host}:{p}/x"),
        };
        let a = NetworkDestination::parse("https://example.com/x", &[]).unwrap();
        let b = NetworkDestination::parse(&url_b, &[]).unwrap();
        prop_assert_eq!(a.canonical_form() == b.canonical_form(), expected,
            "a=https://example.com/x b={}", url_b);
    }

    #[test]
    fn symlink_aliases_converge(target in arb_abs_path(), alias in arb_segment()) {
        // `/link/x` and `/real/x` converge when link → real.
        let r = FakeResolver::default().link("/link", &target);
        let via_link = CanonicalPath::parse(&format!("/link/{alias}"), &r, false).unwrap();
        let direct = CanonicalPath::parse(&format!("{target}/{alias}"), &r, false).unwrap();
        prop_assert_eq!(via_link, direct);
    }
}

// ---------------------------------------------------------------------------
// Invariant 5: replay is rejected
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn nonce_reuse_rejected(nonce in prop::string::string_regex("[a-z0-9]{4,16}").unwrap()) {
        let store = NonceStore::new();
        prop_assert!(store.check_and_insert(&nonce, 1000, 60_000).is_ok());
        prop_assert!(store.check_and_insert(&nonce, 2000, 60_000).is_err());
    }

    #[test]
    fn one_shot_second_use_has_no_effect(
        tool in arb_tool_name(),
        ver in arb_version(),
        path in arb_abs_path(),
    ) {
        let (keys, sks) = test_keys(1);
        let mut sessions = SessionRegistry::new();
        sessions.register("ed25519:session-0".to_string(), None, sks[0].verifying_key());
        let ledger = BudgetLedger::new();
        let nonces = NonceStore::new();
        let r = FakeResolver::default();

        let env = ActionEnvelope {
            version: ACTION_ENVELOPE_VERSION,
            action_id: "550e8400-e29b-41d4-a716-446655440000".parse().unwrap(),
            session_id: "ed25519:session-0".to_string(),
            tool: ToolRef { name: tool.clone(), version: ver.to_string() },
            // The frozen contract requires integer-only arguments.
            arguments: [("n".to_string(), json!(1))].into_iter().collect(),
            inputs: vec![],
            resources: ResourceSet {
                paths: vec![PathResource {
                    path: path.clone(),
                    rights: WirePathRights::Read,
                }],
                network: vec![],
                secrets: vec![],
            },
            expected_effects: EffectClasses {
                file_read: true,
                file_write: false,
                network_egress: false,
                network_ingress: false,
                process_spawn: false,
            },
            lease_chain: vec![],
            nonce: "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(),
            expires_at_ms: 1_000_000,
        };
        let action = CanonicalAction::from_envelope(&env, &r, false).unwrap();
        let vhl = SigningKey::generate(&mut OsRng);
        let mut grant = OneShotGrant {
            approval_id: "appr-1".to_string(),
            action_digest: action.digest.clone(),
            session_subject: "ed25519:session-0".to_string(),
            signer_key_id: "vhl-human".to_string(),
            nonce: "grant-nonce".to_string(),
            created_at_ms: 100,
            expires_at_ms: 100_000,
            signature: String::new(),
        };
        grant.sign(&vhl);
        let lease = mint_one_shot_lease(
            &grant, &vhl.verifying_key(), &action,
            &keys, &sessions, &ledger, &nonces, 200,
        ).unwrap();

        // Consuming twice: the second has no effect.
        let mut tracker: HashSet<String> = HashSet::new();
        prop_assert!(consume_single_use(&lease, &mut tracker, 300).is_ok());
        prop_assert!(matches!(
            consume_single_use(&lease, &mut tracker, 400),
            Err(LeaseError::AlreadyConsumed(_))
        ));

        // Authorizing the same envelope twice: the second is denied
        // (one-shot consumed AND envelope nonce replayed).
        let mut map = HashMap::new();
        map.insert(lease.lease_id.clone(), lease.clone());
        let mut env2 = env.clone();
        env2.lease_chain = vec![LeaseId::from_uuid(lease.lease_id.parse().expect("lease id is a UUID"))];
        let mut tracker2: HashSet<String> = HashSet::new();
        let params = AuthorizeParams {
            now_ms: 500, case_insensitive_fs: false,
            allow_approval_fallback: false, approval_ttl_ms: 60_000,
        };
        let mut outbox: Vec<lumen_core::lease::VhlRequest> = vec![];
        let d1 = authorize_envelope(
            &env2, &r, &map, &RevocationIndex::new(), &sessions, &keys,
            &mut tracker2, &nonces, &ledger, &mut outbox, &params,
        );
        prop_assert!(d1.is_allow(), "first use denied: {:?}", d1);
        let d2 = authorize_envelope(
            &env2, &r, &map, &RevocationIndex::new(), &sessions, &keys,
            &mut tracker2, &nonces, &ledger, &mut outbox, &params,
        );
        prop_assert!(!d2.is_allow(), "replay allowed!");
    }
}

// ---------------------------------------------------------------------------
// Invariant 6: audit gaps are visible
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Tamper {
    DeleteOne,
    SwapTwo,
    FlipDecision,
    DropCheckpoint,
    ForgeCheckpoint,
}

fn arb_tamper() -> impl Strategy<Value = Tamper> {
    prop::sample::select(vec![
        Tamper::DeleteOne,
        Tamper::SwapTwo,
        Tamper::FlipDecision,
        Tamper::DropCheckpoint,
        Tamper::ForgeCheckpoint,
    ])
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn audit_gaps_visible(
        count in 2usize..8,
        tamper in arb_tamper(),
        redact_note in prop::string::string_regex("[a-z]{0,12}").unwrap(),
    ) {
        use lumen_core::kernel_audit::GENESIS_PREV_HASH;
        use lumen_core::pi_boundary::AuditEventKind;
        let keys = KernelKeys::generate();
        let mut log = KernelAuditLog::new(MemoryAuditStore::default());
        // 64-hex action digests (the frozen contract's digest shape).
        let digest = |i: usize| format!("{:064x}", i + 1);
        for i in 0..count {
            let allowed = i % 2 == 0;
            log.append(
                "kernel",
                if allowed { AuditEventKind::PolicyAllowed } else { AuditEventKind::PolicyDenied },
                "ed25519:session-0",
                &digest(i),
                Some(if allowed { "allow" } else { "deny" }),
                1000 + i as i64,
                json!({"lease_id": format!("lease-{i}"), "api_key": redact_note.clone()}),
            ).unwrap();
        }
        // The genesis event links to the frozen genesis prev_hash.
        prop_assert_eq!(log.store().events()[0].prev_hash.as_str(), GENESIS_PREV_HASH);
        log.checkpoint((count - 1) as u64, &keys).unwrap();
        // Untouched, everything verifies.
        log.verify(&keys.host_verifying(), &keys.host_key_id).unwrap();

        // Apply one tamper; verification must report the break.
        let mut events: Vec<_> = log.store().events().to_vec();
        let mut checkpoints: Vec<_> = log.store().checkpoints().to_vec();
        match tamper {
            Tamper::DeleteOne => { events.remove(0); }
            Tamper::SwapTwo => { events.swap(0, 1); }
            Tamper::FlipDecision => {
                events[0].decision = Some(if events[0].decision.as_deref() == Some("allow") {
                    "deny".to_string()
                } else {
                    "allow".to_string()
                });
            }
            Tamper::DropCheckpoint => { checkpoints.clear(); }
            Tamper::ForgeCheckpoint => {
                let other = KernelKeys::generate();
                let mut forged_store = MemoryAuditStore::default();
                for e in &events { forged_store.append_event(e.clone()); }
                let mut forged_log = KernelAuditLog::new(forged_store);
                checkpoints = vec![forged_log.checkpoint(0, &other).unwrap()];
            }
        }
        let mut store = MemoryAuditStore::default();
        for e in events { store.append_event(e); }
        for c in checkpoints { store.checkpoint(c); }
        let tampered = KernelAuditLog::new(store);
        let result = tampered.verify(&keys.host_verifying(), &keys.host_key_id);
        match tamper {
            Tamper::DropCheckpoint => {
                // Chain verifies; absence of a checkpoint is itself visible
                // to anyone watching checkpoint cadence.
                prop_assert!(result.is_ok());
                prop_assert!(tampered.store().checkpoints().is_empty());
            }
            _ => prop_assert!(result.is_err(), "tamper {:?} not detected", tamper),
        }

        // Redaction held for every event: the secret value must appear only
        // as the redaction marker, never as its own JSON string value.
        for e in tampered.store().events() {
            let s = e.detail.clone();
            let quoted = format!("\"{}\"", redact_note);
            prop_assert!(redact_note.is_empty() || !s.contains(&quoted),
                "secret leaked into audit: {}", s);
            if !redact_note.is_empty() {
                prop_assert!(s.contains("[REDACTED]"), "redaction marker missing: {}", s);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Invariant 1b: end-to-end mint acceptance ⟺ subset proof (model agreement)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Minting a child must accept exactly when the subset proof accepts:
    /// `mint_child_lease` succeeds ⟺ `child.is_subset_of(&parent).is_ok()`.
    /// Any divergence is a counterexample.
    #[test]
    fn mint_agrees_with_subset_proof(pair in arb_narrowed_pair(), widen in arb_widen()) {
        let (keys, sks) = test_keys(2);
        let sessions = test_sessions(&sks);
        let ledger = BudgetLedger::new();
        let nonces = NonceStore::new();

        let root = mint_root_lease(
            RootLeaseParams {
                lease_id: "lease-root".to_string(),
                subject: "ed25519:session-0".to_string(),
                scope: pair.parent.clone(),
                limits: LeaseLimits {
                    not_before_ms: 0, expires_at_ms: 1_000_000,
                    budget: Budget::new()
                        .set(BudgetDimension::Executions, 1000)
                        .set(BudgetDimension::SpendMicros, 1_000_000)
                        .set(BudgetDimension::Tokens, 1_000_000),
                    max_executions: None, single_use: false,
                },
                depth_limit: 8,
                lease_nonce: "root-nonce-x".to_string(),
                issued_at_ms: 1,
            },
            &keys, &sessions, &ledger, &nonces, 1,
        ).unwrap();

        // Narrowed child: both must accept.
        let narrowed = mint_child_lease(
            &root,
            ChildLeaseParams {
                lease_id: "lease-child-ok".to_string(),
                subject: "ed25519:session-1".to_string(),
                scope: pair.child.clone(),
                limits: LeaseLimits {
                    not_before_ms: 0, expires_at_ms: 500_000,
                    budget: exec_budget(10), max_executions: None, single_use: false,
                },
                depth_limit: 8,
                lease_nonce: "child-nonce-ok".to_string(),
                issued_at_ms: 2,
            },
            &sks[0], &sessions, &RevocationIndex::new(), &ledger, &nonces, 2,
        );
        prop_assert_eq!(
            narrowed.is_ok(),
            pair.child.is_subset_of(&pair.parent).is_ok(),
            "mint/subset divergence on narrowed child"
        );

        // Widened child: both must reject (unless the widening didn't widen).
        if widen_covers_parent(&pair, widen) {
            return Ok(());
        }
        let widened_scope = apply_widen(&pair, widen);
        let widened = mint_child_lease(
            &root,
            ChildLeaseParams {
                lease_id: "lease-child-wide".to_string(),
                subject: "ed25519:session-1".to_string(),
                scope: widened_scope.clone(),
                limits: LeaseLimits {
                    not_before_ms: 0, expires_at_ms: 500_000,
                    budget: exec_budget(10), max_executions: None, single_use: false,
                },
                depth_limit: 8,
                lease_nonce: "child-nonce-wide".to_string(),
                issued_at_ms: 2,
            },
            &sks[0], &sessions, &RevocationIndex::new(), &ledger, &nonces, 2,
        );
        prop_assert_eq!(
            widened.is_ok(),
            widened_scope.is_subset_of(&pair.parent).is_ok(),
            "mint/subset divergence on widened child {:?}",
            widen
        );
        prop_assert!(widened.is_err(), "widened child {:?} minted!", widen);
    }
}
