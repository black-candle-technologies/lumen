//! Phase 4 human-authority fail-closed tests.
//!
//! Every test drives the real phase-1 lease engine (`mint_one_shot_lease`,
//! `validate_chain`) — no mocks of the authority path. Each attack case
//! asserts the action stays blocked: no lease minted, no second effect, no
//! silent widening.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use rand::rngs::OsRng;
use serde_json::json;
use sha2::{Digest as _, Sha256};

use lumen_core::budget::{Budget, BudgetDimension, BudgetLedger};
use lumen_core::canonical::EffectClass;
use lumen_core::canonical::PathResolver;
use lumen_core::canonical::{HostPattern, PathRights as CanonicalPathRights};
use lumen_core::kernel_audit::{KernelAuditLog, MemoryAuditStore};
use lumen_core::lease::{
    CanonicalAction, KernelKeys, LeaseDocument, LeaseError, LeaseLimits, OneShotGrant,
    RevocationIndex, RootLeaseParams, SessionRegistry, mint_root_lease, validate_chain,
};
use lumen_core::nonce::NonceStore;
use lumen_core::pi_boundary::ACTION_ENVELOPE_VERSION;
use lumen_core::pi_boundary::{ActionEnvelope, ResourceSet, ToolRef};
use lumen_core::session_identity::SessionIdentityVault;
use lumen_core::vhl::{
    Attestation, AttestationProof, CourierVhlVerifier, Fido2Credential, Fido2RpConfig, ProofKind,
    SessionToken, StandingLeaseConfirmation, VhlApprovalRequest, VhlAuditSink, VhlAuthority,
    VhlError, VhlRequestState, attestation_signing_bytes, body_hash,
};
use std::collections::BTreeMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const NOW_MS: i64 = 1_780_000_000_000;
const APPROVAL_TTL_MS: i64 = 300_000;
const HUMAN_ADDRESS: &str = "ed25519:human-test-approver-key";
const RP_ID: &str = "lumen.test";
const RP_ORIGIN: &str = "https://lumen.test";

/// Lexical path resolver for tests: canonical paths resolve to themselves.
struct TestResolver;

impl PathResolver for TestResolver {
    fn resolve(&self, path: &Path) -> std::io::Result<PathBuf> {
        let mut out = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Prefix(prefix) => out.push(prefix.as_os_str()),
                Component::RootDir => out.push("/"),
                Component::CurDir => {}
                Component::ParentDir => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "parent component in canonical path",
                    ));
                }
                Component::Normal(part) => out.push(part),
            }
        }
        Ok(out)
    }
}

fn envelope(
    session_subject: &str,
    arguments: serde_json::Value,
    input_hashes: Vec<String>,
) -> ActionEnvelope {
    use lumen_core::pi_boundary::{EffectClasses, InputRef, PathResource, PathRights};
    let arguments: BTreeMap<String, serde_json::Value> =
        serde_json::from_value(arguments).unwrap_or_default();
    ActionEnvelope {
        version: ACTION_ENVELOPE_VERSION,
        action_id: Uuid::new_v4(),
        session_id: session_subject.to_string(),
        tool: ToolRef {
            name: "fs.read".to_string(),
            version: "1.0.0".to_string(),
        },
        arguments,
        inputs: input_hashes
            .into_iter()
            .map(|content_hash| InputRef {
                content_hash,
                snapshot_id: None,
            })
            .collect(),
        resources: ResourceSet {
            paths: vec![PathResource {
                path: "/workspace/README.md".to_string(),
                rights: PathRights::Read,
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
        nonce: format!("test-nonce-{}", Uuid::new_v4()),
        expires_at_ms: NOW_MS + 600_000,
    }
}

fn canonical_action(env: &ActionEnvelope) -> CanonicalAction {
    CanonicalAction::from_envelope(env, &TestResolver, false).expect("valid test action")
}

#[derive(Default)]
struct RecordingAudit {
    events: Vec<(String, String, String, String, serde_json::Value, i64)>,
}

impl lumen_core::vhl::VhlAuditSink for RecordingAudit {
    fn record_vhl(
        &mut self,
        actor: &str,
        session_id: &str,
        action_digest: &str,
        decision: &str,
        details: serde_json::Value,
        now_ms: i64,
    ) -> Result<(), VhlError> {
        self.events.push((
            actor.to_string(),
            session_id.to_string(),
            action_digest.to_string(),
            decision.to_string(),
            details,
            now_ms,
        ));
        Ok(())
    }
}

struct Harness {
    vault: SessionIdentityVault,
    sessions: SessionRegistry,
    ledger: BudgetLedger,
    nonces: NonceStore,
    keys: KernelKeys,
    revocations: RevocationIndex,
    authority: VhlAuthority<CourierVhlVerifier>,
    audit: RecordingAudit,
    human_key: SigningKey,
    session_subject: String,
}

impl Harness {
    fn new() -> Self {
        let mut vault = SessionIdentityVault::new();
        let mut sessions = SessionRegistry::new();
        let receipt = vault
            .start_session(&mut sessions, None, NOW_MS)
            .expect("session starts");
        let human_key = SigningKey::generate(&mut OsRng);
        let mut verifier = CourierVhlVerifier::new(Fido2RpConfig {
            id: RP_ID.to_string(),
            origins: vec![RP_ORIGIN.to_string()],
        });
        verifier.enroll_approver(HUMAN_ADDRESS, vec![human_key.verifying_key()]);
        Self {
            vault,
            sessions,
            ledger: BudgetLedger::new(),
            nonces: NonceStore::new(),
            keys: KernelKeys::generate(),
            revocations: RevocationIndex::new(),
            authority: VhlAuthority::new(verifier),
            audit: RecordingAudit::default(),
            human_key,
            session_subject: receipt.subject,
        }
    }

    /// Run the full challenge ceremony for `action_digest`.
    fn complete_ceremony(&mut self, action_digest: &str) -> String {
        let (challenge_id, code) = self
            .authority
            .challenges_mut()
            .mint(action_digest, APPROVAL_TTL_MS, NOW_MS)
            .expect("challenge mints");
        self.authority
            .challenges_mut()
            .submit_code(&challenge_id, &code, NOW_MS)
            .expect("ceremony completes");
        challenge_id
    }

    /// Build a valid Tier-2 challenge attestation for `request`, as the
    /// human's device would.
    fn attestation_for(&self, request: &VhlApprovalRequest, challenge_id: &str) -> Attestation {
        let body = request.render_body().expect("body renders");
        let mut att = Attestation {
            version: 2,
            id: URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes()),
            tier: 2,
            msg_hash: URL_SAFE_NO_PAD.encode(body_hash(&body)),
            approver: HUMAN_ADDRESS.to_string(),
            issued_at: NOW_MS / 1000,
            expires_at: NOW_MS / 1000 + 300,
            proof: AttestationProof {
                kind: ProofKind::Challenge,
                strength: "challenge".to_string(),
                token: None,
                credential_id: None,
                assertion: None,
                challenge_id: Some(challenge_id.to_string()),
            },
            request_id: request.request_id.clone(),
            sig: String::new(),
        };
        let bytes = attestation_signing_bytes(&att).expect("signing bytes");
        att.sig = URL_SAFE_NO_PAD.encode(self.human_key.sign(&bytes).to_bytes());
        att
    }

    /// Open → ceremony → attestation → decide. Returns the approved request.
    fn approved_request(&mut self, env: &ActionEnvelope) -> VhlApprovalRequest {
        let action = canonical_action(env);
        let mut request = self
            .authority
            .open_request(&action, env, APPROVAL_TTL_MS, NOW_MS)
            .expect("request opens");
        let challenge_id = self.complete_ceremony(&request.action_digest);
        let attestation = self.attestation_for(&request, &challenge_id);
        self.authority
            .decide(&mut request, &attestation, &mut self.audit, NOW_MS)
            .expect("decision verifies");
        request
    }

    /// The human-signed one-shot grant matching an approved request.
    fn grant_for(&self, request: &VhlApprovalRequest) -> OneShotGrant {
        let mut grant = OneShotGrant {
            approval_id: request.request_id.clone(),
            action_digest: request.action_digest.clone(),
            session_subject: request.session_subject.clone(),
            signer_key_id: HUMAN_ADDRESS.to_string(),
            nonce: request.nonce.clone(),
            created_at_ms: NOW_MS,
            expires_at_ms: NOW_MS + APPROVAL_TTL_MS,
            signature: String::new(),
        };
        grant.sign(&self.human_key);
        grant
    }

    fn mint_lease(
        &mut self,
        request: &mut VhlApprovalRequest,
        grant: &OneShotGrant,
        env: &ActionEnvelope,
    ) -> Result<LeaseDocument, VhlError> {
        // Split borrows: the authority needs &self while request is &mut.
        let Harness {
            authority,
            keys,
            sessions,
            ledger,
            nonces,
            audit,
            ..
        } = self;
        let action = canonical_action(env);
        authority.mint_one_shot(
            request, grant, &action, keys, sessions, ledger, nonces, audit, NOW_MS,
        )
    }
}

// ---------------------------------------------------------------------------
// Happy path: approve once → single-use lease for the exact action
// ---------------------------------------------------------------------------

#[test]
fn approve_once_mints_single_use_lease_for_exact_action() {
    let mut h = Harness::new();
    let env = envelope(
        &h.session_subject.clone(),
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let mut request = h.approved_request(&env);
    assert!(matches!(request.state, VhlRequestState::Approved { .. }));

    let grant = h.grant_for(&request);
    let lease = h
        .mint_lease(&mut request, &grant, &env)
        .expect("lease mints");
    assert!(lease.limits.single_use);
    assert_eq!(lease.subject, h.session_subject);
    assert_eq!(lease.limits.max_executions, Some(1));
    assert!(matches!(request.state, VhlRequestState::Minted { .. }));

    // The approval view the human saw binds the exact action and session.
    assert_eq!(request.view.action_digest, request.action_digest);
    assert_eq!(request.view.session_subject, h.session_subject);
    assert_eq!(
        request.view.input_hashes,
        vec!["sha256:input-1".to_string()]
    );

    // Consuming completes the lifecycle; a second consume fails closed.
    h.authority
        .note_consumed(&mut request, &mut h.audit, NOW_MS)
        .expect("consume records");
    assert!(matches!(request.state, VhlRequestState::Consumed { .. }));
    let again = h
        .authority
        .note_consumed(&mut request, &mut h.audit, NOW_MS);
    assert!(matches!(again, Err(VhlError::IllegalTransition(_))));

    // The audit trail saw granted → minted → consumed, in order.
    let decisions: Vec<&str> = h.audit.events.iter().map(|e| e.3.as_str()).collect();
    assert_eq!(
        decisions,
        vec!["approval.granted", "approval.minted", "approval.consumed"]
    );
}

#[test]
fn consume_audit_failure_leaves_request_minted() {
    let mut h = Harness::new();
    let env = envelope(
        &h.session_subject.clone(),
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let mut request = h.approved_request(&env);
    let grant = h.grant_for(&request);
    h.mint_lease(&mut request, &grant, &env)
        .expect("lease mints");
    assert!(matches!(request.state, VhlRequestState::Minted { .. }));

    // A failed audit append must not advance the request: it stays Minted
    // (retryable) instead of becoming Consumed with no audit event.
    let mut failing = FailingAudit;
    let err = h
        .authority
        .note_consumed(&mut request, &mut failing, NOW_MS)
        .expect_err("audit failure must fail the consume");
    assert!(matches!(err, VhlError::Encoding(_)), "got {err:?}");
    assert!(
        matches!(request.state, VhlRequestState::Minted { .. }),
        "failed consume must not advance the request"
    );

    // Retry with a working audit completes the lifecycle.
    h.authority
        .note_consumed(&mut request, &mut h.audit, NOW_MS)
        .expect("retry records");
    assert!(matches!(request.state, VhlRequestState::Consumed { .. }));
}

// ---------------------------------------------------------------------------
// Argument mutation: the approved action is exactly what was reviewed
// ---------------------------------------------------------------------------

#[test]
fn argument_mutation_fails_closed_at_mint() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let mut request = h.approved_request(&env);
    let grant = h.grant_for(&request);

    // Attacker swaps the action presented at mint time: same shape, different
    // argument → different digest. The grant no longer matches.
    let mutated_env = envelope(
        &subject,
        json!({"path": "/workspace/SECRETS.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let err = h
        .mint_lease(&mut request, &grant, &mutated_env)
        .expect_err("mutated action must not mint");
    assert!(matches!(err, VhlError::DigestMismatch), "got {err:?}");
    // The request is untouched: still approved, still mintable for the real action.
    assert!(matches!(request.state, VhlRequestState::Approved { .. }));
}

#[test]
fn argument_mutation_fails_closed_at_decide() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let action = canonical_action(&env);
    let request = h
        .authority
        .open_request(&action, &env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");
    let challenge_id = h.complete_ceremony(&request.action_digest);
    let attestation = h.attestation_for(&request, &challenge_id);

    // The attestation answers the reviewed request; presenting it against a
    // request for mutated arguments fails on the request binding.
    let mutated_env = envelope(
        &subject,
        json!({"path": "/workspace/README.md", "extra": "evil"}),
        vec!["sha256:input-1".to_string()],
    );
    let mutated_action = canonical_action(&mutated_env);
    let mut mutated_request = h
        .authority
        .open_request(&mutated_action, &mutated_env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");
    let err = h
        .authority
        .decide(&mut mutated_request, &attestation, &mut h.audit, NOW_MS)
        .expect_err("mutated request must not verify");
    assert!(matches!(err, VhlError::RequestMismatch), "got {err:?}");
    assert!(matches!(mutated_request.state, VhlRequestState::Requested));
}

#[test]
fn resigned_request_id_swap_still_fails_on_body_hash() {
    // Defense in depth: even if an attacker re-signs an attestation with a
    // swapped request id (a compromised device signing a binding the human
    // never reviewed), the message hash still pins the exact reviewed body.
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let action = canonical_action(&env);
    let request = h
        .authority
        .open_request(&action, &env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");
    let challenge_id = h.complete_ceremony(&request.action_digest);

    let other_env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-2".to_string()],
    );
    let other_action = canonical_action(&other_env);
    let other_request = h
        .authority
        .open_request(&other_action, &other_env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");
    let other_challenge = h.complete_ceremony(&other_request.action_digest);

    // Attestation for the original body, but with the other request's id and
    // ceremony — re-signed, so the request binding passes and only the body
    // hash can catch it.
    let mut attestation = h.attestation_for(&request, &challenge_id);
    attestation.request_id.clone_from(&other_request.request_id);
    attestation.proof.challenge_id = Some(other_challenge);
    let bytes = attestation_signing_bytes(&attestation).expect("signing bytes");
    attestation.sig = URL_SAFE_NO_PAD.encode(h.human_key.sign(&bytes).to_bytes());

    let mut other_request = other_request;
    let err = h
        .authority
        .decide(&mut other_request, &attestation, &mut h.audit, NOW_MS)
        .expect_err("body mismatch must fail");
    assert!(matches!(err, VhlError::BodyHashMismatch), "got {err:?}");
}

// ---------------------------------------------------------------------------
// Input-hash mutation: changed inputs are a new request, never an update
// ---------------------------------------------------------------------------

#[test]
fn input_hash_mutation_fails_closed() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let action = canonical_action(&env);
    let request = h
        .authority
        .open_request(&action, &env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");

    // Same action, but the inputs the action depends on changed: a new
    // request with a new id and nonce, as the kernel would open it.
    let changed_env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-2-TAMPERED".to_string()],
    );
    let changed_action = canonical_action(&changed_env);
    let mut changed_request = h
        .authority
        .open_request(&changed_action, &changed_env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");
    assert_ne!(request.request_id, changed_request.request_id);

    // An attestation minted for the original inputs cannot answer the
    // changed request: the request binding fails first, and the request
    // stays undecided.
    let challenge_id = h.complete_ceremony(&changed_request.action_digest);
    let attestation = h.attestation_for(&request, &challenge_id);
    let err = h
        .authority
        .decide(&mut changed_request, &attestation, &mut h.audit, NOW_MS)
        .expect_err("input-hash mutation must not verify");
    assert!(matches!(err, VhlError::RequestMismatch), "got {err:?}");
    assert!(matches!(changed_request.state, VhlRequestState::Requested));
}

// ---------------------------------------------------------------------------
// Digest mutation: the grant is bound to the exact approved digest
// ---------------------------------------------------------------------------

#[test]
fn digest_mutation_in_grant_fails_closed() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let mut request = h.approved_request(&env);
    let mut grant = h.grant_for(&request);
    // Flip the grant's digest after the human signed: the signature no
    // longer verifies, and the digest no longer matches the request.
    grant.action_digest = "0".repeat(64);
    let err = h
        .mint_lease(&mut request, &grant, &env)
        .expect_err("mutated grant must not mint");
    assert!(
        matches!(err, VhlError::DigestMismatch | VhlError::GrantSignature),
        "got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Session-subject swap: the approval is bound to the session that asked
// ---------------------------------------------------------------------------

#[test]
fn session_subject_swap_fails_closed() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let mut request = h.approved_request(&env);
    let mut grant = h.grant_for(&request);

    // Attacker re-targets the grant at a different session.
    let other = h
        .vault
        .start_session(&mut h.sessions, None, NOW_MS)
        .expect("second session")
        .subject;
    grant.session_subject = other.clone();
    // Re-signing with the human key keeps the signature valid, isolating the
    // subject binding check.
    grant.sign(&h.human_key);
    let err = h
        .mint_lease(&mut request, &grant, &env)
        .expect_err("subject-swapped grant must not mint");
    assert!(matches!(err, VhlError::SubjectMismatch), "got {err:?}");
}

// ---------------------------------------------------------------------------
// Replay: one attestation authorizes exactly one decision
// ---------------------------------------------------------------------------

#[test]
fn attestation_replay_has_no_second_effect() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let action = canonical_action(&env);
    let mut request = h
        .authority
        .open_request(&action, &env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");
    let challenge_id = h.complete_ceremony(&request.action_digest);
    let attestation = h.attestation_for(&request, &challenge_id);

    // First decision succeeds and records the attestation id in the replay set.
    h.authority
        .decide(&mut request, &attestation, &mut h.audit, NOW_MS)
        .expect("first decision succeeds");
    // The exact same attestation presented again is a replay: replay is
    // checked before request state, so the second decide fails with Replay
    // rather than advancing anything a second time.
    let err = h
        .authority
        .decide(&mut request, &attestation, &mut h.audit, NOW_MS)
        .expect_err("replay must fail");
    assert!(matches!(err, VhlError::Replay(_)), "got {err:?}");
    assert!(matches!(request.state, VhlRequestState::Approved { .. }));
}

#[test]
fn double_mint_has_no_second_effect() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let mut request = h.approved_request(&env);
    let grant = h.grant_for(&request);
    h.mint_lease(&mut request, &grant, &env)
        .expect("first mint");
    // The grant nonce is already consumed by the lease engine, and the
    // request already left Approved: both layers refuse the second mint.
    let err = h
        .mint_lease(&mut request, &grant, &env)
        .expect_err("second mint must fail");
    assert!(matches!(err, VhlError::IllegalTransition(_)), "got {err:?}");
}

// ---------------------------------------------------------------------------
// Expiry: dead requests decide nothing
// ---------------------------------------------------------------------------

#[test]
fn expired_request_fails_closed() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let action = canonical_action(&env);
    let mut request = h
        .authority
        .open_request(&action, &env, 1, NOW_MS)
        .expect("request opens");
    let challenge_id = h.complete_ceremony(&request.action_digest);
    let attestation = h.attestation_for(&request, &challenge_id);

    // Decide after the deadline: the verifier refuses, then the request is
    // marked expired and can never be decided afterwards.
    let late = NOW_MS + 60_000;
    let err = h
        .authority
        .decide(&mut request, &attestation, &mut h.audit, late)
        .expect_err("late decision must fail");
    assert!(matches!(err, VhlError::RequestExpired), "got {err:?}");
    assert!(request.note_expiry(late));
    assert!(matches!(request.state, VhlRequestState::Expired { .. }));
    let err = h
        .authority
        .decide(&mut request, &attestation, &mut h.audit, late)
        .expect_err("expired request is decided forever");
    assert!(matches!(err, VhlError::IllegalTransition(_)), "got {err:?}");
}

// ---------------------------------------------------------------------------
// Session end during action: lease revoked, commit denied by the real engine
// ---------------------------------------------------------------------------

#[test]
fn session_end_during_action_revokes_lease_and_denies_commit() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let mut request = h.approved_request(&env);
    let grant = h.grant_for(&request);
    let lease = h
        .mint_lease(&mut request, &grant, &env)
        .expect("lease mints");

    // The session ends mid-action: keys destroyed, lease revoked.
    let receipt = VhlAuthority::<CourierVhlVerifier>::end_session_and_revoke_leases(
        &mut h.vault,
        &mut h.sessions,
        &mut h.revocations,
        &subject,
        std::slice::from_ref(&lease.lease_id),
        NOW_MS,
    )
    .expect("session ends");
    assert_eq!(receipt.subject, subject);
    // The vault no longer holds the key: nothing can sign as this session.
    assert!(
        h.vault
            .sign(
                &subject,
                lumen_core::session_identity::SignatureDomain::SessionAttribution,
                b"x"
            )
            .is_err()
    );

    // The commit presents the minted lease chain; the real lease engine
    // denies it as revoked.
    let store: HashMap<String, LeaseDocument> = [(lease.lease_id.clone(), lease.clone())]
        .into_iter()
        .collect();
    let chain = vec![lease.lease_id.clone()];
    let err = validate_chain(
        &store,
        &chain,
        &h.revocations,
        &h.sessions,
        &h.keys,
        &NoopOneShot,
        NOW_MS,
    )
    .expect_err("revoked lease must not validate");
    assert!(matches!(err, LeaseError::Revoked(_)), "got {err:?}");
}

struct NoopOneShot;

impl lumen_core::lease::OneShotTracker for NoopOneShot {
    fn is_consumed(&self, _lease_id: &str) -> bool {
        false
    }
    fn consume(&mut self, _lease_id: &str) -> bool {
        true
    }
}

#[test]
fn ending_parent_destroys_descendant_keys() {
    let mut h = Harness::new();
    let parent = h.session_subject.clone();
    let child = h
        .vault
        .start_session(&mut h.sessions, Some(parent.clone()), NOW_MS)
        .expect("child starts")
        .subject;
    assert!(h.vault.is_live(&child));
    h.vault
        .end_session(&mut h.sessions, &parent, NOW_MS)
        .expect("parent ends");
    // Both keys are gone; neither can sign.
    assert!(!h.vault.is_live(&parent));
    assert!(!h.vault.is_live(&child));
}

// ---------------------------------------------------------------------------
// Challenge registry: replay, expiry, wrong codes
// ---------------------------------------------------------------------------

#[test]
fn challenge_wrong_code_burns_attempts_then_burns_challenge() {
    let mut h = Harness::new();
    let digest = "a".repeat(64);
    let (challenge_id, _code) = h
        .authority
        .challenges_mut()
        .mint(&digest, APPROVAL_TTL_MS, NOW_MS)
        .expect("mints");
    for _ in 0..4 {
        let err = h
            .authority
            .challenges_mut()
            .submit_code(&challenge_id, "wrong-code", NOW_MS)
            .expect_err("wrong code fails");
        assert!(matches!(err, VhlError::Challenge(_)));
    }
    // Fifth wrong attempt burns the challenge: even the right code fails now.
    let (challenge_id2, code2) = h
        .authority
        .challenges_mut()
        .mint(&digest, APPROVAL_TTL_MS, NOW_MS)
        .expect("mints");
    for _ in 0..5 {
        let _ = h
            .authority
            .challenges_mut()
            .submit_code(&challenge_id2, "wrong-code", NOW_MS);
    }
    let err = h
        .authority
        .challenges_mut()
        .submit_code(&challenge_id2, &code2, NOW_MS)
        .expect_err("burned challenge rejects even the right code");
    assert!(matches!(err, VhlError::Challenge(_)));
    // The first challenge still has one attempt left and completes.
    let (challenge_id3, code3) = h
        .authority
        .challenges_mut()
        .mint(&digest, APPROVAL_TTL_MS, NOW_MS)
        .expect("mints");
    h.authority
        .challenges_mut()
        .submit_code(&challenge_id3, &code3, NOW_MS)
        .expect("right code completes");
    // Completion alone authorizes nothing and is idempotent…
    h.authority
        .challenges_mut()
        .submit_code(&challenge_id3, &code3, NOW_MS)
        .expect("re-completion is idempotent");
    // …but the authorization is consumed exactly once.
    assert!(
        h.authority
            .challenges_mut()
            .consume_completed(&challenge_id3, &digest, NOW_MS),
        "first consumption succeeds"
    );
    assert!(
        !h.authority
            .challenges_mut()
            .consume_completed(&challenge_id3, &digest, NOW_MS),
        "each ceremony authorizes at most one decision"
    );
}

#[test]
fn challenge_expiry_and_action_binding() {
    let mut h = Harness::new();
    let digest_a = "a".repeat(64);
    let digest_b = "b".repeat(64);
    let (challenge_id, code) = h
        .authority
        .challenges_mut()
        .mint(&digest_a, 1_000, NOW_MS)
        .expect("mints");
    // After expiry the code is dead.
    let err = h
        .authority
        .challenges_mut()
        .submit_code(&challenge_id, &code, NOW_MS + 60_000)
        .expect_err("expired challenge fails");
    assert!(matches!(err, VhlError::Challenge(_)));

    // A live ceremony is bound to its exact action digest: consumption for
    // a different action fails and does not burn the ceremony.
    let (challenge_id, code) = h
        .authority
        .challenges_mut()
        .mint(&digest_a, APPROVAL_TTL_MS, NOW_MS)
        .expect("mints");
    h.authority
        .challenges_mut()
        .submit_code(&challenge_id, &code, NOW_MS)
        .expect("completes");
    assert!(
        !h.authority
            .challenges_mut()
            .consume_completed(&challenge_id, &digest_b, NOW_MS),
        "ceremony must not authorize a different action"
    );
    assert!(
        h.authority
            .challenges_mut()
            .consume_completed(&challenge_id, &digest_a, NOW_MS),
        "the ceremony still authorizes its own action"
    );
}

// ---------------------------------------------------------------------------
// Proof strength: Tier-2 + fido2/challenge only; session/pin never authorize
// ---------------------------------------------------------------------------

#[test]
fn weak_proofs_do_not_authorize_exceptional_action() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let action = canonical_action(&env);

    for (kind, strength) in [(ProofKind::Session, "session"), (ProofKind::Pin, "pin")] {
        // A Session proof carries a real session token: even a well-formed
        // one is weak for exceptional actions.
        let session_token = (kind == ProofKind::Session).then(|| SessionToken {
            version: 1,
            id: URL_SAFE_NO_PAD.encode(b"token-id-1"),
            issuer: "courier".to_string(),
            session_id: URL_SAFE_NO_PAD.encode(b"session-1"),
            issued_at: NOW_MS / 1000 - 60,
            expires_at: NOW_MS / 1000 + 300,
            scope: String::new(),
            presence: "session".to_string(),
            boot_id: String::new(),
            sig: URL_SAFE_NO_PAD.encode(b"sig"),
        });
        let mut request = h
            .authority
            .open_request(&action, &env, APPROVAL_TTL_MS, NOW_MS)
            .expect("request opens");
        let body = request.render_body().expect("body renders");
        let mut attestation = Attestation {
            version: 2,
            id: URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes()),
            tier: 2,
            msg_hash: URL_SAFE_NO_PAD.encode(body_hash(&body)),
            approver: HUMAN_ADDRESS.to_string(),
            issued_at: NOW_MS / 1000,
            expires_at: NOW_MS / 1000 + 300,
            proof: AttestationProof {
                kind,
                strength: strength.to_string(),
                token: session_token.clone(),
                credential_id: None,
                assertion: None,
                challenge_id: None,
            },
            request_id: request.request_id.clone(),
            sig: String::new(),
        };
        let bytes = attestation_signing_bytes(&attestation).expect("signing bytes");
        attestation.sig = URL_SAFE_NO_PAD.encode(h.human_key.sign(&bytes).to_bytes());
        let err = h
            .authority
            .decide(&mut request, &attestation, &mut h.audit, NOW_MS)
            .expect_err("weak proof must not decide");
        assert!(
            matches!(err, VhlError::InsufficientProof(_)),
            "got {err:?} for {kind:?}"
        );
    }
}

#[test]
fn tier1_attestation_does_not_authorize() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let action = canonical_action(&env);
    let mut request = h
        .authority
        .open_request(&action, &env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");
    let challenge_id = h.complete_ceremony(&request.action_digest);
    let mut attestation = h.attestation_for(&request, &challenge_id);
    attestation.tier = 1; // Tier 1 is session-scoped, not per-action.
    let bytes = attestation_signing_bytes(&attestation).expect("signing bytes");
    attestation.sig = URL_SAFE_NO_PAD.encode(h.human_key.sign(&bytes).to_bytes());
    let err = h
        .authority
        .decide(&mut request, &attestation, &mut h.audit, NOW_MS)
        .expect_err("tier-1 must not authorize");
    assert!(matches!(err, VhlError::TierNotSufficient(1)), "got {err:?}");
}

// ---------------------------------------------------------------------------
// Courier v1/v2 wire compatibility: golden canonical bytes
// ---------------------------------------------------------------------------

fn golden_attestation_v2() -> Attestation {
    Attestation {
        version: 2,
        id: URL_SAFE_NO_PAD.encode(b"test-attestation-id-1"),
        tier: 2,
        msg_hash: URL_SAFE_NO_PAD.encode([0xABu8; 32]),
        approver: "ed25519:approver".to_string(),
        issued_at: 1_700_000_000,
        expires_at: 1_700_000_300,
        proof: AttestationProof {
            kind: ProofKind::Challenge,
            strength: "challenge".to_string(),
            token: None,
            credential_id: None,
            assertion: None,
            challenge_id: Some("challenge-1".to_string()),
        },
        request_id: "request-1".to_string(),
        sig: String::new(),
    }
}

#[test]
fn v2_canonical_bytes_are_stable_and_verify() {
    let att = golden_attestation_v2();
    let bytes = attestation_signing_bytes(&att).expect("signing bytes");
    // Domain separation + version + tier prefix.
    assert!(bytes.starts_with(b"courier-vhl-attest-v1\x00"));
    assert_eq!(bytes[b"courier-vhl-attest-v1\x00".len()], 2);
    assert_eq!(bytes[b"courier-vhl-attest-v1\x00".len() + 1], 2);
    // A signature over these bytes verifies under the signer's key; a
    // signature over any other bytes does not.
    let key = SigningKey::generate(&mut OsRng);
    let sig = key.sign(&bytes);
    let mut signed = att.clone();
    signed.sig = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    lumen_core::vhl::verify_attestation_signature(&signed, &key.verifying_key())
        .expect("valid signature verifies");
    signed.msg_hash = URL_SAFE_NO_PAD.encode([0xCDu8; 32]);
    assert!(
        lumen_core::vhl::verify_attestation_signature(&signed, &key.verifying_key()).is_err(),
        "mutated body must not verify"
    );
}

#[test]
fn v1_canonical_bytes_are_frozen() {
    // The v1 form is byte-frozen for Courier compatibility: existing v1
    // signatures verify against exactly these bytes. Hand-computed from the
    // documented v1 layout (NUL-separated, no length prefixes).
    let mut att = golden_attestation_v2();
    att.version = 1;
    let bytes = attestation_signing_bytes(&att).expect("signing bytes");
    let mut expected = Vec::new();
    expected.extend_from_slice(b"courier-vhl-attest-v1\x00");
    expected.push(1u8);
    expected.push(2u8);
    expected.extend_from_slice(b"test-attestation-id-1");
    expected.extend_from_slice(&[0xABu8; 32]);
    expected.extend_from_slice(b"ed25519:approver");
    expected.push(0x00);
    expected.extend_from_slice(&1_700_000_000u64.to_be_bytes());
    expected.extend_from_slice(&1_700_000_300u64.to_be_bytes());
    expected.extend_from_slice(b"challenge");
    expected.push(0x00);
    expected.extend_from_slice(b"challenge");
    expected.push(0x00);
    expected.extend_from_slice(b"challenge-1");
    expected.extend_from_slice(b"request-1");
    assert_eq!(bytes, expected, "v1 canonical bytes must stay frozen");

    // v1 and v2 signing bytes differ for the same attestation (no cross-
    // version signature replay).
    let v2bytes = attestation_signing_bytes(&golden_attestation_v2()).expect("v2 bytes");
    assert_ne!(bytes, v2bytes);
}

#[test]
fn unknown_attestation_version_fails_closed() {
    let mut att = golden_attestation_v2();
    att.version = 9;
    let err = attestation_signing_bytes(&att).expect_err("unknown version fails");
    assert!(
        matches!(err, VhlError::UnsupportedAttestationVersion(9)),
        "got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// FIDO2: real assertion verification with sign-counter replay control
// ---------------------------------------------------------------------------

/// Build a WebAuthn assertion the way an authenticator would: authData with
/// the RP id hash, flags, and sign count; clientDataJSON binding the action
/// hash as the challenge; signature over authData || sha256(clientDataJSON).
fn fido2_assertion(
    credential_key: &SigningKey,
    action_hash: &[u8; 32],
    rp_id: &str,
    origin: &str,
    flags: u8,
    sign_count: u32,
) -> String {
    let rp_id_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    let mut auth_data = Vec::with_capacity(37);
    auth_data.extend_from_slice(&rp_id_hash);
    auth_data.push(flags);
    auth_data.extend_from_slice(&sign_count.to_be_bytes());
    let client_data_json = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{origin}\"}}",
        URL_SAFE_NO_PAD.encode(action_hash)
    );
    let client_data_hash: [u8; 32] = Sha256::digest(client_data_json.as_bytes()).into();
    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&client_data_hash);
    let signature = credential_key.sign(&signed);
    let assertion_json = json!({
        "type": "public-key",
        "response": {
            "authenticatorData": URL_SAFE_NO_PAD.encode(&auth_data),
            "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data_json.as_bytes()),
            "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    });
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion_json).unwrap())
}

fn enroll_fido2(h: &mut Harness, credential_key: &SigningKey, sign_count: u32) -> String {
    let credential_id = URL_SAFE_NO_PAD.encode(b"test-credential-id-1");
    h.authority.verifier_mut().enroll_credential(
        HUMAN_ADDRESS,
        Fido2Credential {
            credential_id: credential_id.clone(),
            public_key: credential_key.verifying_key().to_bytes(),
            cose_key: vec![],
            sign_count,
            uv_required: false,
        },
    );
    credential_id
}

fn fido2_attestation(
    h: &Harness,
    request: &VhlApprovalRequest,
    credential_id: &str,
    assertion: &str,
    strength: &str,
) -> Attestation {
    let body = request.render_body().expect("body renders");
    let mut att = Attestation {
        version: 2,
        id: URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes()),
        tier: 2,
        msg_hash: URL_SAFE_NO_PAD.encode(body_hash(&body)),
        approver: HUMAN_ADDRESS.to_string(),
        issued_at: NOW_MS / 1000,
        expires_at: NOW_MS / 1000 + 300,
        proof: AttestationProof {
            kind: ProofKind::Fido2,
            strength: strength.to_string(),
            token: None,
            credential_id: Some(credential_id.to_string()),
            assertion: Some(assertion.to_string()),
            challenge_id: None,
        },
        request_id: request.request_id.clone(),
        sig: String::new(),
    };
    let bytes = attestation_signing_bytes(&att).expect("signing bytes");
    att.sig = URL_SAFE_NO_PAD.encode(h.human_key.sign(&bytes).to_bytes());
    att
}

#[test]
fn fido2_attestation_verifies_and_counter_replay_fails() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let action = canonical_action(&env);
    let credential_key = SigningKey::generate(&mut OsRng);
    let credential_id = enroll_fido2(&mut h, &credential_key, 41);

    let mut request = h
        .authority
        .open_request(&action, &env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");
    let body = request.render_body().expect("body renders");
    let action_hash = body_hash(&body);
    let assertion = fido2_assertion(&credential_key, &action_hash, RP_ID, RP_ORIGIN, 0x01, 42);
    let attestation = fido2_attestation(&h, &request, &credential_id, &assertion, "fido2");
    h.authority
        .decide(&mut request, &attestation, &mut h.audit, NOW_MS)
        .expect("fido2 attestation verifies");

    // A cloned assertion with a non-increasing sign count is a replay: the
    // counter must strictly increase.
    let mut request2 = h
        .authority
        .open_request(&action, &env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");
    let body2 = request2.render_body().expect("body renders");
    let action_hash2 = body_hash(&body2);
    let replay_assertion =
        fido2_assertion(&credential_key, &action_hash2, RP_ID, RP_ORIGIN, 0x01, 42);
    let replay = fido2_attestation(&h, &request2, &credential_id, &replay_assertion, "fido2");
    let err = h
        .authority
        .decide(&mut request2, &replay, &mut h.audit, NOW_MS)
        .expect_err("stale sign count must fail");
    assert!(matches!(err, VhlError::Fido2(_)), "got {err:?}");

    // Wrong RP origin fails closed.
    let mut request3 = h
        .authority
        .open_request(&action, &env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");
    let body3 = request3.render_body().expect("body renders");
    let bad_origin = fido2_assertion(
        &credential_key,
        &body_hash(&body3),
        RP_ID,
        "https://evil.test",
        0x01,
        43,
    );
    let bad = fido2_attestation(&h, &request3, &credential_id, &bad_origin, "fido2");
    let err = h
        .authority
        .decide(&mut request3, &bad, &mut h.audit, NOW_MS)
        .expect_err("wrong origin must fail");
    assert!(matches!(err, VhlError::Fido2(_)), "got {err:?}");
}

// ---------------------------------------------------------------------------
// Standing leases: the explicit, separate workflow — never inferred
// ---------------------------------------------------------------------------

#[test]
fn standing_lease_requires_the_explicit_workflow() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let action = canonical_action(&env);

    // A one-shot approval cannot be confirmed as a standing lease…
    let mut one_shot = h.approved_request(&env);
    let challenge_id = h.complete_ceremony(&one_shot.action_digest);
    let attestation = h.attestation_for(&one_shot, &challenge_id);
    let err = h
        .authority
        .confirm_standing_lease(&mut one_shot, &attestation, &mut h.audit, NOW_MS)
        .expect_err("one-shot is not a standing lease");
    assert!(
        matches!(err, VhlError::StandingLeaseNotConfirmed),
        "got {err:?}"
    );

    // …and decide() refuses standing-lease requests: the workflows are
    // separate functions, not a flag.
    let mut standing = h
        .authority
        .open_standing_request(&action, &env, 10, APPROVAL_TTL_MS, NOW_MS)
        .expect("standing request opens");
    assert!(standing.view.summary.contains("NOT a one-time approval"));
    let challenge_id = h.complete_ceremony(&standing.action_digest);
    let attestation = h.attestation_for(&standing, &challenge_id);
    let err = h
        .authority
        .decide(&mut standing, &attestation, &mut h.audit, NOW_MS)
        .expect_err("decide() is one-shot only");
    assert!(matches!(err, VhlError::IllegalTransition(_)), "got {err:?}");
}

#[test]
fn standing_lease_mint_needs_confirmation_and_matches_approved_scope() {
    let mut h = Harness::new();
    // Parent session holds standing authority; the child session will act.
    let parent_subject = h.session_subject.clone();
    let child_subject = h
        .vault
        .start_session(&mut h.sessions, Some(parent_subject.clone()), NOW_MS)
        .expect("child session")
        .subject;

    let env = envelope(
        &child_subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let action = canonical_action(&env);
    let mut request = h
        .authority
        .open_standing_request(&action, &env, 10, APPROVAL_TTL_MS, NOW_MS)
        .expect("standing request opens");
    let challenge_id = h.complete_ceremony(&request.action_digest);
    let attestation = h.attestation_for(&request, &challenge_id);
    let confirmation = h
        .authority
        .confirm_standing_lease(&mut request, &attestation, &mut h.audit, NOW_MS)
        .expect("confirmation issues");
    assert_eq!(confirmation.request_id(), request.request_id);

    // Parent root lease with scope covering the approved action.
    let parent_scope = parent_test_scope(&action);
    let parent_lease = mint_root_lease(
        RootLeaseParams {
            lease_id: "root-parent-1".to_string(),
            subject: parent_subject.clone(),
            scope: parent_scope,
            limits: LeaseLimits {
                not_before_ms: NOW_MS,
                expires_at_ms: NOW_MS + 3_600_000,
                budget: Budget::new().set(BudgetDimension::Executions, 100),
                max_executions: Some(100),
                single_use: false,
            },
            depth_limit: 4,
            lease_nonce: "root-parent-nonce-1".to_string(),
            issued_at_ms: NOW_MS,
        },
        &h.keys,
        &h.sessions,
        &h.ledger,
        &h.nonces,
        NOW_MS,
    )
    .expect("parent root lease mints");

    // Without the confirmation there is no mint path: the confirmation
    // type can only be built by confirm_standing_lease.
    let Harness {
        authority,
        vault,
        sessions,
        revocations,
        ledger,
        nonces,
        audit,
        ..
    } = &mut h;
    let lease = authority
        .mint_standing_lease(
            confirmation,
            &mut request,
            &parent_lease,
            vault,
            sessions,
            revocations,
            ledger,
            nonces,
            audit,
            NOW_MS,
        )
        .expect("standing lease mints");
    assert!(!lease.limits.single_use, "standing lease is reusable");
    assert_eq!(lease.subject, child_subject);
    assert_eq!(
        lease.parent_id.as_deref(),
        Some(parent_lease.lease_id.as_str())
    );
    assert_eq!(lease.limits.max_executions, Some(10));
    // The minted scope is exactly what the human reviewed.
    assert_eq!(lease.scope.effects, action.effects);
    assert_eq!(lease.scope.paths.len(), action.paths.len());
    assert!(matches!(request.state, VhlRequestState::Minted { .. }));

    // The standing lease validates through the real engine as a child of
    // the parent.
    let store: HashMap<String, LeaseDocument> = [
        (lease.lease_id.clone(), lease.clone()),
        (parent_lease.lease_id.clone(), parent_lease),
    ]
    .into_iter()
    .collect();
    validate_chain(
        &store,
        &[lease.lease_id.clone(), "root-parent-1".to_string()],
        &h.revocations,
        &h.sessions,
        &h.keys,
        &NoopOneShot,
        NOW_MS,
    )
    .expect("standing chain validates");
}

/// Parent scope mirroring the action's exact authority (what policy would
/// grant as standing authority for the session).
fn parent_test_scope(action: &CanonicalAction) -> lumen_core::canonical::ResourceScope {
    use lumen_core::canonical::{PathGrant, PathRights, ResourceScope};
    let mut scope = ResourceScope::default();
    scope.tools.insert(
        action.tool_name.as_str().to_string(),
        semver::VersionReq::parse(&format!("={}", action.tool_version)).expect("pinned"),
    );
    let rights = PathRights {
        read: action.effects.contains(&EffectClass::Read)
            || action.effects.contains(&EffectClass::Execute),
        write: action.effects.contains(&EffectClass::Write),
    };
    for root in &action.paths {
        scope.paths.push(PathGrant {
            root: root.clone(),
            rights,
        });
    }
    scope
        .destinations
        .extend(action.destinations.iter().cloned());
    scope
        .secrets
        .extend(action.secrets.iter().map(|s| s.as_str().to_string()));
    scope.effects = action.effects.clone();
    scope
}

// ---------------------------------------------------------------------------
// Audit: decision-event removal / gaps are detectable
// ---------------------------------------------------------------------------

#[test]
fn audit_event_removal_breaks_the_chain() {
    use lumen_core::kernel_audit::{AuditStore as _, verify_event_chain};
    use lumen_core::pi_boundary::AuditEventKind;

    let mut log = KernelAuditLog::new(MemoryAuditStore::default());
    for (i, decision) in ["approval.granted", "approval.minted", "approval.consumed"]
        .iter()
        .enumerate()
    {
        log.append(
            "human",
            AuditEventKind::ApprovalRequested,
            "test-session",
            &"d".repeat(64),
            Some(decision),
            NOW_MS + i as i64,
            json!({"seq": i}),
        )
        .expect("append");
    }
    let events = log.store().events().to_vec();
    verify_event_chain(&events).expect("intact chain verifies");

    // Removal of a decision event breaks sequence continuity: detectable.
    let mut tampered = events.clone();
    tampered.remove(1);
    assert!(
        verify_event_chain(&tampered).is_err(),
        "removed decision event must break the chain"
    );

    // Mutation of a decision event breaks the hash link: detectable.
    let mut tampered = events.clone();
    tampered[0].decision = Some("approval.denied".to_string());
    assert!(
        verify_event_chain(&tampered).is_err(),
        "mutated decision event must break the chain"
    );
}

// ---------------------------------------------------------------------------
// Courier transport seam: native message types round-trip
// ---------------------------------------------------------------------------

#[test]
fn vhl_courier_messages_round_trip() {
    use lumen_core::vhl::VhlCourierMessage;

    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let action = canonical_action(&env);
    let request = h
        .authority
        .open_request(&action, &env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");

    let msg = VhlCourierMessage::ApprovalRequest {
        request: request.clone(),
    };
    assert_eq!(msg.message_type(), "lumen.vhl.approval-request.v1");
    let bytes = msg.encode().expect("encodes");
    let decoded = VhlCourierMessage::decode(&bytes).expect("decodes");
    assert_eq!(decoded, msg);

    let challenge_id = h.complete_ceremony(&request.action_digest);
    let attestation = h.attestation_for(&request, &challenge_id);
    let msg = VhlCourierMessage::Attestation {
        attestation: attestation.clone(),
    };
    assert_eq!(msg.message_type(), "lumen.vhl.attestation.v1");
    let bytes = msg.encode().expect("encodes");
    assert_eq!(VhlCourierMessage::decode(&bytes).expect("decodes"), msg);

    let msg = VhlCourierMessage::ChallengeNotice {
        challenge_id: "challenge-1".to_string(),
        action_digest: request.action_digest.clone(),
        expires_at_ms: NOW_MS + APPROVAL_TTL_MS,
    };
    assert_eq!(msg.message_type(), "lumen.vhl.challenge-notice.v1");
    let bytes = msg.encode().expect("encodes");
    assert_eq!(VhlCourierMessage::decode(&bytes).expect("decodes"), msg);
}

#[test]
fn challenge_ceremony_authorizes_exactly_one_decision() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let action = canonical_action(&env);

    // First request: full ceremony, attestation, decision — succeeds.
    let mut request1 = h
        .authority
        .open_request(&action, &env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");
    let challenge_id = h.complete_ceremony(&request1.action_digest);
    let attestation1 = h.attestation_for(&request1, &challenge_id);
    h.authority
        .decide(&mut request1, &attestation1, &mut h.audit, NOW_MS)
        .expect("first decision succeeds");

    // A second, distinct attestation (fresh id, fresh signature) reusing the
    // same completed challenge must NOT authorize another decision: the
    // ceremony is consumed, not just read.
    let mut request2 = h
        .authority
        .open_request(&action, &env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");
    // Same action digest (same action), new request id.
    assert_eq!(request2.action_digest, request1.action_digest);
    let attestation2 = h.attestation_for(&request2, &challenge_id);
    assert_ne!(attestation2.id, attestation1.id);
    let err = h
        .authority
        .decide(&mut request2, &attestation2, &mut h.audit, NOW_MS)
        .expect_err("reused ceremony must fail");
    assert!(matches!(err, VhlError::Challenge(_)), "got {err:?}");
    assert!(matches!(request2.state, VhlRequestState::Requested));
}

// ---------------------------------------------------------------------------
// Review remediation: deny() must prepare the (fallible) transition before
// the audit, like decide(). A denial clicked after approval is
// IllegalTransition and must leave neither state nor a false denial event.
// ---------------------------------------------------------------------------

#[test]
fn deny_after_approval_fails_without_false_denial_audit() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let action = canonical_action(&env);

    let mut request = h
        .authority
        .open_request(&action, &env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");
    let challenge_id = h.complete_ceremony(&request.action_digest);
    let attestation = h.attestation_for(&request, &challenge_id);
    let mut audit = RecordingAudit::default();
    h.authority
        .decide(&mut request, &attestation, &mut audit, NOW_MS)
        .expect("approval succeeds");
    assert!(matches!(request.state, VhlRequestState::Approved { .. }));

    let err = h
        .authority
        .deny(&mut request, HUMAN_ADDRESS, "too late", &mut audit, NOW_MS)
        .expect_err("deny after approval must fail");
    assert!(matches!(err, VhlError::IllegalTransition(_)), "got {err:?}");
    assert!(
        matches!(request.state, VhlRequestState::Approved { .. }),
        "approved request must stay approved"
    );
    assert!(
        !audit.events.iter().any(|e| e.3 == "approval.denied"),
        "no denial audit event for a request that was never denied"
    );
}

/// An audit sink that always fails: proves decision paths are atomic with
/// respect to audit — a failed append must not leave the request advanced.
#[derive(Debug, Default)]
struct FailingAudit;

impl VhlAuditSink for FailingAudit {
    fn record_vhl(
        &mut self,
        _approver: &str,
        _session_id: &str,
        _action_digest: &str,
        _decision: &str,
        _details: serde_json::Value,
        _now_ms: i64,
    ) -> Result<(), VhlError> {
        Err(VhlError::Encoding("audit store unavailable".to_string()))
    }
}

#[test]
fn audit_failure_leaves_request_unadvanced() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let action = canonical_action(&env);

    // Approval path: audit fails → request stays Requested.
    let mut request = h
        .authority
        .open_request(&action, &env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");
    let challenge_id = h.complete_ceremony(&request.action_digest);
    let attestation = h.attestation_for(&request, &challenge_id);
    let mut failing = FailingAudit;
    let err = h
        .authority
        .decide(&mut request, &attestation, &mut failing, NOW_MS)
        .expect_err("audit failure must fail the decision");
    assert!(matches!(err, VhlError::Encoding(_)), "got {err:?}");
    assert!(
        matches!(request.state, VhlRequestState::Requested),
        "state must not advance when audit fails"
    );

    // Denial path: same guarantee.
    let mut request2 = h
        .authority
        .open_request(&action, &env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");
    h.authority
        .deny(&mut request2, HUMAN_ADDRESS, "nope", &mut failing, NOW_MS)
        .expect_err("audit failure must fail the denial");
    assert!(matches!(request2.state, VhlRequestState::Requested));
}

// ---------------------------------------------------------------------------
// Review remediation: side-effect-free verification, confirmation binding,
// per-path rights, canonical destinations, mint retryability
// ---------------------------------------------------------------------------

/// Envelope with two paths carrying different declared rights: a read-only
/// path and a read+write path.
fn envelope_mixed_paths(session_subject: &str) -> ActionEnvelope {
    use lumen_core::pi_boundary::{PathResource, PathRights as WirePathRights};
    let mut env = envelope(
        session_subject,
        json!({"paths": ["/workspace/README.md", "/workspace/notes.txt"]}),
        vec![],
    );
    env.resources.paths = vec![
        PathResource {
            path: "/workspace/README.md".to_string(),
            rights: WirePathRights::Read,
        },
        PathResource {
            path: "/workspace/notes.txt".to_string(),
            rights: WirePathRights::Write,
        },
    ];
    env.expected_effects.file_write = true;
    env
}

/// Envelope with a single HTTPS network resource.
fn envelope_with_network(session_subject: &str) -> ActionEnvelope {
    use lumen_core::pi_boundary::NetworkResource;
    let mut env = envelope(
        session_subject,
        json!({"url": "https://example.com/api"}),
        vec![],
    );
    env.resources.network = vec![NetworkResource {
        scheme: "https".to_string(),
        host: "example.com".to_string(),
        port: 443,
    }];
    env.expected_effects.network_egress = true;
    env
}

/// Start a child session under the harness session; returns its subject.
fn child_session(h: &mut Harness) -> String {
    let parent_subject = h.session_subject.clone();
    h.vault
        .start_session(&mut h.sessions, Some(parent_subject), NOW_MS)
        .expect("child session")
        .subject
}

/// Full standing-lease flow through confirmation, plus a parent root lease
/// whose scope covers the approved action. The envelope must already name
/// a live child session.
fn confirm_standing(
    h: &mut Harness,
    env: &ActionEnvelope,
    budget_executions: u64,
) -> (VhlApprovalRequest, StandingLeaseConfirmation, LeaseDocument) {
    let action = canonical_action(env);
    let mut request = h
        .authority
        .open_standing_request(&action, env, budget_executions, APPROVAL_TTL_MS, NOW_MS)
        .expect("standing request opens");
    let challenge_id = h.complete_ceremony(&request.action_digest);
    let attestation = h.attestation_for(&request, &challenge_id);
    let confirmation = h
        .authority
        .confirm_standing_lease(&mut request, &attestation, &mut h.audit, NOW_MS)
        .expect("confirmation issues");
    let parent_lease = mint_root_lease(
        RootLeaseParams {
            lease_id: "root-parent-1".to_string(),
            subject: h.session_subject.clone(),
            scope: parent_test_scope(&action),
            limits: LeaseLimits {
                not_before_ms: NOW_MS,
                expires_at_ms: NOW_MS + 3_600_000,
                budget: Budget::new().set(BudgetDimension::Executions, 100),
                max_executions: Some(100),
                single_use: false,
            },
            depth_limit: 4,
            lease_nonce: "root-parent-nonce-1".to_string(),
            issued_at_ms: NOW_MS,
        },
        &h.keys,
        &h.sessions,
        &h.ledger,
        &h.nonces,
        NOW_MS,
    )
    .expect("parent root lease mints");
    (request, confirmation, parent_lease)
}

/// Mint a confirmed standing lease. The audit sink is a separate `&mut`
/// (not a harness field) so tests can inject failures without
/// double-borrowing the harness.
#[allow(clippy::too_many_arguments)]
fn mint_standing(
    authority: &VhlAuthority<CourierVhlVerifier>,
    vault: &SessionIdentityVault,
    sessions: &SessionRegistry,
    revocations: &RevocationIndex,
    ledger: &BudgetLedger,
    nonces: &NonceStore,
    confirmation: StandingLeaseConfirmation,
    request: &mut VhlApprovalRequest,
    parent_lease: &LeaseDocument,
    audit: &mut dyn VhlAuditSink,
    now_ms: i64,
) -> Result<LeaseDocument, VhlError> {
    authority.mint_standing_lease(
        confirmation,
        request,
        parent_lease,
        vault,
        sessions,
        revocations,
        ledger,
        nonces,
        audit,
        now_ms,
    )
}

/// Split the harness for a standing mint with the harness's recording audit.
macro_rules! mint_standing_recording {
    ($h:expr, $confirmation:expr, $request:expr, $parent_lease:expr) => {{
        let Harness {
            authority,
            vault,
            sessions,
            revocations,
            ledger,
            nonces,
            audit,
            ..
        } = &mut $h;
        mint_standing(
            authority,
            vault,
            sessions,
            revocations,
            ledger,
            nonces,
            $confirmation,
            $request,
            $parent_lease,
            audit,
            NOW_MS,
        )
    }};
}

/// Split the harness for a standing mint with an injected audit sink.
macro_rules! mint_standing_injected {
    ($h:expr, $confirmation:expr, $request:expr, $parent_lease:expr, $audit:expr) => {{
        let Harness {
            authority,
            vault,
            sessions,
            revocations,
            ledger,
            nonces,
            ..
        } = &mut $h;
        mint_standing(
            authority,
            vault,
            sessions,
            revocations,
            ledger,
            nonces,
            $confirmation,
            $request,
            $parent_lease,
            $audit,
            NOW_MS,
        )
    }};
}

#[test]
fn audit_failure_leaves_challenge_proof_unconsumed() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let action = canonical_action(&env);
    let mut request = h
        .authority
        .open_request(&action, &env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");
    let challenge_id = h.complete_ceremony(&request.action_digest);
    let attestation = h.attestation_for(&request, &challenge_id);

    // Verification is side-effect-free: the audit fails, so the decision
    // fails with the proof unconsumed — no stranded valid proof.
    let mut failing = FailingAudit;
    let err = h
        .authority
        .decide(&mut request, &attestation, &mut failing, NOW_MS)
        .expect_err("audit failure must fail the decision");
    assert!(matches!(err, VhlError::Encoding(_)), "got {err:?}");
    assert!(matches!(request.state, VhlRequestState::Requested));
    assert!(
        h.authority
            .challenges()
            .is_consumable(&challenge_id, &request.action_digest, NOW_MS),
        "challenge must still be consumable after audit failure"
    );

    // The exact same attestation retries cleanly: nothing was marked seen.
    h.authority
        .decide(&mut request, &attestation, &mut h.audit, NOW_MS)
        .expect("retry succeeds");
    assert!(matches!(request.state, VhlRequestState::Approved { .. }));

    // After the durable commit the ceremony is spent.
    assert!(
        !h.authority
            .challenges()
            .is_consumable(&challenge_id, &request.action_digest, NOW_MS),
        "challenge must be consumed after the committed decision"
    );
}

#[test]
fn standing_mint_rejects_view_mutated_after_confirmation() {
    let mut h = Harness::new();
    let child_subject = child_session(&mut h);
    let env = envelope(
        &child_subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let (mut request, confirmation, parent_lease) = confirm_standing(&mut h, &env, 10);

    // The caller keeps &mut access to the request after confirmation: widen
    // the approved budget before mint.
    request.view.budget_executions += 100;
    let err = mint_standing_recording!(h, confirmation, &mut request, &parent_lease)
        .expect_err("mutated view must fail the confirmation binding");
    assert!(matches!(err, VhlError::ConfirmationMismatch), "got {err:?}");
    assert!(
        matches!(request.state, VhlRequestState::Approved { .. }),
        "failed mint must not advance the request"
    );
}

#[test]
fn standing_mint_preserves_per_path_rights() {
    let mut h = Harness::new();
    let child_subject = child_session(&mut h);
    let env = envelope_mixed_paths(&child_subject);
    let action = canonical_action(&env);
    // The canonical action carries each path's own declared rights.
    assert_eq!(
        action.path_rights,
        vec![CanonicalPathRights::READ, CanonicalPathRights::READ_WRITE]
    );
    let (mut request, confirmation, parent_lease) = confirm_standing(&mut h, &env, 10);
    // The approved view binds each path's own rights, and the human-readable
    // summary shows them.
    assert_eq!(
        request.view.path_rights,
        vec![CanonicalPathRights::READ, CanonicalPathRights::READ_WRITE]
    );
    assert!(
        request.view.summary.contains("[read]"),
        "summary must show per-path rights:\n{}",
        request.view.summary
    );
    assert!(request.view.summary.contains("[read+write]"));

    let lease = mint_standing_recording!(h, confirmation, &mut request, &parent_lease)
        .expect("standing lease mints");
    assert_eq!(lease.scope.paths.len(), 2);
    // The read-only path must NOT be widened to write: under the old
    // aggregate derivation both paths would have been read+write.
    assert_eq!(lease.scope.paths[0].rights, CanonicalPathRights::READ);
    assert_eq!(lease.scope.paths[1].rights, CanonicalPathRights::READ_WRITE);
    assert!(
        lease.scope.paths[0]
            .root
            .canonical_form()
            .ends_with("README.md")
    );
}

#[test]
fn standing_mint_decodes_canonical_destinations() {
    let mut h = Harness::new();
    let child_subject = child_session(&mut h);
    let env = envelope_with_network(&child_subject);
    let (mut request, confirmation, parent_lease) = confirm_standing(&mut h, &env, 10);
    // The approved view holds the canonical `net:` string the human saw.
    assert_eq!(request.view.destinations.len(), 1);
    assert!(
        request.view.destinations[0].starts_with("net:https://dns:example.com:ports:443"),
        "got {}",
        request.view.destinations[0]
    );

    let lease = mint_standing_recording!(h, confirmation, &mut request, &parent_lease)
        .expect("standing lease mints");
    assert_eq!(lease.scope.destinations.len(), 1);
    let dest = &lease.scope.destinations[0];
    assert_eq!(dest.scheme, "https");
    assert!(matches!(&dest.host, HostPattern::DnsName(n) if n == "example.com"));
    assert!(dest.ports.contains(443));
    assert!(!dest.ports.contains(80));
    assert!(dest.methods.is_empty());
    // The decoded destination re-encodes to exactly the approved string:
    // no port set or method allowlist was dropped or invented.
    assert_eq!(dest.canonical_form(), request.view.destinations[0]);
}

#[test]
fn one_shot_mint_audit_failure_is_retryable() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let mut request = h.approved_request(&env);
    let grant = h.grant_for(&request);
    let action = canonical_action(&env);

    // The lease engine runs, then the durable append fails: unwind the
    // engine's side effects so the approval is retryable, not stranded.
    let mut failing = FailingAudit;
    let err = {
        let Harness {
            authority,
            keys,
            sessions,
            ledger,
            nonces,
            ..
        } = &mut h;
        authority.mint_one_shot(
            &mut request,
            &grant,
            &action,
            keys,
            sessions,
            ledger,
            nonces,
            &mut failing,
            NOW_MS,
        )
    }
    .expect_err("audit failure must fail the mint");
    assert!(matches!(err, VhlError::Encoding(_)), "got {err:?}");
    assert!(
        matches!(request.state, VhlRequestState::Approved { .. }),
        "failed mint must leave the request Approved"
    );
    assert_eq!(
        h.nonces.len(),
        0,
        "the consumed grant nonce must be forgotten for retry"
    );
    h.ledger.check_invariants().expect("ledger invariants hold");

    // Retry with a working audit: the exact same grant mints exactly once.
    let lease = h
        .mint_lease(&mut request, &grant, &env)
        .expect("retry mints");
    assert!(lease.limits.single_use);
    assert!(matches!(request.state, VhlRequestState::Minted { .. }));
    let again = h.mint_lease(&mut request, &grant, &env);
    assert!(
        matches!(again, Err(VhlError::IllegalTransition(_))),
        "double mint must fail closed, got {again:?}"
    );
}

#[test]
fn standing_mint_audit_failure_is_retryable() {
    let mut h = Harness::new();
    let child_subject = child_session(&mut h);
    let env = envelope(
        &child_subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let (mut request, confirmation, parent_lease) = confirm_standing(&mut h, &env, 10);
    let parent_id = parent_lease.lease_id.clone();

    // The child mint runs (nonce consumed, parent budget reserved, child
    // account registered), then the durable append fails: unwind all three.
    let mut failing = FailingAudit;
    let err = mint_standing_injected!(
        h,
        confirmation.clone(),
        &mut request,
        &parent_lease,
        &mut failing
    )
    .expect_err("audit failure must fail the mint");
    assert!(matches!(err, VhlError::Encoding(_)), "got {err:?}");
    assert!(
        matches!(request.state, VhlRequestState::Approved { .. }),
        "failed mint must leave the request Approved"
    );
    assert!(
        h.ledger.active_reservations().is_empty(),
        "the parent budget reservation must be released"
    );
    let (_, reserved_out, _, _) = h
        .ledger
        .account_summary(&parent_id)
        .expect("parent account survives");
    assert!(
        reserved_out.is_zero(),
        "parent reserved_out must be restored, got {reserved_out:?}"
    );
    h.ledger.check_invariants().expect("ledger invariants hold");

    // Retry with a working audit: the same confirmation mints exactly once.
    let lease = mint_standing_recording!(h, confirmation, &mut request, &parent_lease)
        .expect("retry mints");
    assert!(!lease.limits.single_use);
    assert_eq!(
        lease.parent_id.as_deref(),
        Some(parent_lease.lease_id.as_str())
    );
    assert!(matches!(request.state, VhlRequestState::Minted { .. }));
}

#[test]
fn audit_failure_leaves_fido2_proof_unconsumed() {
    let mut h = Harness::new();
    let subject = h.session_subject.clone();
    let env = envelope(
        &subject,
        json!({"path": "/workspace/README.md"}),
        vec!["sha256:input-1".to_string()],
    );
    let action = canonical_action(&env);
    let credential_key = SigningKey::generate(&mut OsRng);
    let credential_id = enroll_fido2(&mut h, &credential_key, 41);

    let mut request = h
        .authority
        .open_request(&action, &env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");
    let body = request.render_body().expect("body renders");
    let assertion = fido2_assertion(
        &credential_key,
        &body_hash(&body),
        RP_ID,
        RP_ORIGIN,
        0x01,
        42,
    );
    let attestation = fido2_attestation(&h, &request, &credential_id, &assertion, "fido2");

    // The audit fails after pure verification: the decision fails with the
    // FIDO2 proof unconsumed — the counter must not advance and the
    // attestation id must not be marked seen.
    let mut failing = FailingAudit;
    let err = h
        .authority
        .decide(&mut request, &attestation, &mut failing, NOW_MS)
        .expect_err("audit failure must fail the decision");
    assert!(matches!(err, VhlError::Encoding(_)), "got {err:?}");
    assert!(matches!(request.state, VhlRequestState::Requested));

    // The exact same attestation retries cleanly: had the counter advanced,
    // check_fido2 would reject the non-increasing sign count; had the
    // attestation been marked seen, the replay check would reject it.
    h.authority
        .decide(&mut request, &attestation, &mut h.audit, NOW_MS)
        .expect("retry succeeds");
    assert!(matches!(request.state, VhlRequestState::Approved { .. }));

    // After the durable commit the counter DID advance: reusing the same
    // sign count is now a replay.
    let mut request2 = h
        .authority
        .open_request(&action, &env, APPROVAL_TTL_MS, NOW_MS)
        .expect("request opens");
    let body2 = request2.render_body().expect("body renders");
    let replay_assertion = fido2_assertion(
        &credential_key,
        &body_hash(&body2),
        RP_ID,
        RP_ORIGIN,
        0x01,
        42,
    );
    let replay = fido2_attestation(&h, &request2, &credential_id, &replay_assertion, "fido2");
    let err = h
        .authority
        .decide(&mut request2, &replay, &mut h.audit, NOW_MS)
        .expect_err("stale sign count must fail");
    assert!(matches!(err, VhlError::Fido2(_)), "got {err:?}");
}
