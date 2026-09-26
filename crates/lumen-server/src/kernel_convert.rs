//! Conversion between host views and the authoritative kernel contracts.
//!
//! `AuthorityKernelClient` uses this adapter with the signed lease engine.
//! The host view and core ActionEnvelope v2 have different representations:
//! host string IDs/timestamps and resource lists map to typed kernel fields.
//! The kernel action digest binds approvals and kernel audit records; the
//! returned host decision separately binds the host transport digest. These
//! digests must not be substituted. Consolidation remains host integration work.
//!
//! Unrepresentable SecretUse/MessageSend effect classes are rejected. Host
//! paths map to per-resource write rights when Write is declared, otherwise
//! read rights; host secret references lack a purpose and map to an empty one.
//! The adapter supplies no authority: kernel canonicalization, lease checks,
//! budgets, isolated execution and controlled commit are still required.

use lumen_core::pi_boundary::{
    self, ActionEnvelope as FrozenEnvelope, DecisionOutcome, EffectClasses as FrozenEffectClasses,
    InputRef as FrozenInputRef, LeaseId, NetworkResource as FrozenNet,
    Obligation as FrozenObligation, PathResource as FrozenPath, PathRights as FrozenRights,
    PolicyDecision as FrozenDecision, ResourceSet as FrozenResources, SecretRef as FrozenSecret,
    ToolRef as FrozenToolRef,
};
use uuid::Uuid;

use crate::kernel_client::{
    ACTION_ENVELOPE_VERSION as HOST_ENVELOPE_VERSION, ActionEnvelope, Decision, EffectClass,
    EnvelopeError, KernelError, Obligation, POLICY_DECISION_VERSION as HOST_DECISION_VERSION,
    PolicyDecision, now_rfc3339, rfc3339_to_ms,
};
pub(crate) fn to_frozen_envelope(env: &ActionEnvelope) -> Result<FrozenEnvelope, KernelError> {
    // Structural validation first: versions, UUID shape, timestamp shape.
    env.validate()?;
    if env.protocol_version != pi_boundary::ACTION_ENVELOPE_VERSION {
        return Err(EnvelopeError::VersionMismatch(
            env.protocol_version,
            pi_boundary::ACTION_ENVELOPE_VERSION,
        )
        .into());
    }
    debug_assert_eq!(
        HOST_ENVELOPE_VERSION,
        pi_boundary::ACTION_ENVELOPE_VERSION,
        "host and frozen envelope versions drifted"
    );

    let action_id = Uuid::parse_str(&env.action_id)
        .map_err(|_| EnvelopeError::BadActionId(env.action_id.clone()))?;

    let arguments = match &env.arguments {
        serde_json::Value::Object(map) => map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        _ => {
            return Err(EnvelopeError::Deserialize(
                "envelope arguments must be a JSON object".to_string(),
            )
            .into());
        }
    };

    let inputs = env
        .input_hashes
        .iter()
        .map(|h| FrozenInputRef {
            content_hash: h.clone(),
            snapshot_id: None,
        })
        .collect();

    let write = env.expected_effects.contains(&EffectClass::Write);
    let paths = env
        .resources
        .paths
        .iter()
        .map(|p| FrozenPath {
            path: p.clone(),
            rights: if write {
                FrozenRights::Write
            } else {
                FrozenRights::Read
            },
        })
        .collect();

    let mut network = Vec::with_capacity(env.resources.hosts.len());
    for dest in &env.resources.hosts {
        network.push(parse_network_dest(dest)?);
    }

    let secrets = env
        .resources
        .secret_refs
        .iter()
        .map(|id| FrozenSecret {
            id: id.clone(),
            // The host shape carries no purpose; the frozen field is
            // required but unused by the phase-0 policy.
            purpose: String::new(),
        })
        .collect();

    let mut effects = FrozenEffectClasses {
        file_read: false,
        file_write: false,
        network_egress: false,
        network_ingress: false,
        process_spawn: false,
    };
    // Fail closed on effect classes the frozen contract cannot express:
    // silently discarding them would let the kernel authorize an action
    // on a lease that never granted the dropped effect, and the decision
    // is rebound to the host envelope's digest, hiding the loss from the
    // caller.
    let unsupported: Vec<&str> = env
        .expected_effects
        .iter()
        .filter_map(|class| match class {
            EffectClass::SecretUse => Some("SecretUse"),
            EffectClass::MessageSend => Some("MessageSend"),
            _ => None,
        })
        .collect();
    if !unsupported.is_empty() {
        return Err(EnvelopeError::UnsupportedEffect(unsupported.join(", ")).into());
    }
    for class in &env.expected_effects {
        match class {
            EffectClass::Read => effects.file_read = true,
            EffectClass::Write => effects.file_write = true,
            // `Network` covers egress here; the frozen contract has no
            // ingress flag expressible from the host shape, and the
            // phase-0 policy denies network actions regardless.
            EffectClass::Network => effects.network_egress = true,
            EffectClass::Execute => effects.process_spawn = true,
            // Unreachable: rejected above. Kept to stay exhaustive if new
            // variants are added without updating the rejection list.
            EffectClass::SecretUse | EffectClass::MessageSend => {
                return Err(EnvelopeError::UnsupportedEffect(format!("{class:?}")).into());
            }
        }
    }

    let mut lease_chain = Vec::with_capacity(env.lease_chain.len());
    for id in &env.lease_chain {
        let uuid = Uuid::parse_str(id)
            .map_err(|_| EnvelopeError::Deserialize(format!("bad lease id '{id}'")))?;
        lease_chain.push(LeaseId::from_uuid(uuid));
    }

    let expires_at_ms = rfc3339_to_ms(&env.expires_at)
        .ok_or_else(|| EnvelopeError::BadExpiry(env.expires_at.clone()))?;

    Ok(FrozenEnvelope {
        version: pi_boundary::ACTION_ENVELOPE_VERSION,
        action_id,
        session_id: env.session_id.clone(),
        tool: FrozenToolRef {
            name: env.tool.name.clone(),
            version: env.tool.version.clone(),
        },
        arguments,
        inputs,
        resources: FrozenResources {
            paths,
            network,
            secrets,
        },
        expected_effects: effects,
        lease_chain,
        nonce: env.nonce.clone(),
        expires_at_ms,
    })
}

/// Parse a host `scheme://host:port` destination into the frozen typed shape.
fn parse_network_dest(dest: &str) -> Result<FrozenNet, KernelError> {
    let (scheme, rest) = dest
        .split_once("://")
        .ok_or_else(|| EnvelopeError::Deserialize(format!("bad network destination '{dest}'")))?;
    // `rsplit_once` keeps the port split correct for bracketed IPv6 hosts.
    let (host, port) = rest
        .rsplit_once(':')
        .ok_or_else(|| EnvelopeError::Deserialize(format!("bad network destination '{dest}'")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| EnvelopeError::Deserialize(format!("bad network destination '{dest}'")))?;
    if scheme.is_empty() || host.is_empty() {
        return Err(EnvelopeError::Deserialize(format!("bad network destination '{dest}'")).into());
    }
    Ok(FrozenNet {
        scheme: scheme.to_string(),
        host: host.to_string(),
        port,
    })
}

/// Convert a frozen decision back to the host shape, binding it to the
/// host envelope's digest so [`PolicyDecision::bind`] keeps working.
pub(crate) fn to_host_decision(
    frozen: &FrozenDecision,
    envelope: &ActionEnvelope,
) -> Result<PolicyDecision, KernelError> {
    if frozen.version != pi_boundary::POLICY_DECISION_VERSION {
        return Err(KernelError::Protocol(
            "unsupported kernel policy decision version".into(),
        ));
    }
    let action_digest = envelope.digest()?;
    let decision = match &frozen.outcome {
        DecisionOutcome::Allow { obligations } => {
            // The leaf lease (chain head) is what authorized this action.
            let lease_id = envelope
                .lease_chain
                .first()
                .cloned()
                .unwrap_or_else(|| "none".to_string());
            Decision::Allow {
                lease_id,
                obligations: obligations.iter().map(to_host_obligation).collect(),
            }
        }
        DecisionOutcome::Deny { reason } => Decision::Deny {
            reason: format!("{}: {}", reason.code, reason.detail),
        },
        DecisionOutcome::PendingApproval {
            approval_id,
            reason,
        } => Decision::PendingApproval {
            approval_request_id: approval_id.clone(),
            reason: reason.clone(),
        },
    };
    Ok(PolicyDecision {
        protocol_version: HOST_DECISION_VERSION,
        action_digest,
        decision,
        decided_at: now_rfc3339(),
    })
}

fn to_host_obligation(ob: &FrozenObligation) -> Obligation {
    match ob {
        FrozenObligation::TruncateOutput { max_bytes } => Obligation {
            kind: "truncate_output".to_string(),
            params: serde_json::json!({ "max_bytes": max_bytes }),
        },
        FrozenObligation::RedactSecrets => Obligation {
            kind: "redact_secrets".to_string(),
            params: serde_json::json!({}),
        },
        FrozenObligation::RequireSandboxProfile { profile } => Obligation {
            kind: "require_sandbox_profile".to_string(),
            params: serde_json::json!({ "profile": profile }),
        },
        FrozenObligation::SettleBudget {
            reservation_id,
            lease_id,
            action_id,
        } => Obligation {
            kind: "settle_budget".to_string(),
            params: serde_json::json!({
                "reservation_id": reservation_id,
                "lease_id": lease_id,
                "action_id": action_id,
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_client::{ACTION_ENVELOPE_VERSION, ResourceSet, ToolRef, deadline_rfc3339};

    fn envelope_with_effects(effects: Vec<EffectClass>) -> ActionEnvelope {
        ActionEnvelope {
            protocol_version: ACTION_ENVELOPE_VERSION,
            action_id: uuid::Uuid::new_v4().to_string(),
            session_id: "ed25519:test-session".to_string(),
            tool: ToolRef {
                name: "bct.test_tool".to_string(),
                version: "1.0.0".to_string(),
            },
            arguments: serde_json::json!({}),
            input_hashes: vec![],
            resources: ResourceSet {
                paths: vec![],
                hosts: vec![],
                secret_refs: vec![],
            },
            lease_chain: vec![],
            nonce: uuid::Uuid::new_v4().to_string(),
            expires_at: deadline_rfc3339(600),
            expected_effects: effects,
        }
    }

    #[test]
    fn host_and_kernel_fixture_digests_remain_distinct_and_exact() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/host_action.v2.json")).unwrap();
        let host: ActionEnvelope =
            serde_json::from_value(fixture["request"]["envelope"].clone()).unwrap();
        assert_eq!(host.digest().unwrap(), fixture["host_action_digest"]);
        let core = to_frozen_envelope(&host).unwrap();
        assert_eq!(
            serde_json::to_value(&core).unwrap(),
            fixture["kernel_envelope"]
        );
        assert_eq!(core.digest().unwrap(), fixture["kernel_action_digest"]);
        assert_ne!(core.digest().unwrap(), host.digest().unwrap());
        let policy = to_host_decision(&FrozenDecision::allow(vec![]), &host).unwrap();
        policy.bind(&host).unwrap();
        assert_eq!(
            policy.action_digest,
            fixture["host_policy"]["action_digest"]
        );
    }

    #[test]
    fn conversion_never_upgrades_a_stale_or_future_policy_version() {
        let envelope = envelope_with_effects(vec![EffectClass::Read]);
        let decision = FrozenDecision::allow(vec![]);
        to_host_decision(&decision, &envelope)
            .unwrap()
            .bind(&envelope)
            .unwrap();
        for version in [0, 1, 2, 4, u32::MAX] {
            let mut invalid = decision.clone();
            invalid.version = version;
            assert!(to_host_decision(&invalid, &envelope).is_err());
        }
    }

    #[test]
    fn rejects_effects_without_frozen_counterpart() {
        // `SecretUse` and `MessageSend` cannot be expressed to the frozen
        // kernel; silently discarding them would let the kernel authorize
        // an action on a lease that never granted the effect.
        for class in [EffectClass::SecretUse, EffectClass::MessageSend] {
            let error = to_frozen_envelope(&envelope_with_effects(vec![class]))
                .expect_err("unrepresentable effect must fail closed");
            assert!(
                matches!(
                    error,
                    KernelError::BadEnvelope(EnvelopeError::UnsupportedEffect(_))
                ),
                "unexpected error for {class:?}: {error:?}"
            );
        }
    }

    #[test]
    fn representable_effects_still_convert() {
        let frozen = to_frozen_envelope(&envelope_with_effects(vec![
            EffectClass::Read,
            EffectClass::Write,
            EffectClass::Network,
            EffectClass::Execute,
        ]))
        .expect("representable effects must convert");
        assert!(frozen.expected_effects.file_read);
        assert!(frozen.expected_effects.file_write);
        assert!(frozen.expected_effects.network_egress);
        assert!(frozen.expected_effects.process_spawn);
    }
}
