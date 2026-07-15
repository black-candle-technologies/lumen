use lumen_core::{
    action::{ActionEnvelope, ActionId, ActionKind, CanonicalValue, RunId},
    capability::{Capability, CapabilityName, ResourceScope},
    egress::{
        DataClass, DestinationScope, EndpointClass, ProviderEgressPolicy, ProviderId,
        ProviderRoute, RoutingDecision, RoutingFailure, select_model_provider,
    },
    identity::{
        ChannelDestination, ComponentId, ExternalChannelIdentity, PrincipalId, WorkspaceId,
    },
};
use std::collections::BTreeSet;
use uuid::Uuid;

fn workspace_id() -> WorkspaceId {
    WorkspaceId::from_uuid(
        Uuid::parse_str("26db5a31-94f0-4e92-a9c9-4cdf19d71c31").expect("valid UUID"),
    )
}

fn action_id(value: &str) -> ActionId {
    ActionId::from_uuid(Uuid::parse_str(value).expect("valid UUID"))
}

fn run_id() -> RunId {
    RunId::from_uuid(Uuid::parse_str("f553a2c1-ee86-4c66-af7f-8e913a08ff17").expect("valid UUID"))
}

fn classes(values: impl IntoIterator<Item = DataClass>) -> BTreeSet<DataClass> {
    values.into_iter().collect()
}

#[test]
fn data_classes_are_ordered_by_egress_risk_and_secret_is_never_remote() {
    assert!(DataClass::Workspace > DataClass::Public);
    assert!(DataClass::Sensitive > DataClass::Workspace);
    assert!(DataClass::Secret > DataClass::Sensitive);

    assert!(DataClass::Public.may_leave_runtime());
    assert!(DataClass::Workspace.may_leave_runtime());
    assert!(DataClass::Sensitive.may_leave_runtime());
    assert!(!DataClass::Secret.may_leave_runtime());
}

#[test]
fn provider_policy_rejects_secret_data_class() {
    let provider = ProviderId::parse("openai-compatible").expect("provider ID");

    let policy =
        ProviderEgressPolicy::new(provider.clone(), [DataClass::Public, DataClass::Workspace])
            .expect("non-secret policy");
    assert_eq!(policy.provider(), &provider);
    assert!(policy.allows(DataClass::Public));
    assert!(policy.allows(DataClass::Workspace));
    assert!(!policy.allows(DataClass::Sensitive));

    assert!(ProviderEgressPolicy::new(provider, [DataClass::Secret]).is_err());
}

#[test]
fn destination_scopes_are_canonical_https_origins_or_paths() {
    let origin = DestinationScope::parse("https://API.example.com").expect("origin");
    assert_eq!(origin.as_str(), "https://api.example.com/");

    let path = DestinationScope::parse("https://api.example.com/v1/chat").expect("path");
    assert_eq!(path.as_str(), "https://api.example.com/v1/chat");

    assert!(DestinationScope::parse("http://api.example.com").is_err());
    assert!(DestinationScope::parse("https://api.example.com/#fragment").is_err());
    assert!(DestinationScope::parse("https://api.example.com/?token=secret").is_err());
}

#[test]
fn network_and_channel_capabilities_are_exactly_scoped() {
    let api = ResourceScope::exact(
        "destination",
        DestinationScope::parse("https://api.example.com/v1")
            .unwrap()
            .as_str(),
    )
    .expect("destination scope");
    let channel =
        ResourceScope::exact("channel", "slack:T123:C456").expect("channel destination scope");

    assert_eq!(CapabilityName::NetworkEgress.as_str(), "network.egress");
    assert_eq!(CapabilityName::ChannelSend.as_str(), "channel.send");
    assert_eq!(
        CapabilityName::parse("network.egress"),
        Some(CapabilityName::NetworkEgress)
    );
    assert_eq!(
        CapabilityName::parse("channel.send"),
        Some(CapabilityName::ChannelSend)
    );

    let first = ActionEnvelope::new(
        action_id("63908e55-6719-48c4-b43b-95f52264703f"),
        run_id(),
        workspace_id(),
        PrincipalId::new("local", "operator").unwrap(),
        ComponentId::new("builtin.network").unwrap(),
        ActionKind::new("network.request").unwrap(),
        CanonicalValue::object([("url", CanonicalValue::from("https://api.example.com/v1"))]),
        vec![Capability::new(CapabilityName::NetworkEgress, api.clone())],
    );
    let second = ActionEnvelope::new(
        action_id("63908e55-6719-48c4-b43b-95f52264703f"),
        run_id(),
        workspace_id(),
        PrincipalId::new("local", "operator").unwrap(),
        ComponentId::new("builtin.network").unwrap(),
        ActionKind::new("network.request").unwrap(),
        CanonicalValue::object([("url", CanonicalValue::from("https://api.example.com/v1"))]),
        vec![Capability::new(CapabilityName::ChannelSend, channel)],
    );

    assert_ne!(first.fingerprint(), second.fingerprint());
}

#[test]
fn external_channel_identity_is_canonical_and_channel_scoped() {
    let identity =
        ExternalChannelIdentity::new("slack", "T123", "C456", "U789").expect("external identity");
    let destination = ChannelDestination::new(
        identity.provider(),
        identity.external_workspace_id(),
        identity.channel_id(),
    )
    .expect("channel destination");

    assert_eq!(identity.provider(), "slack");
    assert_eq!(identity.external_workspace_id(), "T123");
    assert_eq!(identity.channel_id(), "C456");
    assert_eq!(identity.external_user_id(), "U789");
    assert_eq!(destination.as_scope_value(), "slack:T123:C456");
    assert_eq!(
        ResourceScope::exact("channel", destination.as_scope_value()).expect("scope"),
        ResourceScope::Exact {
            resource_type: "channel".to_owned(),
            value: "slack:T123:C456".to_owned(),
        }
    );

    assert!(ExternalChannelIdentity::new("slack", " T123", "C456", "U789").is_err());
    assert!(ExternalChannelIdentity::new("slack", "T123", "C456", "U\n789").is_err());
    assert!(ChannelDestination::new("slack", "T123", "").is_err());
}

#[test]
fn routing_prefers_enabled_local_providers_without_egress() {
    let local = ProviderRoute::new(
        ProviderId::parse("local-llama").unwrap(),
        EndpointClass::Local,
        true,
        [
            DataClass::Public,
            DataClass::Workspace,
            DataClass::Sensitive,
        ],
        None,
        10,
    )
    .unwrap();
    let remote = ProviderRoute::new(
        ProviderId::parse("remote-compatible").unwrap(),
        EndpointClass::Remote,
        true,
        [DataClass::Public],
        Some(classes([DataClass::Public])),
        1,
    )
    .unwrap();

    let decision = select_model_provider(DataClass::Public, [remote, local]).unwrap();

    assert_eq!(decision.provider().as_str(), "local-llama");
    assert!(!decision.egress_occurred());
    assert_eq!(
        decision,
        RoutingDecision::local(ProviderId::parse("local-llama").unwrap())
    );
}

#[test]
fn routing_denies_remote_without_workspace_policy() {
    let remote = ProviderRoute::new(
        ProviderId::parse("remote-compatible").unwrap(),
        EndpointClass::Remote,
        true,
        [DataClass::Public],
        None,
        1,
    )
    .unwrap();

    assert_eq!(
        select_model_provider(DataClass::Public, [remote]).unwrap_err(),
        RoutingFailure::RemoteEgressDenied
    );
}

#[test]
fn routing_requires_provider_and_workspace_policy_intersection() {
    let denied = ProviderRoute::new(
        ProviderId::parse("remote-compatible").unwrap(),
        EndpointClass::Remote,
        true,
        [DataClass::Public],
        Some(classes([DataClass::Workspace])),
        1,
    )
    .unwrap();
    assert_eq!(
        select_model_provider(DataClass::Public, [denied]).unwrap_err(),
        RoutingFailure::RemoteEgressDenied
    );

    let allowed = ProviderRoute::new(
        ProviderId::parse("remote-compatible").unwrap(),
        EndpointClass::Remote,
        true,
        [DataClass::Public, DataClass::Workspace],
        Some(classes([DataClass::Workspace])),
        1,
    )
    .unwrap();
    let decision = select_model_provider(DataClass::Workspace, [allowed]).unwrap();

    assert_eq!(decision.provider().as_str(), "remote-compatible");
    assert!(decision.egress_occurred());
}

#[test]
fn routing_never_sends_secret_or_uses_disabled_provider() {
    let disabled = ProviderRoute::new(
        ProviderId::parse("remote-compatible").unwrap(),
        EndpointClass::Remote,
        false,
        [DataClass::Public],
        Some(classes([DataClass::Public])),
        1,
    )
    .unwrap();

    assert_eq!(
        select_model_provider(DataClass::Public, [disabled]).unwrap_err(),
        RoutingFailure::NoEligibleProvider
    );

    let secret_route = ProviderRoute::new(
        ProviderId::parse("local-llama").unwrap(),
        EndpointClass::Local,
        true,
        [
            DataClass::Public,
            DataClass::Workspace,
            DataClass::Sensitive,
        ],
        None,
        1,
    )
    .unwrap();
    assert_eq!(
        select_model_provider(DataClass::Secret, [secret_route]).unwrap_err(),
        RoutingFailure::SecretDataClass
    );
}
