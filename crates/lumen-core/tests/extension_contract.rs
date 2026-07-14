use lumen_core::{
    action::{ActionEnvelope, ActionId, ActionKind, CanonicalValue, RunId},
    capability::{Capability, CapabilityName, CapabilitySet, EffectiveCapabilities, ResourceScope},
    extension::{
        ExtensionFailure, ExtensionFailureClass, ExtensionInvocationLimits, ExtensionProvenance,
        ExtensionResponse, PluginComponentId, PluginId, PluginManifest, PluginRuntime,
        PluginVersion, ProtocolVersion, Sha256Digest, canonical_grant_set_digest,
    },
    identity::{ComponentId, PrincipalId, WorkspaceId},
    policy::{Policy, PolicyDecision},
};
use uuid::Uuid;

fn workspace_id() -> WorkspaceId {
    WorkspaceId::from_uuid(
        Uuid::parse_str("26db5a31-94f0-4e92-a9c9-4cdf19d71c31").expect("valid UUID"),
    )
}

fn action_id() -> ActionId {
    ActionId::from_uuid(
        Uuid::parse_str("63908e55-6719-48c4-b43b-95f52264703f").expect("valid UUID"),
    )
}

fn run_id() -> RunId {
    RunId::from_uuid(Uuid::parse_str("f553a2c1-ee86-4c66-af7f-8e913a08ff17").expect("valid UUID"))
}

fn digest(byte: char) -> Sha256Digest {
    Sha256Digest::parse(byte.to_string().repeat(64)).expect("valid digest")
}

fn provenance() -> ExtensionProvenance {
    ExtensionProvenance::new(
        PluginId::parse("dev.example.git-tools").expect("plugin ID"),
        PluginVersion::parse("1.2.3").expect("plugin version"),
        PluginComponentId::parse("status").expect("component ID"),
        PluginRuntime::WasmComponent,
        digest('1'),
        digest('2'),
        digest('3'),
        digest('4'),
        digest('5'),
        ProtocolVersion::new(1).expect("protocol version"),
        Some(action_id()),
    )
}

fn invocation(provenance: ExtensionProvenance, input: CanonicalValue) -> ActionEnvelope {
    let scope = ResourceScope::exact("plugin_component", provenance.resource_key())
        .expect("exact plugin scope");
    ActionEnvelope::new(
        action_id(),
        run_id(),
        workspace_id(),
        PrincipalId::new("local", "riley").expect("principal"),
        ComponentId::new("runtime.extensions").expect("requesting component"),
        ActionKind::new("plugin.invoke").expect("action kind"),
        CanonicalValue::object([("input", input)]),
        vec![Capability::new(CapabilityName::PluginInvoke, scope)],
    )
    .with_extension_provenance(provenance)
}

#[test]
fn extension_identifiers_versions_and_digests_are_canonical() {
    assert_eq!(
        PluginId::parse("dev.example.git-tools")
            .expect("valid plugin ID")
            .as_str(),
        "dev.example.git-tools"
    );
    for invalid in [
        "example",
        "Example.tools.plugin",
        "dev..tools.plugin",
        "dev.example.-tools",
        "dev/example/tools",
    ] {
        assert!(PluginId::parse(invalid).is_err(), "accepted {invalid:?}");
    }

    assert_eq!(
        PluginComponentId::parse("git-status")
            .expect("valid component ID")
            .as_str(),
        "git-status"
    );
    assert!(PluginComponentId::parse("Git Status").is_err());

    assert_eq!(
        PluginVersion::parse("1.2.3-alpha.1+local")
            .expect("canonical semantic version")
            .as_str(),
        "1.2.3-alpha.1+local"
    );
    for invalid in ["1", "1.2", "v1.2.3", "01.2.3"] {
        assert!(
            PluginVersion::parse(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }

    assert!(Sha256Digest::parse("a".repeat(64)).is_ok());
    assert!(Sha256Digest::parse("A".repeat(64)).is_err());
    assert!(Sha256Digest::parse("a".repeat(63)).is_err());
    assert!(ProtocolVersion::new(0).is_err());
}

#[test]
fn plugin_invocation_scope_is_exact_to_version_and_component() {
    let provenance = provenance();
    assert_eq!(
        provenance.resource_key(),
        "dev.example.git-tools@1.2.3#status"
    );
    let action = invocation(provenance.clone(), CanonicalValue::from("{}"));
    let granted = action.required_capabilities()[0].clone();
    let capabilities = EffectiveCapabilities::new([CapabilitySet::new([granted])]);

    assert_eq!(
        Policy::default().evaluate(&action, &capabilities),
        PolicyDecision::Allow
    );

    let other_component = Capability::new(
        CapabilityName::PluginInvoke,
        ResourceScope::exact("plugin_component", "dev.example.git-tools@1.2.3#commit")
            .expect("scope"),
    );
    assert!(!CapabilitySet::new([other_component]).allows(&action.required_capabilities()[0]));
}

#[test]
fn authority_changing_plugin_capabilities_require_approval_by_default() {
    for name in [
        CapabilityName::PluginInstall,
        CapabilityName::PluginEnable,
        CapabilityName::PluginCapabilitiesSet,
        CapabilityName::PluginSettingsSet,
        CapabilityName::PluginQuarantineRelease,
    ] {
        let required = Capability::new(
            name,
            ResourceScope::exact("plugin", "dev.example.git-tools@1.2.3").expect("scope"),
        );
        let action = ActionEnvelope::new(
            action_id(),
            run_id(),
            workspace_id(),
            PrincipalId::new("local", "admin").expect("principal"),
            ComponentId::new("runtime.extensions").expect("component"),
            ActionKind::new("plugin.admin").expect("kind"),
            CanonicalValue::object([] as [(&str, CanonicalValue); 0]),
            vec![required.clone()],
        );
        let effective = EffectiveCapabilities::new([CapabilitySet::new([required])]);
        assert_eq!(
            Policy::default().evaluate(&action, &effective),
            PolicyDecision::RequireApproval,
            "{name:?} must require approval"
        );
    }
}

#[test]
fn authenticated_plugin_disablement_is_allowed_after_capability_validation() {
    let required = Capability::new(
        CapabilityName::PluginEnable,
        ResourceScope::exact("plugin", "dev.example.git-tools@1.2.3").expect("scope"),
    );
    let action = ActionEnvelope::new(
        action_id(),
        run_id(),
        workspace_id(),
        PrincipalId::new("local", "admin").expect("principal"),
        ComponentId::new("runtime.extensions").expect("component"),
        ActionKind::new("plugin.disable").expect("kind"),
        CanonicalValue::object([] as [(&str, CanonicalValue); 0]),
        vec![required.clone()],
    );
    let effective = EffectiveCapabilities::new([CapabilitySet::new([required])]);
    assert_eq!(
        Policy::default().evaluate(&action, &effective),
        PolicyDecision::Allow
    );
}

#[test]
fn extension_provenance_and_input_bind_the_action_fingerprint() {
    let original = invocation(provenance(), CanonicalValue::from("first"));
    let changed_input = invocation(provenance(), CanonicalValue::from("second"));
    assert_ne!(original.fingerprint(), changed_input.fingerprint());

    let mut changed_settings = provenance();
    changed_settings = changed_settings.with_settings_digest(digest('a'));
    assert_ne!(
        original.fingerprint(),
        invocation(changed_settings, CanonicalValue::from("first")).fingerprint()
    );

    let mut changed_grants = provenance();
    changed_grants = changed_grants.with_grant_set_digest(digest('b'));
    assert_ne!(
        original.fingerprint(),
        invocation(changed_grants, CanonicalValue::from("first")).fingerprint()
    );
}

#[test]
fn diagnostic_text_is_not_part_of_authoritative_provenance() {
    let original = provenance();
    let action = invocation(original.clone(), CanonicalValue::from("input"));
    let encoded = serde_json::to_value(&action).expect("serialize action");

    assert_eq!(
        encoded["extension_provenance"]["plugin_id"],
        "dev.example.git-tools"
    );
    assert!(encoded.get("diagnostics").is_none());
    assert_eq!(
        action.fingerprint(),
        invocation(original, CanonicalValue::from("input")).fingerprint()
    );
}

#[test]
fn manifest_is_strict_and_paths_are_canonical() {
    let valid = r#"
manifest_version = 1
id = "dev.example.git-tools"
name = "Git Tools"
version = "1.2.3"
description = "Read Git status"

[runtime]
type = "wasm-component"
entrypoint = "plugin.wasm"
protocol_version = 1

[[components]]
id = "status"
kind = "tool"
description = "Read status"
input_schema = "schemas/input.json"
output_schema = "schemas/output.json"
action_kinds = ["filesystem.read"]

[[components.capabilities]]
name = "fs.read"
scope = "workspace"

[settings]
schema = "schemas/settings.json"

[integrity]
algorithm = "sha256"
artifact = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;
    let manifest: PluginManifest = toml::from_str(valid).expect("strict valid manifest");
    assert_eq!(manifest.id().as_str(), "dev.example.git-tools");
    assert_eq!(manifest.runtime().entrypoint().as_str(), "plugin.wasm");
    assert_eq!(manifest.components().len(), 1);

    let unknown = valid.replace(
        "manifest_version = 1",
        "manifest_version = 1\nunknown = true",
    );
    assert!(toml::from_str::<PluginManifest>(&unknown).is_err());
    let traversal = valid.replace("plugin.wasm", "../plugin.wasm");
    assert!(toml::from_str::<PluginManifest>(&traversal).is_err());
    let duplicate = valid.replace(
        "[settings]",
        "[[components]]\nid = \"status\"\nkind = \"tool\"\ndescription = \"duplicate\"\ninput_schema = \"schemas/input.json\"\noutput_schema = \"schemas/output.json\"\n[settings]",
    );
    assert!(toml::from_str::<PluginManifest>(&duplicate).is_err());
}

#[test]
fn invocation_limits_and_responses_are_typed_and_bounded() {
    let limits = ExtensionInvocationLimits::new(1_000, 64 * 1024, 100_000, 32 * 1024 * 1024)
        .expect("valid invocation limits");
    assert_eq!(limits.deadline_millis(), 1_000);
    assert!(ExtensionInvocationLimits::new(0, 1, 1, 1).is_err());

    let result = ExtensionResponse::result(CanonicalValue::from("ok"));
    assert!(matches!(result, ExtensionResponse::Result { .. }));
    let proposal = ExtensionResponse::proposal(
        ActionKind::new("filesystem.read").expect("kind"),
        CanonicalValue::object([("path", CanonicalValue::from("README.md"))]),
    );
    assert!(matches!(proposal, ExtensionResponse::Proposal { .. }));
    let failure = ExtensionFailure::new(ExtensionFailureClass::PluginFault, "invalid input")
        .expect("bounded failure");
    assert!(matches!(
        ExtensionResponse::failure(failure),
        ExtensionResponse::Failure { .. }
    ));
    assert!(ExtensionFailure::new(ExtensionFailureClass::PluginFault, "x".repeat(4097)).is_err());
}

#[test]
fn every_invocation_and_effect_authority_layer_must_allow_the_action() {
    let required = Capability::new(
        CapabilityName::FsRead,
        ResourceScope::exact("workspace_file", "src/lib.rs").expect("scope"),
    );
    let broad = Capability::new(
        CapabilityName::FsRead,
        ResourceScope::exact("workspace_file", "src/lib.rs").expect("scope"),
    );
    let layers = (0..8).map(|_| CapabilitySet::new([broad.clone()]));
    let effective = EffectiveCapabilities::new(layers);
    assert!(effective.allows(&required));
    let denied = EffectiveCapabilities::new(
        (0..7)
            .map(|_| CapabilitySet::new([broad.clone()]))
            .chain(std::iter::once(CapabilitySet::default())),
    );
    assert!(!denied.allows(&required));

    let digest = canonical_grant_set_digest(&[required.clone(), required]);
    let single = canonical_grant_set_digest(&[broad]);
    assert_eq!(digest, single, "grant hashing sorts and deduplicates");
}
