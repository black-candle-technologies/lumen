use lumen_core::action::{ActionEnvelope, ActionId, ActionKind, CanonicalValue, RunId};
use lumen_core::capability::{
    Capability, CapabilityName, CapabilitySet, EffectiveCapabilities, ResourceScope, WorkspacePath,
};
use lumen_core::identity::{ComponentId, PrincipalId, WorkspaceId};
use lumen_core::policy::{DenialReason, Policy, PolicyDecision};
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

fn file_capability(path: &str) -> Capability {
    Capability::new(
        CapabilityName::FsRead,
        ResourceScope::path(
            workspace_id(),
            WorkspacePath::parse(path).expect("valid path"),
        ),
    )
}

fn file_write_capability(path: &str) -> Capability {
    Capability::new(
        CapabilityName::FsWrite,
        ResourceScope::path(
            workspace_id(),
            WorkspacePath::parse(path).expect("valid path"),
        ),
    )
}

fn action(arguments: CanonicalValue, capabilities: Vec<Capability>) -> ActionEnvelope {
    ActionEnvelope::new(
        action_id(),
        run_id(),
        workspace_id(),
        PrincipalId::new("local", "riley").expect("valid principal"),
        ComponentId::new("builtin.filesystem").expect("valid component"),
        ActionKind::new("filesystem.read").expect("valid action kind"),
        arguments,
        capabilities,
    )
}

#[test]
fn action_fingerprint_is_canonical() {
    let first = action(
        CanonicalValue::object([
            ("path", CanonicalValue::from("src/lib.rs")),
            ("line_limit", CanonicalValue::from(200_i64)),
        ]),
        vec![
            file_capability("src/lib.rs"),
            Capability::new(
                CapabilityName::FsRead,
                ResourceScope::workspace(workspace_id()),
            ),
        ],
    );
    let second = action(
        CanonicalValue::object([
            ("line_limit", CanonicalValue::from(200_i64)),
            ("path", CanonicalValue::from("src/lib.rs")),
        ]),
        vec![
            Capability::new(
                CapabilityName::FsRead,
                ResourceScope::workspace(workspace_id()),
            ),
            file_capability("src/lib.rs"),
        ],
    );

    assert_eq!(first.fingerprint(), second.fingerprint());
    assert_eq!(first.fingerprint().as_str().len(), 64);
}

#[test]
fn action_fingerprint_changes_when_arguments_change() {
    let first = action(
        CanonicalValue::object([("path", CanonicalValue::from("src/lib.rs"))]),
        vec![file_capability("src/lib.rs")],
    );
    let second = action(
        CanonicalValue::object([("path", CanonicalValue::from("src/main.rs"))]),
        vec![file_capability("src/lib.rs")],
    );

    assert_ne!(first.fingerprint(), second.fingerprint());
}

#[test]
fn workspace_paths_reject_ambiguous_or_escaping_forms() {
    for invalid in [
        "/etc/passwd",
        "../secrets",
        "src/../secrets",
        "src/./lib.rs",
        "src//lib.rs",
        "src\\lib.rs",
    ] {
        assert!(
            WorkspacePath::parse(invalid).is_err(),
            "{invalid:?} must not be accepted"
        );
    }

    assert_eq!(
        WorkspacePath::parse("src/lib.rs")
            .expect("canonical path")
            .as_str(),
        "src/lib.rs"
    );
}

#[test]
fn path_scope_contains_only_segment_descendants_in_the_same_workspace() {
    let root = ResourceScope::path(
        workspace_id(),
        WorkspacePath::parse("src").expect("valid path"),
    );
    let descendant = ResourceScope::path(
        workspace_id(),
        WorkspacePath::parse("src/lib.rs").expect("valid path"),
    );
    let sibling_prefix = ResourceScope::path(
        workspace_id(),
        WorkspacePath::parse("src-generated/output.rs").expect("valid path"),
    );

    assert!(root.contains(&descendant));
    assert!(!root.contains(&sibling_prefix));
}

#[test]
fn effective_capabilities_are_the_intersection_of_all_layers() {
    let actor = CapabilitySet::new([Capability::new(
        CapabilityName::FsRead,
        ResourceScope::workspace(workspace_id()),
    )]);
    let plugin = CapabilitySet::new([Capability::new(
        CapabilityName::FsRead,
        ResourceScope::path(
            workspace_id(),
            WorkspacePath::parse("src").expect("valid path"),
        ),
    )]);
    let effective = EffectiveCapabilities::new([actor, plugin]);

    assert!(effective.allows(&file_capability("src/lib.rs")));
    assert!(!effective.allows(&file_capability("Cargo.toml")));
    assert!(!EffectiveCapabilities::default().allows(&file_capability("src/lib.rs")));
}

#[test]
fn policy_denies_missing_capabilities_by_default() {
    let action = action(
        CanonicalValue::object([("path", CanonicalValue::from("src/lib.rs"))]),
        vec![file_capability("src/lib.rs")],
    );

    assert_eq!(
        Policy::default().evaluate(&action, &EffectiveCapabilities::default()),
        PolicyDecision::Deny(DenialReason::MissingCapability(file_capability(
            "src/lib.rs"
        )))
    );
}

#[test]
fn policy_denies_actions_without_declared_capabilities() {
    let action = action(
        CanonicalValue::object([] as [(&str, CanonicalValue); 0]),
        vec![],
    );

    assert_eq!(
        Policy::default().evaluate(&action, &EffectiveCapabilities::default()),
        PolicyDecision::Deny(DenialReason::NoCapabilitiesDeclared)
    );
}

#[test]
fn default_policy_allows_reads_but_requires_approval_for_processes() {
    let read_capability = file_capability("src/lib.rs");
    let read_action = action(
        CanonicalValue::object([("path", CanonicalValue::from("src/lib.rs"))]),
        vec![read_capability.clone()],
    );
    let read_effective = EffectiveCapabilities::new([CapabilitySet::new([read_capability])]);

    assert_eq!(
        Policy::default().evaluate(&read_action, &read_effective),
        PolicyDecision::Allow
    );

    let process_capability = Capability::new(
        CapabilityName::ProcessSpawn,
        ResourceScope::exact("executable", "/usr/bin/git").expect("valid exact scope"),
    );
    let process_action = action(
        CanonicalValue::object([("program", CanonicalValue::from("/usr/bin/git"))]),
        vec![process_capability.clone()],
    );
    let process_effective = EffectiveCapabilities::new([CapabilitySet::new([process_capability])]);

    assert_eq!(
        Policy::default().evaluate(&process_action, &process_effective),
        PolicyDecision::RequireApproval
    );
}

#[test]
fn default_policy_requires_approval_for_exactly_scoped_file_writes() {
    let required = file_write_capability("notes/today.md");
    let write = action(
        CanonicalValue::object([
            ("path", CanonicalValue::from("notes/today.md")),
            ("content", CanonicalValue::from("replacement")),
        ]),
        vec![required.clone()],
    );
    let exact = EffectiveCapabilities::new([CapabilitySet::new([required.clone()])]);
    let sibling = EffectiveCapabilities::new([CapabilitySet::new([file_write_capability(
        "notes/tomorrow.md",
    )])]);

    assert_eq!(
        Policy::default().evaluate(&write, &exact),
        PolicyDecision::RequireApproval
    );
    assert_eq!(
        Policy::default().evaluate(&write, &sibling),
        PolicyDecision::Deny(DenialReason::MissingCapability(required))
    );
}
