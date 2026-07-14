use std::{fs, path::Path};

use lumen_integrations::{
    extension_package::{PackageIdentity, PackageLimits, PackageStageError, PackageStager},
    extension_schema::{BoundedSchema, SchemaLimits, merge_scoped_settings},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn write_package(root: &Path, artifact: &[u8]) {
    fs::create_dir_all(root.join("schemas")).expect("schema directory");
    fs::write(root.join("plugin.wasm"), artifact).expect("artifact");
    fs::write(
        root.join("schemas/input.json"),
        br#"{"type":"object","properties":{"path":{"type":"string","maxLength":128}},"required":["path"],"additionalProperties":false}"#,
    )
    .expect("input schema");
    fs::write(
        root.join("schemas/output.json"),
        br#"{"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"],"additionalProperties":false}"#,
    )
    .expect("output schema");
    fs::write(
        root.join("schemas/settings.json"),
        br#"{"type":"object","properties":{"prefix":{"type":"string","maxLength":32}},"additionalProperties":false}"#,
    )
    .expect("settings schema");
    fs::write(root.join("README.txt"), "review notes").expect("extra bounded file");
    let digest = format!("{:x}", Sha256::digest(artifact));
    fs::write(
        root.join("lumen-plugin.toml"),
        format!(
            r#"manifest_version = 1
id = "dev.example.git-tools"
name = "Git Tools"
version = "1.2.3"
description = "Read status"

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
artifact = "{digest}"
"#
        ),
    )
    .expect("manifest");
}

#[test]
fn stages_a_deterministic_verified_copy_with_all_regular_files() {
    let first = tempdir().expect("source");
    let second = tempdir().expect("source");
    let quarantine = tempdir().expect("quarantine");
    write_package(first.path(), b"component bytes");
    write_package(second.path(), b"component bytes");
    let stager = PackageStager::new(PackageLimits::default());

    let staged = stager
        .stage(first.path(), quarantine.path())
        .expect("valid package stages");
    let duplicate = stager
        .stage(second.path(), quarantine.path())
        .expect("same bytes stage idempotently");

    assert_eq!(staged.package_digest(), duplicate.package_digest());
    assert_eq!(staged.files().len(), 6);
    assert!(staged.files().contains_key("README.txt"));
    assert!(
        staged
            .quarantine_path()
            .starts_with(fs::canonicalize(quarantine.path()).expect("canonical quarantine"))
    );
    assert_eq!(
        fs::read(staged.quarantine_path().join("plugin.wasm")).expect("staged artifact"),
        b"component bytes"
    );
    assert_eq!(
        staged.artifact_digest(),
        staged.manifest().integrity().artifact()
    );
}

#[cfg(unix)]
#[test]
fn rejects_symlinks_and_hard_links() {
    use std::os::unix::fs::symlink;

    let quarantine = tempdir().expect("quarantine");
    let symlinked = tempdir().expect("source");
    write_package(symlinked.path(), b"component");
    symlink("README.txt", symlinked.path().join("alias")).expect("symlink");
    assert!(matches!(
        PackageStager::default().stage(symlinked.path(), quarantine.path()),
        Err(PackageStageError::UnsupportedFile(_))
    ));

    let hardlinked = tempdir().expect("source");
    write_package(hardlinked.path(), b"component");
    fs::hard_link(
        hardlinked.path().join("README.txt"),
        hardlinked.path().join("copy.txt"),
    )
    .expect("hard link");
    assert!(matches!(
        PackageStager::default().stage(hardlinked.path(), quarantine.path()),
        Err(PackageStageError::UnsupportedFile(_))
    ));

    let special = tempdir().expect("source");
    write_package(special.path(), b"component");
    nix::unistd::mkfifo(
        &special.path().join("plugin.pipe"),
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .expect("FIFO");
    assert!(matches!(
        PackageStager::default().stage(special.path(), quarantine.path()),
        Err(PackageStageError::UnsupportedFile(_))
    ));
}

#[test]
fn rejects_invalid_manifest_artifact_and_package_bounds() {
    let quarantine = tempdir().expect("quarantine");
    let source = tempdir().expect("source");
    write_package(source.path(), b"component");
    fs::write(source.path().join("plugin.wasm"), b"substituted").expect("mutate artifact");
    assert!(matches!(
        PackageStager::default().stage(source.path(), quarantine.path()),
        Err(PackageStageError::ArtifactDigestMismatch)
    ));

    write_package(source.path(), b"component");
    let limits = PackageLimits::new(32, 8, 1_024, SchemaLimits::default()).expect("limits");
    assert!(matches!(
        PackageStager::new(limits).stage(source.path(), quarantine.path()),
        Err(PackageStageError::FileTooLarge(_))
    ));

    write_package(source.path(), b"component");
    let manifest_path = source.path().join("lumen-plugin.toml");
    let manifest = fs::read_to_string(&manifest_path).expect("manifest");
    fs::write(
        &manifest_path,
        manifest.replace(
            "manifest_version = 1",
            "manifest_version = 1\nunknown = true",
        ),
    )
    .expect("unknown field");
    assert!(matches!(
        PackageStager::default().stage(source.path(), quarantine.path()),
        Err(PackageStageError::InvalidManifest(_))
    ));

    write_package(source.path(), b"component");
    let limits = PackageLimits::new(5, 1024 * 1024, 8 * 1024 * 1024, SchemaLimits::default())
        .expect("limits");
    assert!(matches!(
        PackageStager::new(limits).stage(source.path(), quarantine.path()),
        Err(PackageStageError::TooManyFiles)
    ));
}

#[test]
fn staged_snapshot_is_unchanged_when_the_source_changes_later() {
    let quarantine = tempdir().expect("quarantine");
    let source = tempdir().expect("source");
    write_package(source.path(), b"reviewed component");
    let staged = PackageStager::default()
        .stage(source.path(), quarantine.path())
        .expect("stage");

    fs::write(source.path().join("plugin.wasm"), b"changed after review").expect("source change");
    assert_eq!(
        fs::read(staged.quarantine_path().join("plugin.wasm")).expect("staged bytes"),
        b"reviewed component"
    );
}

#[test]
fn content_addressed_quarantine_rejects_extra_or_changed_files() {
    let quarantine = tempdir().expect("quarantine");
    let source = tempdir().expect("source");
    write_package(source.path(), b"reviewed component");
    let stager = PackageStager::default();
    let staged = stager
        .stage(source.path(), quarantine.path())
        .expect("stage");
    fs::write(staged.quarantine_path().join("unexpected"), b"injected").expect("tamper");

    assert!(matches!(
        stager.stage(source.path(), quarantine.path()),
        Err(PackageStageError::QuarantineConflict)
    ));
}

#[test]
fn approved_staged_bytes_install_idempotently_under_their_content_address() {
    let quarantine = tempdir().expect("quarantine");
    let installed = tempdir().expect("installed");
    let source = tempdir().expect("source");
    write_package(source.path(), b"reviewed component");
    let stager = PackageStager::default();
    let staged = stager
        .stage(source.path(), quarantine.path())
        .expect("stage");
    let identity = PackageIdentity::from(&staged);

    let first = stager
        .install_staged(staged.quarantine_path(), installed.path(), &identity)
        .expect("install");
    let second = stager
        .install_staged(staged.quarantine_path(), installed.path(), &identity)
        .expect("idempotent install");

    assert_eq!(first.path(), second.path());
    assert_eq!(
        first.path().file_name().and_then(std::ffi::OsStr::to_str),
        Some(staged.package_digest().as_str())
    );
    assert_eq!(
        fs::read(first.path().join("plugin.wasm")).expect("installed artifact"),
        b"reviewed component"
    );
}

#[test]
fn install_rechecks_every_approved_digest_before_copying() {
    let quarantine = tempdir().expect("quarantine");
    let installed = tempdir().expect("installed");
    let source = tempdir().expect("source");
    write_package(source.path(), b"reviewed component");
    let stager = PackageStager::default();
    let staged = stager
        .stage(source.path(), quarantine.path())
        .expect("stage");
    let identity = PackageIdentity::from(&staged);

    let artifact = staged.quarantine_path().join("plugin.wasm");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = fs::metadata(&artifact).expect("metadata").permissions();
        permissions.set_mode(permissions.mode() | 0o200);
        fs::set_permissions(&artifact, permissions).expect("make mutable for adversarial test");
    }
    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(&artifact).expect("metadata").permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&artifact, permissions).expect("make mutable for adversarial test");
    }
    fs::write(&artifact, b"substituted after approval").expect("substitute");

    assert!(matches!(
        stager.install_staged(staged.quarantine_path(), installed.path(), &identity),
        Err(PackageStageError::ApprovedIdentityMismatch)
    ));
    assert_eq!(
        fs::read_dir(installed.path())
            .expect("installed root")
            .count(),
        0
    );
}

#[test]
fn schema_subset_rejects_external_recursive_and_expensive_constructs() {
    for schema in [
        json!({"$ref": "https://example.com/schema.json"}),
        json!({"$ref": "#"}),
        json!({"type": "string", "pattern": "(a+)+$"}),
        json!({"anyOf": [{"type": "string"}, {"type": "number"}]}),
        json!({"type": "object", "patternProperties": {".*": {"type": "string"}}}),
    ] {
        assert!(BoundedSchema::compile(schema, SchemaLimits::default()).is_err());
    }

    let deep = json!({"type": "array", "items": {"type": "array", "items": {"type": "array", "items": {"type": "string"}}}});
    assert!(
        BoundedSchema::compile(
            deep,
            SchemaLimits::new(2, 4096, 16, 16, 128, 4096).expect("limits")
        )
        .is_err()
    );
}

#[test]
fn schema_validation_enforces_shape_and_runtime_bounds() {
    let schema = BoundedSchema::compile(
        json!({
            "type": "object",
            "properties": {"name": {"type": "string", "maxLength": 8}},
            "required": ["name"],
            "additionalProperties": false
        }),
        SchemaLimits::new(8, 4_096, 16, 16, 128, 4_096).expect("limits"),
    )
    .expect("bounded schema");

    schema.validate(&json!({"name": "lumen"})).expect("valid");
    assert!(
        schema
            .validate(&json!({"name": "name is too long"}))
            .is_err()
    );
    assert!(
        schema
            .validate(&json!({"name": "ok", "unknown": true}))
            .is_err()
    );
    assert!(
        schema
            .validate(&json!({"name": "ok", "nested": [[[[[[[[[1]]]]]]]]]}))
            .is_err()
    );
}

#[test]
fn scoped_settings_merge_objects_replace_arrays_and_bind_revisions() {
    let schema = BoundedSchema::compile(
        json!({
            "type": "object",
            "properties": {
                "nested": {
                    "type": "object",
                    "properties": {
                        "left": {"type": "string"},
                        "right": {"type": "string"}
                    },
                    "additionalProperties": false
                },
                "items": {"type": "array", "items": {"type": "string"}}
            },
            "additionalProperties": false
        }),
        SchemaLimits::default(),
    )
    .expect("schema");
    let first = merge_scoped_settings(
        &schema,
        [
            (
                1,
                json!({"nested": {"left": "global"}, "items": ["a", "b"]}),
            ),
            (4, json!({"nested": {"right": "workspace"}, "items": ["c"]})),
        ],
    )
    .expect("settings");
    assert_eq!(
        first.value(),
        &json!({"nested": {"left": "global", "right": "workspace"}, "items": ["c"]})
    );
    let changed_revision = merge_scoped_settings(
        &schema,
        [
            (
                1,
                json!({"nested": {"left": "global"}, "items": ["a", "b"]}),
            ),
            (5, json!({"nested": {"right": "workspace"}, "items": ["c"]})),
        ],
    )
    .expect("settings");
    assert_ne!(first.digest(), changed_revision.digest());
    assert!(merge_scoped_settings(&schema, [(1, json!({"unknown": true}))]).is_err());
}
