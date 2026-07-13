use std::{fs, path::Path};

use serde_json::Value;

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn desktop_shell_has_one_local_least_privilege_authority_surface() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let config: Value = serde_json::from_str(&read(&root.join("tauri.conf.json")))
        .expect("Tauri configuration JSON");
    let app = &config["app"];
    assert_eq!(app["withGlobalTauri"], false);
    let windows = app["windows"].as_array().expect("windows array");
    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0]["label"], "main");

    let security = &app["security"];
    let csp = security["csp"].as_str().expect("production CSP");
    let dev_csp = security["devCsp"].as_str().expect("development CSP");
    assert!(csp.contains("default-src 'self'"));
    assert!(csp.contains("connect-src 'self' http://127.0.0.1:3210"));
    assert!(!csp.contains("localhost:5173"));
    assert!(!csp.contains('*'));
    assert!(dev_csp.contains("http://localhost:5173"));
    assert!(security.get("dangerousRemoteDomainIpcAccess").is_none());

    let capability_directory = root.join("capabilities");
    let mut files = fs::read_dir(&capability_directory)
        .expect("capability directory")
        .map(|entry| entry.expect("capability entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "json"))
        .collect::<Vec<_>>();
    files.sort();
    assert_eq!(files, vec![capability_directory.join("main.json")]);
    let capability: Value =
        serde_json::from_str(&read(&files[0])).expect("main capability JSON");
    assert_eq!(capability["identifier"], "main");
    assert_eq!(capability["windows"], serde_json::json!(["main"]));
    assert_eq!(capability["permissions"], serde_json::json!([]));
    assert!(capability.get("remote").is_none());

    let manifest = read(&root.join("Cargo.toml"));
    let runtime = read(&root.join("src/lib.rs"));
    for forbidden in ["tauri-plugin-opener", "tauri-plugin-shell", "tauri-plugin-fs"] {
        assert!(!manifest.contains(forbidden), "forbidden dependency: {forbidden}");
    }
    for forbidden in [
        "#[tauri::command]",
        "invoke_handler",
        "generate_handler!",
        ".plugin(",
    ] {
        assert!(!runtime.contains(forbidden), "forbidden runtime API: {forbidden}");
    }
}
