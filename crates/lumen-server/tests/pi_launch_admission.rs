//! Uses the NON-cfg(test) library. Fixture-only launch helpers cannot be called
//! here. A fake executable that would write a marker proves rejection occurs
//! before spawning, even with valid pins and apparently safe Pi flags.
use std::{path::PathBuf, sync::Arc};

use lumen_server::{
    AuthdClient, MemorySessionStore, MockAuthdClient, MockKernelClient, SessionSupervisor,
    SupervisorConfig, default_catalog,
    pi_supervisor::{PiSupervisor, PiSupervisorConfig},
    sha256_hex,
};

#[tokio::test]
async fn reference_launcher_cannot_start_any_child() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("executed");
    let config = PiSupervisorConfig {
        pi_binary: PathBuf::from("/bin/sh"),
        args: vec![
            "-c".into(),
            "touch \"$1\"".into(),
            "--no-builtin-tools".into(),
            marker.display().to_string(),
        ],
        ..Default::default()
    };
    for _ in 0..3 {
        let err = PiSupervisor::spawn(config.clone())
            .await
            .err()
            .expect("launch must fail");
        assert!(err.to_string().contains("verified OS confinement"));
        assert!(!marker.exists());
    }
}

#[tokio::test]
async fn pinned_session_launch_is_denied_before_identity_or_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("executed");
    let executable = PathBuf::from("/bin/sh");
    let digest = sha256_hex(&std::fs::read(&executable).unwrap());
    let config = SupervisorConfig {
        pi_binary: executable.clone(),
        pi_args: vec![
            "-c".into(),
            "touch \"$1\"".into(),
            "--no-builtin-tools".into(),
            marker.display().to_string(),
        ],
        pi_version: "0.87.1".into(),
        pi_digest: digest.clone(),
        extension_path: executable,
        extension_digest: digest,
        ..Default::default()
    };
    let supervisor = Arc::new(SessionSupervisor::new(
        config,
        Arc::new(MockKernelClient::new()),
        Arc::new(default_catalog()),
        Arc::new(MemorySessionStore::new()),
    ));
    let owner = MockAuthdClient::new()
        .with_token("fixture-token", "fixture-account")
        .authenticate("fixture-token")
        .await
        .unwrap();
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let supervisor = supervisor.clone();
        let owner = owner.clone();
        tasks.push(tokio::spawn(async move {
            let error = supervisor
                .spawn_session(&owner)
                .await
                .expect_err("launch must fail");
            assert!(error.to_string().contains("verified OS confinement"));
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert!(!marker.exists());
    assert!(supervisor.list_sessions().is_empty());
}
