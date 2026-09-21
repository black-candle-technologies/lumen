#![cfg(target_os = "linux")]

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};

use tempfile::tempdir;

mod support;
use support::toml_path;

const WORKSPACE_ID: &str = "26db5a31-94f0-4e92-a9c9-4cdf19d71c31";
const TEST_TOKEN: &str = "owned-readiness-fixture-token";

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn fixture_config(root: &std::path::Path, bind_port: u16, model_port: u16) -> std::path::PathBuf {
    let config = root.join("lumen.toml");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).expect("owned workspace");
    std::fs::write(
        &config,
        format!(
            r#"
[server]
bind = "127.0.0.1:{bind_port}"
[database]
path = {}
[model]
endpoint = "http://127.0.0.1:{model_port}/v1/"
model = "unavailable-fixture-model"
[workspace]
id = "{WORKSPACE_ID}"
name = "Owned readiness fixture"
path = {}
[runtime]
data_directory = {}
[bootstrap_admin]
provider = "local"
subject = "operator"
"#,
            toml_path(root.join("lumen.sqlite3")),
            toml_path(&workspace),
            toml_path(root.join("data"))
        ),
    )
    .expect("owned config");
    config
}

fn spawn_server(config: &std::path::Path) -> OwnedChild {
    OwnedChild(
        Command::new(env!("CARGO_BIN_EXE_lumen"))
            .arg("--config")
            .arg(config)
            .arg("serve")
            .env("LUMEN_BEARER_TOKEN", TEST_TOKEN)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("owned Lumen process"),
    )
}

fn stderr_lines(child: &mut OwnedChild) -> Receiver<String> {
    let stderr = child.0.stderr.take().expect("owned stderr");
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = sender.send(line);
        }
    });
    receiver
}

fn wait_for_event(lines: &Receiver<String>, event: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let line = lines
            .recv_timeout(remaining)
            .expect("bounded server output");
        if line.contains(event) {
            return line;
        }
        assert!(
            !line.starts_with("error:"),
            "server error before {event}: {line}"
        );
    }
}

fn get(port: u16, path: &str, token: &str) -> String {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).expect("server accepts TCP");
    socket
        .set_read_timeout(Some(Duration::from_secs(6)))
        .expect("bounded read");
    write!(socket, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n")
        .expect("request written");
    let mut response = String::new();
    socket
        .read_to_string(&mut response)
        .expect("bounded response");
    response
}

#[test]
fn ready_server_reports_layers_with_model_down_and_stops_boundedly() {
    let directory = tempdir().expect("owned fixture root");
    let bind = TcpListener::bind("127.0.0.1:0").expect("select bind port");
    let bind_port = bind.local_addr().expect("bind address").port();
    drop(bind);
    let model = TcpListener::bind("127.0.0.1:0").expect("select model port");
    let model_port = model.local_addr().expect("model address").port();
    let config = fixture_config(directory.path(), bind_port, model_port);
    let mut server = spawn_server(&config);
    let lines = stderr_lines(&mut server);
    let starting = lines
        .recv_timeout(Duration::from_secs(20))
        .expect("bounded startup output");
    assert!(
        starting.contains("event=server_starting"),
        "first startup state: {starting}"
    );
    let started = wait_for_event(&lines, "event=server_started");
    assert!(started.contains(&format!("bind=127.0.0.1:{bind_port}")));
    assert!(started.contains(&format!("workspace={WORKSPACE_ID}")));
    assert!(started.contains("config="));
    assert!(started.contains("backend="));
    assert!(started.contains("strength=kernel_enforced"));
    assert!(started.contains(&format!("pid={}", server.0.id())));

    let path = format!("/api/v1/workspaces/{WORKSPACE_ID}/runtime/capabilities");
    let cheap = get(bind_port, &path, TEST_TOKEN);
    assert!(
        cheap.starts_with("HTTP/1.1 200"),
        "cheap readiness: {cheap}"
    );
    assert!(cheap.contains("\"server\":\"listening\""));
    assert!(cheap.contains("\"workspace\":\"ready\""));
    assert!(cheap.contains("\"model\":\"not_checked\""));
    assert!(get(bind_port, &path, "wrong").starts_with("HTTP/1.1 401"));
    assert!(
        get(
            bind_port,
            &format!(
                "/api/v1/workspaces/{}/runtime/capabilities",
                uuid::Uuid::new_v4()
            ),
            TEST_TOKEN
        )
        .starts_with("HTTP/1.1 403")
    );
    drop(model);
    let checked = get(bind_port, &format!("{path}?probe_model=true"), TEST_TOKEN);
    assert!(
        checked.starts_with("HTTP/1.1 200"),
        "model probe: {checked}"
    );
    assert!(checked.contains("\"model\":\"unavailable\""));

    let signal = Command::new("kill")
        .arg("-INT")
        .arg(server.0.id().to_string())
        .status()
        .expect("owned process signal");
    assert!(signal.success());
    wait_for_event(&lines, "event=server_stopping");
    let stopped = wait_for_event(&lines, "event=server_stopped");
    assert!(stopped.contains("result=ok"));
    let deadline = Instant::now() + Duration::from_secs(8);
    while server.0.try_wait().expect("owned process status").is_none() {
        assert!(Instant::now() < deadline, "shutdown exceeded eight seconds");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn occupied_port_reports_bind_failure_without_claiming_readiness() {
    let directory = tempdir().expect("owned fixture root");
    let occupied = TcpListener::bind("127.0.0.1:0").expect("owned occupied port");
    let port = occupied.local_addr().expect("occupied address").port();
    let config = fixture_config(directory.path(), port, port);
    let mut server = spawn_server(&config);
    let lines = stderr_lines(&mut server);
    let failure = wait_for_event(&lines, "event=server_bind_failed");
    assert!(failure.contains(&format!("bind=127.0.0.1:{port}")));
    assert!(!failure.contains(TEST_TOKEN));
    assert!(!server.0.wait().expect("owned process exit").success());
}
