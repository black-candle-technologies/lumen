//! Environment changes happen only in a fresh child process, never in concurrent tests.
#![cfg(feature = "model-client")]
#[test]
fn production_http_client_ignores_environment_proxies() {
    const CHILD: &str = "LUMEN_PROVIDER_PROXY_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = target.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = target.accept().await.unwrap();
                let mut bytes = [0; 1024];
                let n = stream.read(&mut bytes).await.unwrap();
                assert!(
                    std::str::from_utf8(&bytes[..n])
                        .unwrap()
                        .starts_with("GET /direct ")
                );
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
            });
            let client = lumen_integrations::providers::provider_http_client(
                lumen_integrations::providers::ProviderHttpOptions {
                    timeout: std::time::Duration::from_secs(2),
                    max_response_bytes: 1024,
                },
            )
            .unwrap();
            assert_eq!(
                client
                    .get(format!("http://{address}/direct"))
                    .send()
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap(),
                "ok"
            );
            server.await.unwrap();
        });
        return;
    }
    // This listening proxy never answers. Using it would time out instead of reaching /direct.
    let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", proxy.local_addr().unwrap());
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "production_http_client_ignores_environment_proxies",
        ])
        .env(CHILD, "1");
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env(name, &url);
    }
    command.env("NO_PROXY", "").env("no_proxy", "");
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    proxy.set_nonblocking(true).unwrap();
    assert!(
        proxy.accept().is_err(),
        "production client contacted an environment proxy"
    );
}
