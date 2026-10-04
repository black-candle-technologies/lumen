//! Hermetic verified TLS server, shared by protocol and production runtime tests.
use std::{collections::VecDeque, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{self, pki_types::PrivatePkcs8KeyDer},
};

#[derive(Clone)]
pub struct Reply {
    pub status: u16,
    pub body: String,
    pub location: Option<String>,
    pub delay: Duration,
}
impl Reply {
    pub fn json(body: serde_json::Value) -> Self {
        Self {
            status: 200,
            body: body.to_string(),
            location: None,
            delay: Duration::ZERO,
        }
    }
}
pub struct TlsServer {
    pub endpoint: String,
    pub client: reqwest::Client,
    pub requests: Arc<Mutex<Vec<String>>>,
    pub replies: Arc<Mutex<VecDeque<Reply>>>,
    task: tokio::task::JoinHandle<()>,
}
impl TlsServer {
    pub async fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certificate = rcgen::generate_simple_self_signed(vec!["provider.test".into()]).unwrap();
        let cert = certificate.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der());
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key.into())
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let replies = Arc::new(Mutex::new(VecDeque::<Reply>::new()));
        let seen = requests.clone();
        let queue = replies.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let seen = seen.clone();
                let queue = queue.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut bytes = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        let Ok(n) = stream.read(&mut buf).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        };
                        bytes.extend_from_slice(&buf[..n]);
                        if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                            let headers = String::from_utf8_lossy(&bytes[..end]);
                            let length = headers
                                .lines()
                                .find_map(|l| {
                                    l.to_ascii_lowercase()
                                        .strip_prefix("content-length: ")
                                        .and_then(|v| v.parse::<usize>().ok())
                                })
                                .unwrap_or(0);
                            if bytes.len() >= end + 4 + length {
                                break;
                            }
                        }
                        assert!(bytes.len() < 1024 * 1024);
                    }
                    seen.lock().await.push(String::from_utf8(bytes).unwrap());
                    let reply=queue.lock().await.pop_front().unwrap_or_else(||Reply::json(serde_json::json!({"choices":[{"finish_reason":"stop","message":{"content":"hello"}}]})));
                    tokio::time::sleep(reply.delay).await;
                    let location = reply
                        .location
                        .map(|v| format!("location: {v}\r\n"))
                        .unwrap_or_default();
                    let wire = format!(
                        "HTTP/1.1 {} Test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n{}\r\n{}",
                        reply.status,
                        reply.body.len(),
                        location,
                        reply.body
                    );
                    let _ = stream.write_all(wire.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        let client = reqwest::Client::builder()
            .tls_certs_only(vec![reqwest::Certificate::from_der(cert.as_ref()).unwrap()])
            .resolve("provider.test", addr)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        Self {
            endpoint: format!("https://provider.test:{}/gateway/v1/", addr.port()),
            client,
            requests,
            replies,
            task,
        }
    }
}
impl Drop for TlsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
