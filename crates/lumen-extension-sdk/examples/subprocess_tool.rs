use std::{
    io::{Read as _, Write as _},
    time::Duration,
};

use lumen_extension_sdk::{
    InvocationResponse, MAX_FRAME_BYTES, Response, SubprocessRequest, SubprocessResponse,
    decode_frame, encode_frame,
};

fn main() {
    let mut frame = Vec::new();
    std::io::stdin()
        .take((MAX_FRAME_BYTES + 5) as u64)
        .read_to_end(&mut frame)
        .expect("read one request frame");
    let request: SubprocessRequest =
        decode_frame(&frame, MAX_FRAME_BYTES).expect("decode one request frame");
    if request
        .invocation()
        .input()
        .get("loop_forever")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        loop {
            std::hint::spin_loop();
        }
    }
    let result = if request
        .invocation()
        .input()
        .get("probe_ambient")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        let input = request.invocation().input();
        let read = input
            .get("read_path")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|path| std::fs::read(path).is_ok());
        let write = input
            .get("write_path")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|path| std::fs::write(path, b"denied").is_ok());
        let network = input
            .get("socket_address")
            .and_then(serde_json::Value::as_str)
            .and_then(|address| address.parse().ok())
            .is_some_and(|address| {
                std::net::TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok()
            });
        let process = std::process::Command::new("/bin/echo")
            .arg("denied")
            .status()
            .is_ok();
        serde_json::json!({
            "environment": std::env::vars_os().next().is_some(),
            "network": network,
            "process": process,
            "read": read,
            "write": write,
        })
    } else {
        request.invocation().input().clone()
    };
    let response =
        InvocationResponse::new(request.invocation().request_id(), Response::result(result))
            .and_then(|response| SubprocessResponse::new(request.nonce(), response))
            .expect("build correlated response");
    let frame = encode_frame(&response, MAX_FRAME_BYTES).expect("encode one response frame");
    std::io::stdout()
        .write_all(&frame)
        .expect("write one response frame");
}
