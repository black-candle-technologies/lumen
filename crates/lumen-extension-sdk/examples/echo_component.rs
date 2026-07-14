#[cfg(target_arch = "wasm32")]
mod component {
    use lumen_extension_sdk::{
        InvocationRequest, InvocationResponse, Response, generate_guest_bindings,
    };

    generate_guest_bindings!();

    struct Echo;

    impl Guest for Echo {
        fn invoke(encoded_request: String) -> String {
            let request: InvocationRequest =
                serde_json::from_str(&encoded_request).expect("host request must be valid JSON");
            InvocationResponse::new(
                request.request_id(),
                Response::result(request.input().clone()),
            )
            .and_then(|response| response.encode())
            .expect("fixture response must be valid JSON")
        }
    }

    export!(Echo);
}

fn main() {}
