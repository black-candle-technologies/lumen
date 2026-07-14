use lumen_extension_sdk::{InvocationResponse, Response, WireContractError};

#[test]
fn response_contract_enforces_correlation_protocol_and_bounds() {
    let response =
        InvocationResponse::new("request-1", Response::result(serde_json::json!("done"))).unwrap();
    let encoded = response.encode().unwrap();
    assert_eq!(
        InvocationResponse::decode_bounded(&encoded, encoded.len() as u64)
            .unwrap()
            .validate_for(1, "request-1")
            .unwrap(),
        Response::result(serde_json::json!("done"))
    );
    assert_eq!(
        InvocationResponse::decode_bounded(&encoded, encoded.len() as u64 - 1).unwrap_err(),
        WireContractError::ResponseTooLarge
    );
    assert_eq!(
        InvocationResponse::decode_bounded(&encoded, encoded.len() as u64)
            .unwrap()
            .validate_for(1, "request-2")
            .unwrap_err(),
        WireContractError::RequestMismatch
    );

    let mismatched = encoded.replacen("\"protocol_version\":1", "\"protocol_version\":2", 1);
    assert_eq!(
        InvocationResponse::decode_bounded(&mismatched, mismatched.len() as u64)
            .unwrap()
            .validate_for(1, "request-1")
            .unwrap_err(),
        WireContractError::ProtocolMismatch
    );
}

#[test]
fn response_contract_rejects_unknown_fields_and_malformed_json() {
    let unknown = r#"{"protocol_version":1,"request_id":"request-1","response":{"type":"result","value":null},"extra":true}"#;
    assert_eq!(
        InvocationResponse::decode_bounded(unknown, 1024).unwrap_err(),
        WireContractError::InvalidJson
    );
    assert_eq!(
        InvocationResponse::decode_bounded("not-json", 1024).unwrap_err(),
        WireContractError::InvalidJson
    );
}
