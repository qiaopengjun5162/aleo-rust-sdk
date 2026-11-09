//! Offline integration tests for [`aleo_rust_sdk::scanner::RecordScanService`].
//!
//! The scanner's read-only batch/scan endpoints (`/records/sns`, `/records/tags`,
//! `/records/encrypted`) carry no `uuid` and never touch a TEE, so they can be
//! exercised end-to-end against a local [`wiremock`] server: we mount a canned
//! response, point the service at it, and assert both the parsed result and the
//! request the SDK actually sent (via `received_requests`, which pins the wire
//! format without a brittle exact-match body matcher).

use aleo_rust_sdk::hosted::ApiAuth;
use aleo_rust_sdk::scanner::{EncryptedRecord, EncryptedRecordsFilter, RecordScanService};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Point a scanner at a mock server with no auth headers.
fn service_at(uri: &str) -> RecordScanService {
    // `with_endpoints` keeps the base verbatim, so the SDK appends
    // `/records/sns` etc. with a single slash.
    RecordScanService::with_endpoints(uri.to_string(), uri.to_string(), ApiAuth::None)
        .expect("scanner endpoints are valid")
}

/// The one JSON body the SDK sent to `route`, panicking if it sent none or many.
async fn sent_body(server: &MockServer, route: &str) -> serde_json::Value {
    let requests = server.received_requests().await.expect("wiremock records requests");
    let bodies: Vec<serde_json::Value> = requests
        .iter()
        .filter(|req| req.url.path() == route)
        .map(|req| serde_json::from_slice(&req.body).expect("request body is JSON"))
        .collect();
    assert_eq!(bodies.len(), 1, "expected exactly one {route} request");
    bodies.into_iter().next().unwrap()
}

#[tokio::test]
async fn serial_numbers_parses_spent_map_and_sends_array() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/records/sns"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"sn-a":true,"sn-b":false}"#))
        .mount(&server)
        .await;

    let service = service_at(&server.uri());
    let map = service
        .serial_numbers(&["sn-a".to_string(), "sn-b".to_string()])
        .await
        .expect("request should succeed");

    assert_eq!(map.get("sn-a"), Some(&true));
    assert_eq!(map.get("sn-b"), Some(&false));
    assert_eq!(map.len(), 2);

    // The wire format is a bare JSON array, not a wrapped object.
    assert_eq!(
        sent_body(&server, "/records/sns").await,
        json!(["sn-a", "sn-b"])
    );
}

#[tokio::test]
async fn tags_parses_spent_map_and_sends_array() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/records/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"tag-x":true}"#))
        .mount(&server)
        .await;

    let service = service_at(&server.uri());
    let map = service.tags(&["tag-x".to_string()]).await.expect("request should succeed");

    assert_eq!(map.get("tag-x"), Some(&true));
    assert_eq!(sent_body(&server, "/records/tags").await, json!(["tag-x"]));
}

#[tokio::test]
async fn encrypted_scans_ledger_and_sends_filter() {
    let server = MockServer::start().await;
    let filter = EncryptedRecordsFilter {
        start: Some(0),
        end: Some(100),
        programs: Some(vec!["credits.aleo".to_string()]),
        ..Default::default()
    };
    // The SDK must send *only* the fields that are set (skip_serializing_if).
    let expected_body = serde_json::to_value(&filter).unwrap();
    let response = json!([
        {
            "commitment": "commitment1field",
            "program_name": "credits.aleo",
            "record_ciphertext": "record1..."
        }
    ])
    .to_string();

    Mock::given(method("POST"))
        .and(path("/records/encrypted"))
        .respond_with(ResponseTemplate::new(200).set_body_string(response))
        .mount(&server)
        .await;

    let service = service_at(&server.uri());
    let records: Vec<EncryptedRecord> =
        service.encrypted(&filter).await.expect("request should succeed");

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].commitment, "commitment1field");
    assert_eq!(records[0].program_name.as_deref(), Some("credits.aleo"));
    // Unset fields must not be fabricated by the SDK.
    assert_eq!(records[0].block_height, None);

    assert_eq!(
        sent_body(&server, "/records/encrypted").await,
        expected_body
    );
}

#[tokio::test]
async fn serial_numbers_sends_bare_array_not_object() {
    // Defends against a regression where the list would be wrapped in an object,
    // which the scanner endpoint would reject.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/records/sns"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"only-one":false}"#))
        .mount(&server)
        .await;

    let service = service_at(&server.uri());
    let map = service
        .serial_numbers(&["only-one".to_string()])
        .await
        .expect("request should succeed");
    assert_eq!(map.get("only-one"), Some(&false));
    assert_eq!(
        sent_body(&server, "/records/sns").await,
        json!(["only-one"])
    );
}
