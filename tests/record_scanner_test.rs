//! Offline integration tests for [`aleo_rust_sdk::scanner::RecordScanService`].
//!
//! The scanner's read-only batch/scan endpoints (`/records/sns`, `/records/tags`,
//! `/records/encrypted`) carry no `uuid` and never touch a TEE, so they can be
//! exercised end-to-end against a local [`wiremock`] server: we mount a canned
//! response, point the service at it, and assert both the parsed result and the
//! request the SDK actually sent (via `received_requests`, which pins the wire
//! format without a brittle exact-match body matcher).

use aleo_rust_sdk::account::AleoAccount;
use aleo_rust_sdk::hosted::ApiAuth;
use aleo_rust_sdk::scanner::{
    EncryptedRecord, EncryptedRecordsFilter, OwnedFilter, OwnedRecordsResponseFilter,
    RecordScanService,
};
use indexmap::IndexMap;
use serde_json::json;
use snarkvm::console::program::{Entry, Identifier, Literal, Plaintext, Record};
use snarkvm::prelude::{FromStr, Network, Owner, Scalar, TestRng, TestnetV0, U8};
use snarkvm::utilities::rand::Uniform;
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

// ── JS findRecord / findCreditsRecord(s) parity ──────────────────────────

/// Build a genuine snarkVM `credits` ciphertext holding `microcredits`, so the
/// credits helpers exercise their real local-decryption path rather than a
/// stub. Same recipe as `record_decryption_test.rs`.
fn encrypted_credits_record(account: &AleoAccount, microcredits: u64, rng: &mut TestRng) -> String {
    let randomizer = Scalar::rand(rng);
    let nonce = TestnetV0::g_scalar_multiply(&randomizer);
    let owner = Owner::Private(Plaintext::from(Literal::Address(account.address)));
    let mut data = IndexMap::new();
    data.insert(
        Identifier::from_str("microcredits").unwrap(),
        Entry::Private(Plaintext::from_str(&format!("{microcredits}u64")).unwrap()),
    );
    let plaintext =
        Record::<TestnetV0, Plaintext<TestnetV0>>::from_plaintext(owner, data, nonce, U8::new(0))
            .unwrap();
    plaintext.encrypt(randomizer).unwrap().to_string()
}

/// Three decryptable credits records plus one row the view key cannot decrypt.
fn credits_fixture(account: &AleoAccount, rng: &mut TestRng) -> serde_json::Value {
    json!([
        { "commitment": "cm-1m", "record_ciphertext": encrypted_credits_record(account, 1_000_000, rng) },
        { "commitment": "cm-5m", "record_ciphertext": encrypted_credits_record(account, 5_000_000, rng) },
        { "commitment": "cm-10m", "record_ciphertext": encrypted_credits_record(account, 10_000_000, rng) },
        { "commitment": "cm-bad", "record_ciphertext": "not-a-record-ciphertext" },
    ])
}

async fn serve_owned(server: &MockServer, body: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path("/records/owned"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

#[tokio::test]
async fn find_record_returns_first_match_and_errors_when_empty() {
    let server = MockServer::start().await;
    serve_owned(
        &server,
        json!([
            { "commitment": "cm-a", "record_ciphertext": "cipher-a" },
            { "commitment": "cm-b", "record_ciphertext": "cipher-b" },
        ]),
    )
    .await;

    let service = service_at(&server.uri());
    let record = service.find_record("uuid-1", OwnedFilter::unspent()).await.unwrap();
    assert_eq!(record.commitment.as_deref(), Some("cm-a"));
    assert_eq!(sent_body(&server, "/records/owned").await["uuid"], "uuid-1");

    let empty = MockServer::start().await;
    serve_owned(&empty, json!([])).await;
    let err = service_at(&empty.uri())
        .find_record("uuid-1", OwnedFilter::default())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Record not found"), "{err}");
}

#[tokio::test]
async fn find_credits_record_uses_at_least_semantics_and_forces_credits_filter() {
    let rng = &mut TestRng::default();
    let account = AleoAccount::new_random(rng).unwrap();
    let server = MockServer::start().await;
    serve_owned(&server, credits_fixture(&account, rng)).await;

    // `program` is deliberately wrong: the helper must override it. `start`
    // and `responseFilter` must survive untouched.
    let filter = OwnedFilter::default().program("wrong.aleo").start(7).response_filter(
        OwnedRecordsResponseFilter {
            commitment: Some(true),
            ..Default::default()
        },
    );
    let service = service_at(&server.uri());
    let record = service
        .find_credits_record("uuid-1", 4_000_000, &account.view_key, filter)
        .await
        .unwrap();
    assert_eq!(
        record.commitment.as_deref(),
        Some("cm-5m"),
        "first record with at least 4m microcredits"
    );

    let body = sent_body(&server, "/records/owned").await;
    assert_eq!(body["uuid"], "uuid-1");
    assert_eq!(body["unspent"], json!(true), "JS defaults unspent to true");
    assert_eq!(body["filter"]["program"], "credits.aleo");
    assert_eq!(body["filter"]["record"], "credits");
    assert_eq!(body["filter"]["start"], 7, "caller's start survives");
    assert_eq!(body["responseFilter"], json!({ "commitment": true }));
}

#[tokio::test]
async fn find_credits_record_errors_when_no_record_is_large_enough() {
    let rng = &mut TestRng::default();
    let account = AleoAccount::new_random(rng).unwrap();
    let server = MockServer::start().await;
    serve_owned(&server, credits_fixture(&account, rng)).await;

    let err = service_at(&server.uri())
        .find_credits_record(
            "uuid-1",
            20_000_000,
            &account.view_key,
            OwnedFilter::default(),
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("at least 20000000 microcredits"),
        "{err}"
    );
}

#[tokio::test]
async fn find_credits_records_matches_exact_amounts_only() {
    let rng = &mut TestRng::default();
    let account = AleoAccount::new_random(rng).unwrap();
    let server = MockServer::start().await;
    serve_owned(&server, credits_fixture(&account, rng)).await;

    let service = service_at(&server.uri());
    let records = service
        .find_credits_records(
            "uuid-1",
            &[5_000_000, 10_000_000],
            &account.view_key,
            OwnedFilter::default(),
        )
        .await
        .unwrap();
    let commitments: Vec<&str> =
        records.iter().map(|record| record.commitment.as_deref().unwrap()).collect();
    assert_eq!(
        commitments,
        vec!["cm-5m", "cm-10m"],
        "1m and the undecryptable row must be excluded"
    );

    // An empty membership result is not an error, unlike `find_credits_record`.
    let other = MockServer::start().await;
    serve_owned(&other, credits_fixture(&account, rng)).await;
    let none = service_at(&other.uri())
        .find_credits_records("uuid-1", &[42], &account.view_key, OwnedFilter::default())
        .await
        .unwrap();
    assert!(none.is_empty());
}
