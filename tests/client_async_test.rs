use aleo_rust_sdk::AleoClient;
use snarkvm::prelude::TestRng;
use std::str::FromStr;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Helper: spin up a mock server with common endpoints.
async fn setup_mock() -> MockServer {
    let mock_server = MockServer::start().await;

    // Block height endpoint
    Mock::given(method("GET"))
        .and(path("/v2/testnet/block/height/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"20457000", "text/plain"))
        .mount(&mock_server)
        .await;

    // State root endpoint — returns bare quoted string (no JSON envelope)
    Mock::given(method("GET"))
        .and(path_regex(r"/v2/testnet/stateRoot/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            b"\"sr10yqur7mt0f3r38w0pt9xu28xvv2975xlcv5msypvvp8ghhzdcqzs3d4lgs\"",
            "application/json",
        ))
        .mount(&mock_server)
        .await;

    // Mapping value: credits.aleo/account/{addr}
    Mock::given(method("GET"))
        .and(path_regex(
            r"/v2/testnet/program/credits\.aleo/mapping/account/.+",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(b"\"1000000u64\"", "application/json"),
        )
        .mount(&mock_server)
        .await;

    // Mapping value: not found
    Mock::given(method("GET"))
        .and(path_regex(
            r"/v2/testnet/program/nonexistent\.aleo/mapping/.+",
        ))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    // Records endpoint
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": []
        })))
        .mount(&mock_server)
        .await;

    // Program endpoint (needed for prove_execution / verify_execution)
    Mock::given(method("GET"))
        .and(path_regex(r"/v2/testnet/program/.+"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "program": "program credits.aleo;\nfunction transfer_public:\n    input r0 as address.public;\n    input r1 as u64.public;\n",
            "stateRoot": "sr1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "blockHeight": 20457000
        })))
        .mount(&mock_server)
        .await;

    // Fallback: catch-all 404 for unmocked GET
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    mock_server
}

fn make_client(mock_server: &MockServer, rpc_url: &str) -> AleoClient {
    let url = format!("{}/v2/testnet", mock_server.uri());
    AleoClient::new_with_rpc(&url, rpc_url).unwrap()
}

fn random_account(client: &mut AleoClient) {
    let rng = &mut TestRng::default();
    let pk = snarkvm::prelude::PrivateKey::<snarkvm::prelude::TestnetV0>::new(rng).unwrap();
    client.set_account_from_private_key_str(&pk.to_string()).unwrap();
}

// ── get_block_height ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_client_get_block_height() {
    let mock_server = setup_mock().await;
    let client = make_client(&mock_server, &mock_server.uri());
    let height = client.get_block_height().await.unwrap();
    assert_eq!(height, 20457000);
}

#[tokio::test]
async fn test_client_get_block_height_bad_response() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/testnet/block/height/latest"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server, &mock_server.uri());
    let result = client.get_block_height().await;
    assert!(result.is_err());
}

// ── get_balance ────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_client_get_balance() {
    let mock_server = setup_mock().await;
    let mut client = make_client(&mock_server, &mock_server.uri());
    random_account(&mut client);

    let balance = client.get_balance().await.unwrap();
    assert_eq!(balance, Some(1_000_000));
}

#[tokio::test]
async fn test_client_get_balance_no_account() {
    let mock_server = setup_mock().await;
    let client = make_client(&mock_server, &mock_server.uri());
    let result = client.get_balance().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_client_get_block_height_stale() {
    let mock_server = MockServer::start().await;
    // Return non-numeric response
    Mock::given(method("GET"))
        .and(path("/v2/testnet/block/height/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"not_a_number", "text/plain"))
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server, &mock_server.uri());
    let result = client.get_block_height().await;

    // Should fail parsing
    assert!(
        result.is_err(),
        "expected error parsing non-numeric height, got: {:?}",
        result
    );
}

// ── get_state_root ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_client_get_state_root() {
    let mock_server = setup_mock().await;
    let client = make_client(&mock_server, &mock_server.uri());
    let root = client.get_state_root().await.unwrap();
    assert_eq!(
        root.to_string(),
        "sr10yqur7mt0f3r38w0pt9xu28xvv2975xlcv5msypvvp8ghhzdcqzs3d4lgs"
    );
}

// ── prove_execution (error path — returns early before Varuna proving) ─────

#[tokio::test]
async fn test_prove_execution_program_not_found() {
    let mock_server = MockServer::start().await;
    // Return 404 for program fetch — early exit before proving
    Mock::given(method("GET"))
        .and(path_regex(r"/v2/testnet/program/.+"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let mut client = make_client(&mock_server, &mock_server.uri());
    random_account(&mut client);

    let rng = &mut TestRng::default();
    let pk = snarkvm::prelude::PrivateKey::<snarkvm::prelude::TestnetV0>::new(rng).unwrap();
    let pid = snarkvm::console::program::ProgramID::<snarkvm::prelude::TestnetV0>::from_str(
        "credits.aleo",
    )
    .unwrap();

    let result = client
        .prove_execution(&pk, &pid, "transfer_public", vec!["aleo1abc", "1u64"], 0)
        .await;
    assert!(
        result.is_err(),
        "expected error from 404 program fetch, got: {:?}",
        result
    );
}

// ── execute_and_broadcast (error path) ────────────────────────────────────

#[tokio::test]
async fn test_execute_and_broadcast_program_not_found() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let mut client = make_client(&mock_server, &mock_server.uri());
    random_account(&mut client);

    let rng = &mut TestRng::default();
    let pk = snarkvm::prelude::PrivateKey::<snarkvm::prelude::TestnetV0>::new(rng).unwrap();
    let pid = snarkvm::console::program::ProgramID::<snarkvm::prelude::TestnetV0>::from_str(
        "credits.aleo",
    )
    .unwrap();

    let result = client
        .execute_and_broadcast(&pk, &pid, "transfer_public", vec!["aleo1abc", "1u64"], 0)
        .await;
    assert!(result.is_err());
}

// ── execute_and_broadcast_with_values (error path) ────────────────────────

#[tokio::test]
async fn test_execute_broadcast_with_values_program_not_found() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let mut client = make_client(&mock_server, &mock_server.uri());
    random_account(&mut client);

    let rng = &mut TestRng::default();
    let pk = snarkvm::prelude::PrivateKey::<snarkvm::prelude::TestnetV0>::new(rng).unwrap();
    let pid = snarkvm::console::program::ProgramID::<snarkvm::prelude::TestnetV0>::from_str(
        "credits.aleo",
    )
    .unwrap();

    let result = client
        .execute_and_broadcast_with_values(&pk, &pid, "transfer_public", vec![], 0)
        .await;
    assert!(result.is_err());
}

// ── deploy_program (error path — parse failure before network call) ────────

#[tokio::test]
async fn test_deploy_program_invalid_source() {
    let mock_server = MockServer::start().await;
    let mut client = make_client(&mock_server, &mock_server.uri());
    random_account(&mut client);
    let result = client.deploy_program("not valid aleo", 0).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("parse") || err.contains("Failed to parse") || err.contains("Program"),
        "expected parse error, got: {err}"
    );
}

#[tokio::test]
async fn test_deploy_program_no_account() {
    let mock_server = MockServer::start().await;
    let client = make_client(&mock_server, &mock_server.uri());
    let result = client
        .deploy_program(
            "program test.aleo;\nfunction foo:\n    input r0 as u32.public;\n",
            0,
        )
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("No account set"),
        "expected 'No account set', got: {err}"
    );
}

// ── get_balance (REST success path — verified against real API) ──────────

#[tokio::test]
async fn test_get_balance_rest_parse_ok() {
    let mock_server = MockServer::start().await;
    // REST mapping endpoint returns a valid u64 string
    Mock::given(method("GET"))
        .and(path_regex(
            r"/v2/testnet/program/credits\.aleo/mapping/account/.+",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"\"500000u64\"", "text/plain"))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/testnet/block/height/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"20457000", "text/plain"))
        .mount(&mock_server)
        .await;

    let mut client = make_client(&mock_server, &mock_server.uri());
    random_account(&mut client);

    let balance = client.get_balance().await.unwrap();
    assert_eq!(balance, Some(500_000));
}

// ── find_private_credits_records ──────────────────────────────────────────

#[tokio::test]
async fn test_find_private_credits_records_no_account() {
    let mock_server = setup_mock().await;
    let client = make_client(&mock_server, &mock_server.uri());
    let result = client.find_private_credits_records().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_find_private_credits_records_empty() {
    let mock_server = MockServer::start().await;
    // Records endpoint returns empty
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": []
        })))
        .mount(&mock_server)
        .await;

    // Need block height
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"20457000", "text/plain"))
        .mount(&mock_server)
        .await;

    let mut client = make_client(&mock_server, &mock_server.uri());
    random_account(&mut client);

    let records = client.find_private_credits_records().await.unwrap();
    assert!(records.is_empty());
}

// ── verify_execution (error path — invalid transaction JSON) ──────────────

#[tokio::test]
async fn test_verify_execution_wrong_type_returns_non_proof_msg() {
    // Test with a JSON mock that fetches a fake transaction but snarkVM can't deserialize it
    // This exercises the error path (deserialization failure)
    let mock_server = MockServer::start().await;
    // Return an empty JSON object - will fail deserialization
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"{}", "application/json"))
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server, &mock_server.uri());
    let result = client.verify_execution("at1fake").await;
    // Should fail because empty object doesn't match Transaction enum
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("deserialize") || err.contains("Failed"),
        "expected deserialization error, got: {err}"
    );
}

// ── verify_execution (edge cases) ──────────────────────────────────────────

#[tokio::test]
async fn test_client_verify_execution_fails_on_invalid_tx_id() {
    let mock_server = setup_mock().await;
    let client = make_client(&mock_server, &mock_server.uri());
    let result = client.verify_execution("not_a_real_tx_id").await;
    // fetch_transaction will get 404 from the catch-all GET mock
    assert!(result.is_err());
}

// ── fetch_unspent_records ──────────────────────────────────────────────────

#[tokio::test]
async fn test_client_fetch_unspent_records() {
    let mock_server = setup_mock().await;
    let mut client = make_client(&mock_server, &mock_server.uri());
    random_account(&mut client);

    let result = client.fetch_unspent_records().await.unwrap();
    // Should return empty array JSON
    assert_eq!(result, "[]");
}

// ── get_balance (REST 404 → fallback path, both now use same REST endpoint) ─

#[tokio::test]
async fn test_get_balance_rest_404_returns_none() {
    // When REST returns 404 (no mapping entry), get_balance returns None
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(
            r"/v2/testnet/program/credits\.aleo/mapping/account/.+",
        ))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/testnet/block/height/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"20457000", "text/plain"))
        .mount(&mock_server)
        .await;

    let mut client = make_client(&mock_server, &mock_server.uri());
    random_account(&mut client);

    let balance = client.get_balance().await.unwrap();
    assert_eq!(balance, None, "expected None for 404 response");
}

// ── verify_execution (Fee-like transaction: invalid JSON → deserialization err) ─

#[tokio::test]
async fn test_verify_execution_invalid_json_err() {
    let mock_server = MockServer::start().await;
    // Return JSON that looks like a transaction but doesn't match snarkVM's enum
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            br#"{"type":"Fee","execution":null,"deployment":null}"#,
            "application/json",
        ))
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server, &mock_server.uri());
    let result = client.verify_execution("at1feefake").await;
    // Deserialization will fail because JSON doesn't match any Transaction variant
    assert!(
        result.is_err(),
        "expected deserialization error for invalid Transaction JSON"
    );
}

// ── verify_execution against a real, committed proof ──────────────────────
//
// The tests above only cover the deserialization failure. The success path —
// "does `verify_execution` actually verify a proof?" — is what the whole API
// promises, so it is checked against a real Varuna-proved `credits.aleo::
// transfer_public` transaction captured from this SDK (see
// `real_prove.rs::regenerate_verify_fixture`). No network, no proving.

fn fixture_envelope() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/credits_execute_tx.json");
    let raw =
        std::fs::read(&path).unwrap_or_else(|e| panic!("missing fixture {}: {e}", path.display()));
    serde_json::from_slice(&raw).expect("fixture is not valid JSON")
}

/// Serve the fixture transaction, the fixture block height, and the real
/// `credits.aleo` source (taken from a loaded `Process`, so it is exactly what
/// the verifier expects).
async fn mount_verify_fixture(server: &MockServer, tx: &serde_json::Value, height: u32) {
    Mock::given(method("GET"))
        .and(path_regex(r"/v2/testnet/transaction/.+"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(serde_json::to_vec(tx).unwrap(), "application/json"),
        )
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/testnet/block/height/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_string(height.to_string()))
        .mount(server)
        .await;

    let credits_src = {
        use snarkvm::prelude::FromStr as _;
        use snarkvm::synthesizer::program::StackTrait as _;
        let engine = aleo_rust_sdk::ExecutionEngine::new().unwrap();
        let id =
            snarkvm::prelude::ProgramID::<snarkvm::prelude::TestnetV0>::from_str("credits.aleo")
                .unwrap();
        engine.process.lock().get_stack(id).unwrap().program().to_string()
    };
    Mock::given(method("GET"))
        .and(path("/v2/testnet/program/credits.aleo"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            serde_json::to_vec(&credits_src).unwrap(),
            "application/json",
        ))
        .mount(server)
        .await;
}

#[tokio::test]
async fn test_verify_execution_accepts_real_proof() {
    let envelope = fixture_envelope();
    let tx = envelope["transaction"].clone();
    let height = envelope["block_height"].as_u64().unwrap() as u32;
    let tx_id = envelope["transaction_id"].as_str().unwrap().to_string();

    let mock_server = MockServer::start().await;
    mount_verify_fixture(&mock_server, &tx, height).await;

    let client = make_client(&mock_server, &mock_server.uri());
    let report = client
        .verify_execution(&tx_id)
        .await
        .expect("a real on-chain proof must verify");

    assert!(
        report.contains("VERIFIED"),
        "expected a verification report, got: {report}"
    );
    assert!(
        report.contains("credits.aleo"),
        "report should name the program, got: {report}"
    );
    assert!(
        report.contains("transfer_public"),
        "report should name the function, got: {report}"
    );
    // Read the expected transition count from the fixture itself so this
    // assertion cannot rot if the fixture is ever regenerated differently.
    let transitions = tx["execution"]["transitions"].as_array().unwrap().len();
    assert!(
        report.contains(&format!("Transitions: {transitions}")),
        "expected {transitions} transitions in the report, got: {report}"
    );
}

#[tokio::test]
async fn test_verify_execution_rejects_tampered_proof() {
    let envelope = fixture_envelope();
    let height = envelope["block_height"].as_u64().unwrap() as u32;
    let tx_id = envelope["transaction_id"].as_str().unwrap().to_string();

    // Swap the transfer amount for a different (still well-typed) value. The
    // proof commits to the original public inputs, so verification must fail.
    let mut tampered = envelope["transaction"].clone();
    let amount = &mut tampered["execution"]["transitions"][0]["inputs"][1]["value"];
    assert_eq!(amount.as_str(), Some("1000000u64"), "fixture shape changed");
    *amount = serde_json::json!("1000001u64");

    let mock_server = MockServer::start().await;
    mount_verify_fixture(&mock_server, &tampered, height).await;

    let client = make_client(&mock_server, &mock_server.uri());
    let result = client.verify_execution(&tx_id).await;
    let err = result.expect_err("a tampered transaction must not verify");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Execution proof verification FAILED"),
        "tampering must be caught by the proof verifier, not the parser: {msg}"
    );
}

/// The consensus version — and with it the Varuna version — must come from the
/// height the transaction was mined at, not from `block/height/latest`.
///
/// This fixture was proven at consensus V22 (Varuna V3). Serving a *latest*
/// height that maps to an older consensus version must therefore reject it,
/// while `verify_execution_at` with the right height still accepts it. If this
/// test ever goes green on both calls, verification has stopped depending on
/// the consensus version and the whole check is worthless.
#[tokio::test]
async fn test_verify_execution_depends_on_consensus_height() {
    let envelope = fixture_envelope();
    let tx = envelope["transaction"].clone();
    let mined_at = envelope["block_height"].as_u64().unwrap() as u32;
    let tx_id = envelope["transaction_id"].as_str().unwrap().to_string();

    // 19_000_000 is consensus V19 on testnet — a different Varuna version.
    let mock_server = MockServer::start().await;
    mount_verify_fixture(&mock_server, &tx, 19_000_000).await;
    let client = make_client(&mock_server, &mock_server.uri());

    let via_latest = client.verify_execution(&tx_id).await;
    assert!(
        via_latest.is_err(),
        "a V22 proof must not verify under the consensus of an older height; got: {via_latest:?}"
    );

    let via_mined_height = client.verify_execution_at(&tx_id, mined_at).await;
    assert!(
        via_mined_height.is_ok(),
        "the same proof must verify at its own height {mined_at}; got: {via_mined_height:?}"
    );
}
