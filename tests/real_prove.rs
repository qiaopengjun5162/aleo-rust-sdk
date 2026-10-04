use aleo_rust_sdk::{AleoClient, ExecutionEngine, FixedStateRootQuery};
use snarkvm::prelude::{Address, ComputeKey};
use snarkvm::prelude::{FromStr as _, Network, PrivateKey, Program, ProgramID, TestRng, TestnetV0};

/// Real Varuna V2 proof for hello.aleo (u32 addition).
/// Covers the full prove_and_package pipeline: trace.prepare → prove_execution →
/// authorize_fee_public → execute_fee → prove_fee → verify → Transaction::from_execution.
///
/// Marked `#[ignore]` because Varuna proving takes ~15-30s.
#[test]
#[ignore = "slow: Varuna proving takes 15-30s"]
fn test_real_varuna_prove_hello() {
    let mut rng = TestRng::default();
    let pk: PrivateKey<TestnetV0> = PrivateKey::new(&mut rng).unwrap();

    // ── Program ──────────────────────────────────────────────────────
    let hello_src = "program hello.aleo;\nfunction hello:\n    input r0 as u32.public;\n    input r1 as u32.private;\n    add r0 r1 into r2;\n    output r2 as u32.private;\n";
    let program = Program::<TestnetV0>::from_str(hello_src).unwrap();
    let program_id = ProgramID::<TestnetV0>::from_str("hello.aleo").unwrap();

    // ── Engine ───────────────────────────────────────────────────────
    let engine = ExecutionEngine::new_with_v0_fee_keys().unwrap();
    engine.add_program(&program).unwrap();

    // ── Authorize + execute locally ──────────────────────────────────
    let (_response, trace) = engine
        .authorize_and_execute(&pk, &program_id, "hello", vec!["1u32", "2u32"], &mut rng)
        .unwrap();

    // ── Query ────────────────────────────────────────────────────────
    let state_root = <TestnetV0 as Network>::StateRoot::from_str(
        "sr1lkr8fzg8mk69qrtycxjvtrg8rvh77puaq7fm56cjkh04xhprdqzq3a355s",
    )
    .unwrap();
    let query = FixedStateRootQuery {
        state_root,
        block_height: 42,
    };

    // ── Prove + package ──────────────────────────────────────────────
    let tx = engine
        .prove_and_package(trace, &pk, &program_id, "hello", 1, 0, &query, &mut rng)
        .unwrap();

    // ── Verify ───────────────────────────────────────────────────────
    let tx_json = serde_json::to_string(&tx).unwrap();
    println!("Transaction ID: {:?}", tx.id());
    println!("Transaction JSON length: {}", tx_json.len());
    assert!(tx_json.len() > 100);
}

/// Full end-to-end: real Varuna proof + mock broadcast.
/// Covers client.rs lines 158, 171, 172, 174 (the `execute_and_broadcast` tail).
#[tokio::test]
#[ignore = "slow: Varuna proving takes 60s"]
async fn test_execute_and_broadcast_real_prove() {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    let mock_server = MockServer::start().await;
    let base_url = mock_server.uri();
    let rpc_url = format!("{}/jsonrpc", base_url);

    // Mock program fetch: hello.aleo
    let hello_src = "program hello.aleo;\nfunction hello:\n    input r0 as u32.public;\n    input r1 as u32.private;\n    add r0 r1 into r2;\n    output r2 as u32.private;\n";
    Mock::given(method("GET"))
        .and(path("/program/hello.aleo"))
        .respond_with(ResponseTemplate::new(200).set_body_string(hello_src))
        .mount(&mock_server)
        .await;

    // Mock state_root + block_height
    Mock::given(method("GET"))
        .and(path("/stateRoot/latest"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                "\"sr1lkr8fzg8mk69qrtycxjvtrg8rvh77puaq7fm56cjkh04xhprdqzq3a355s\"",
            ),
        )
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/block/height/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_string("42"))
        .mount(&mock_server)
        .await;

    // Mock broadcast endpoint: returns a tx ID
    Mock::given(method("POST"))
        .and(path("/transaction/broadcast"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("\"at1mocktxid1234567890123456789012345678901234567890\""),
        )
        .mount(&mock_server)
        .await;

    let mut client = AleoClient::new_with_rpc(&base_url, &rpc_url).unwrap();
    let mut rng = TestRng::default();
    let pk: PrivateKey<TestnetV0> = PrivateKey::new(&mut rng).unwrap();
    let _ = client.set_account_from_private_key_str(&pk.to_string());

    let program_id = ProgramID::<TestnetV0>::from_str("hello.aleo").unwrap();

    let tx_id = client
        .execute_and_broadcast(&pk, &program_id, "hello", vec!["1u32", "2u32"], 1, 0)
        .await
        .unwrap();

    println!("Broadcasted tx_id: {}", tx_id);
    assert!(
        tx_id.contains("at1mocktxid"),
        "tx_id should contain at1mocktxid, got: {}",
        tx_id
    );
}

/// Cover client.rs line 158 (`?` after authorize_and_execute) by making
/// the authorize step fail with a non-existent function name.
#[tokio::test]
#[ignore = "slow: Varuna proving takes 60s"]
async fn test_execute_and_broadcast_authorize_fails() {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    let mock_server = MockServer::start().await;
    let base_url = mock_server.uri();
    let rpc_url = format!("{}/jsonrpc", base_url);

    let hello_src = "program hello.aleo;\nfunction hello:\n    input r0 as u32.public;\n    input r1 as u32.private;\n    add r0 r1 into r2;\n    output r2 as u32.private;\n";
    Mock::given(method("GET"))
        .and(path("/program/hello.aleo"))
        .respond_with(ResponseTemplate::new(200).set_body_string(hello_src))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/stateRoot/latest"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                "\"sr1lkr8fzg8mk69qrtycxjvtrg8rvh77puaq7fm56cjkh04xhprdqzq3a355s\"",
            ),
        )
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/block/height/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_string("42"))
        .mount(&mock_server)
        .await;

    let mut client = AleoClient::new_with_rpc(&base_url, &rpc_url).unwrap();
    let mut rng = TestRng::default();
    let pk: PrivateKey<TestnetV0> = PrivateKey::new(&mut rng).unwrap();
    let _ = client.set_account_from_private_key_str(&pk.to_string());

    let program_id = ProgramID::<TestnetV0>::from_str("hello.aleo").unwrap();

    // Non-existent function → authorize_and_execute fails → hits line 158 `?`
    let result = client
        .execute_and_broadcast(&pk, &program_id, "nonexistent_fn", vec!["1u32"], 1, 0)
        .await;

    assert!(result.is_err(), "Expected error from nonexistent function");
}

/// Cover execution.rs:166 — multiple transitions from the SAME program.
/// `credits.aleo::transfer_public` produces 2 transitions (sender + recipient),
/// both with program_id = credits.aleo. The 2nd hits `contains_key == true`, skipping
/// the `get_stack` body and going directly to the closing brace on line 166.
#[test]
#[ignore = "slow: Varuna proving takes ~60s"]
fn test_prove_multiple_same_program_transitions() {
    let mut rng = TestRng::default();
    let pk: PrivateKey<TestnetV0> = PrivateKey::new(&mut rng).unwrap();
    let pk_addr = Address::try_from(&ComputeKey::try_from(&pk).unwrap()).unwrap();

    let program_id = ProgramID::<TestnetV0>::from_str("credits.aleo").unwrap();

    let engine = ExecutionEngine::new_with_v0_fee_keys().unwrap();

    let (_response, trace) = engine
        .authorize_and_execute(
            &pk,
            &program_id,
            "transfer_public",
            vec![&pk_addr.to_string(), "1000000u64"],
            &mut rng,
        )
        .unwrap();

    let state_root = <TestnetV0 as Network>::StateRoot::from_str(
        "sr1lkr8fzg8mk69qrtycxjvtrg8rvh77puaq7fm56cjkh04xhprdqzq3a355s",
    )
    .unwrap();
    let query = FixedStateRootQuery {
        state_root,
        block_height: 42,
    };

    let tx = engine
        .prove_and_package(
            trace,
            &pk,
            &program_id,
            "transfer_public",
            1,
            0,
            &query,
            &mut rng,
        )
        .unwrap();

    let tx_json = serde_json::to_string(&tx).unwrap();
    println!("Transfer TX ID: {:?}", tx.id());
    println!("JSON length: {}", tx_json.len());
    assert!(tx_json.len() > 100);
}
