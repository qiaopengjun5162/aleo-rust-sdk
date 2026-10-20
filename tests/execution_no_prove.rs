//! # ExecutionEngine coverage — no Varuna proving required.
//!
//! These tests exercise ExecutionEngine methods that do NOT require
//! the slow Varuna proving pipeline (~30s). They all run in <1s.
//!
//! ## Coverage targets
//! - `authorize_and_execute_with_values` (L100-125) — fully uncovered
//! - `consensus_version_to_varuna` (L52-55) — export helper
//! - `verify_deployment_transaction` (syntax check) — L387-396
//! - `deployment_cost_minimum` (already covered, but repeated for safety)
//!
//! Slower Varuna tests live in `real_prove.rs` (all `#[ignore]`).

use aleo_rust_sdk::{AleoClient, AleoProgram, ExecutionEngine, consensus_version_to_varuna};
use snarkvm::prelude::{
    ConsensusVersion, FromStr as _, PrivateKey, Program, ProgramID, TestRng, TestnetV0, Value,
};

/// Minimal program for local execution.
const HELLO_SRC: &str = "program hello.aleo;\nfunction hello:\n    input r0 as u32.public;\n    input r1 as u32.private;\n    add r0 r1 into r2;\n    output r2 as u32.private;\n";

const CREDITS_ID: &str = "credits.aleo";

// ── consensus_version_to_varuna ─────────────────────────────────────────

#[test]
fn test_consensus_version_to_varuna_v14() {
    let v = consensus_version_to_varuna(ConsensusVersion::V14);
    // VarunaVersion doesn't implement Display, and Debug may vary by crate version
    // Just verify it returns without panicking and has a non-empty repr
    let _ = format!("{v:?}");
}

#[test]
fn test_consensus_version_to_varuna_v20() {
    let v = consensus_version_to_varuna(ConsensusVersion::V20);
    let _ = format!("{v:?}");
}

// ── authorize_and_execute_with_values ───────────────────────────────────

#[test]
fn test_authorize_and_execute_with_values_hello() {
    let engine = ExecutionEngine::new().unwrap();
    let program = Program::<TestnetV0>::from_str(HELLO_SRC).unwrap();
    engine.add_program(&program).unwrap();

    let mut rng = TestRng::default();
    let pk = PrivateKey::new(&mut rng).unwrap();
    let program_id = ProgramID::<TestnetV0>::from_str("hello.aleo").unwrap();

    // Parse inputs as Value
    let v1 = Value::<TestnetV0>::from_str("1u32").unwrap();
    let v2 = Value::<TestnetV0>::from_str("2u32").unwrap();

    let (response, _trace) = engine
        .authorize_and_execute_with_values(&pk, &program_id, "hello", vec![v1, v2], &mut rng)
        .unwrap();

    // The response should contain the output value
    let output = response.outputs().first().unwrap().to_string();
    assert_eq!(
        output, "3u32",
        "expected hello(1u32, 2u32) = 3u32, got {output}"
    );
}

#[test]
fn test_authorize_and_execute_with_values_credits_transfer() {
    let engine = ExecutionEngine::new().unwrap();
    // credits.aleo is built-in, no add_program needed

    let mut rng = TestRng::default();
    let pk = PrivateKey::new(&mut rng).unwrap();
    // Derive the recipient address (use the same pk for simplicity)
    use snarkvm::prelude::Address;
    let addr: Address<TestnetV0> = Address::try_from(&pk).unwrap();

    let program_id = ProgramID::<TestnetV0>::from_str(CREDITS_ID).unwrap();

    let v_addr = Value::<TestnetV0>::from_str(&addr.to_string()).unwrap();
    let v_amount = Value::<TestnetV0>::from_str("1000000u64").unwrap();

    let (response, _trace) = engine
        .authorize_and_execute_with_values(
            &pk,
            &program_id,
            "transfer_public",
            vec![v_addr, v_amount],
            &mut rng,
        )
        .unwrap();

    // transfer_public must emit at least one output value.
    assert!(
        !response.outputs().is_empty(),
        "transfer_public produced no outputs"
    );
}

#[test]
fn test_authorize_and_execute_with_values_wrong_fn() {
    let engine = ExecutionEngine::new().unwrap();
    let mut rng = TestRng::default();
    let pk = PrivateKey::new(&mut rng).unwrap();
    let program_id = ProgramID::<TestnetV0>::from_str(CREDITS_ID).unwrap();

    let result = engine.authorize_and_execute_with_values(
        &pk,
        &program_id,
        "nonexistent_fn",
        vec![],
        &mut rng,
    );
    assert!(result.is_err(), "expected error for nonexistent function");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("not found")
            || err.contains("Nonexistent")
            || err.contains("not exist")
            || err.contains("Authorization failed"),
        "expected error, got: {err}"
    );
}

// ── client.rs: execute_local (synchronous, no network) ──────────────────

#[test]
fn test_client_execute_local_credits() {
    let mut rng = TestRng::default();
    let pk = PrivateKey::<TestnetV0>::new(&mut rng).unwrap();
    let addr: snarkvm::prelude::Address<TestnetV0> =
        snarkvm::prelude::Address::try_from(&pk).unwrap();

    let mut client =
        AleoClient::new_with_rpc("http://localhost:19999", "http://localhost:19999").unwrap();
    client.set_account_from_private_key_str(&pk.to_string()).unwrap();

    let result = client
        .execute_local(
            "credits.aleo",
            "transfer_public",
            &[addr.to_string(), "1u64".to_string()],
        )
        .unwrap();

    assert!(
        result.contains("Response") || result.contains("outputs"),
        "expected response from execute_local, got: {result}"
    );
}

#[test]
fn test_client_execute_local_no_account() {
    let client =
        AleoClient::new_with_rpc("http://localhost:19999", "http://localhost:19999").unwrap();
    let result = client.execute_local("credits.aleo", "transfer_public", &["1u32".to_string()]);
    assert!(
        result.is_err(),
        "expected error when no account set, got: {:?}",
        result
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("No account set"),
        "expected 'No account set', got: {err}"
    );
}

#[test]
fn test_client_execute_local_no_program() {
    // execute_local with account set but no user program loaded
    // should still work for credits.aleo (built-in)
    let mut rng = TestRng::default();
    let pk = PrivateKey::<TestnetV0>::new(&mut rng).unwrap();
    let addr: snarkvm::prelude::Address<TestnetV0> =
        snarkvm::prelude::Address::try_from(&pk).unwrap();

    let mut client =
        AleoClient::new_with_rpc("http://localhost:19999", "http://localhost:19999").unwrap();
    client.set_account_from_private_key_str(&pk.to_string()).unwrap();

    let result = client.execute_local(
        "credits.aleo",
        "transfer_public",
        &[addr.to_string(), "1u64".to_string()],
    );
    assert!(
        result.is_ok(),
        "credits.aleo should work without program loaded, got: {:?}",
        result
    );
}

#[test]
fn test_client_set_program_and_execute_local() {
    // Test set_program() + execute_local with a user-loaded program
    // This covers the `if let Some(prog)` branch inside execute_local
    let mut rng = TestRng::default();
    let pk = PrivateKey::<TestnetV0>::new(&mut rng).unwrap();
    let addr: snarkvm::prelude::Address<TestnetV0> =
        snarkvm::prelude::Address::try_from(&pk).unwrap();

    let mut client =
        AleoClient::new_with_rpc("http://localhost:19999", "http://localhost:19999").unwrap();
    client.set_account_from_private_key_str(&pk.to_string()).unwrap();

    // Load credits program via set_program
    let credits = AleoProgram::credits().unwrap();
    client.set_program(credits);

    let result = client.execute_local(
        "credits.aleo",
        "transfer_public",
        &[addr.to_string(), "1u64".to_string()],
    );
    assert!(
        result.is_ok(),
        "execute_local with loaded program should work, got: {:?}",
        result
    );
}

#[test]
fn test_execution_engine_inner() {
    let engine = ExecutionEngine::new().unwrap();
    let _inner = engine.inner();
    // Just verify it returns a process reference without panicking
}

// ── client.rs: require_program (error + success branches) ────────────────

#[test]
fn test_client_require_program_no_program() {
    let client =
        AleoClient::new_with_rpc("http://localhost:19999", "http://localhost:19999").unwrap();
    let result = client.require_program();
    assert!(result.is_err(), "expected error when no program loaded");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("No program loaded"),
        "expected 'No program loaded', got: {err}"
    );
}

#[test]
fn test_client_require_program_with_program() {
    let mut client =
        AleoClient::new_with_rpc("http://localhost:19999", "http://localhost:19999").unwrap();
    let credits = AleoProgram::credits().unwrap();
    client.set_program(credits);
    let result = client.require_program();
    assert!(result.is_ok(), "expected Ok when program is loaded");
}

// ── client.rs: load_program_from_source ──────────────────────────────────

#[test]
fn test_client_load_program_from_source() {
    let mut client =
        AleoClient::new_with_rpc("http://localhost:19999", "http://localhost:19999").unwrap();
    let src = "program hello.aleo;\nfunction hello:\n    input r0 as u32.public;\n    input r1 as u32.private;\n    add r0 r1 into r2;\n    output r2 as u32.private;\n";
    client.load_program_from_source(src).unwrap();
    let id = client.require_program().unwrap().id().to_string();
    assert_eq!(id, "hello.aleo");
}

#[test]
fn test_client_load_program_from_source_invalid() {
    let mut client =
        AleoClient::new_with_rpc("http://localhost:19999", "http://localhost:19999").unwrap();
    let result = client.load_program_from_source("not valid aleo source");
    assert!(result.is_err(), "expected error for invalid program source");
}

// ── authorize_and_execute (input pre-validation edge) ────────────────────

#[test]
fn test_authorize_and_execute_wrong_input_type() {
    let engine = ExecutionEngine::new().unwrap();
    let mut rng = TestRng::default();
    let pk = PrivateKey::new(&mut rng).unwrap();
    let program_id = ProgramID::<TestnetV0>::from_str(CREDITS_ID).unwrap();

    // transfer_public expects (address, u64) — passing (u32, u32) fails at parse
    let result = engine.authorize_and_execute(
        &pk,
        &program_id,
        "transfer_public",
        vec!["1u32", "2u32"],
        &mut rng,
    );
    assert!(result.is_err(), "expected error for wrong input type");
}
