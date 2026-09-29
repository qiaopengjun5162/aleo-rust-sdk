use aleo_rust_sdk::AleoAccount;
use aleo_rust_sdk::AleoClient;
use aleo_rust_sdk::AleoHttpClient;
use aleo_rust_sdk::AleoProgram;
use aleo_rust_sdk::ExecutionEngine;
use snarkvm::prelude::{FromStr, TestRng};

/// Test that a new account can be created and keys are consistent.
#[test]
fn test_account_creation() {
    let mut rng = TestRng::default();
    let account = AleoAccount::new_random(&mut rng).unwrap();
    assert!(!account.private_key_str().is_empty());
    assert!(!account.view_key.to_string().is_empty());
    assert!(!account.address_str().is_empty());
    // Address != private key
    assert_ne!(account.private_key_str(), account.address_str());
}

/// Test that account reconstruction from private key string works.
#[test]
fn test_account_from_private_key() {
    let mut rng = TestRng::default();
    let a1 = AleoAccount::new_random(&mut rng).unwrap();
    let pk = a1.private_key_str();
    let a2 = AleoAccount::from_private_key_str(&pk).unwrap();
    assert_eq!(a1.address_str(), a2.address_str());
    assert_eq!(a1.view_key.to_string(), a2.view_key.to_string());
}

/// Test that credits program loads and has expected ID.
#[test]
fn test_credits_program_id() {
    let program = AleoProgram::credits().unwrap();
    assert_eq!(
        program.id().to_string(),
        "credits.aleo",
        "Built-in credits program must be credits.aleo"
    );
}

/// Test that a simple program can be parsed from source.
#[test]
fn test_program_from_source() {
    let src = r#"
program hello.aleo;

function greet:
    input r0 as u32.public;
    output r0 as u32.public;
"#;
    let program = AleoProgram::from_source(src).unwrap();
    assert_eq!(program.id().to_string(), "hello.aleo");
}

/// Test execution engine initialization (doesn't require network).
#[test]
fn test_execution_engine_new() {
    let engine = ExecutionEngine::new().unwrap();
    // Engine loads credits.aleo by default; just verify it doesn't error
    let guard = engine.process.lock();
    let pids = guard.program_ids();
    assert!(
        pids.contains(&snarkvm::console::program::ProgramID::from_str("credits.aleo").unwrap()),
        "Built-in credits.aleo program should be loaded"
    );
}

/// Test that AleoHttpClient can be created.
#[test]
fn test_http_client_creation() {
    let client =
        AleoHttpClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    assert_eq!(client.base_url, "https://api.explorer.provable.com/v2/testnet");
}

/// Test that AleoClient can be constructed without account.
#[test]
fn test_client_new() {
    let client =
        AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    assert!(
        client.require_account().is_err(),
        "Fresh client should have no account"
    );
}

/// Test that client account setup works.
#[test]
fn test_client_set_account() {
    let mut rng = TestRng::default();
    let account = AleoAccount::new_random(&mut rng).unwrap();
    let pk = account.private_key_str();

    let mut client =
        AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    client.set_account_from_private_key_str(&pk).unwrap();
    assert!(client.require_account().is_ok());
    assert_eq!(client.require_account().unwrap().address_str(), account.address_str());
}

/// Test program loading in client.
#[test]
fn test_client_program_load() {
    let mut client =
        AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    client.load_program_from_source(
        "program hello.aleo;\nfunction f:\n    input r0 as u32.public;\n    output r0 as u32.public;\n",
    ).unwrap();
    assert!(client.require_program().is_ok());
}

/// Test credits program via client set_program.
#[test]
fn test_client_credits_program() {
    let credits = AleoProgram::credits().unwrap();
    let mut client =
        AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    client.set_program(credits);
    assert_eq!(
        client.require_program().unwrap().id().to_string(),
        "credits.aleo"
    );
}
