use aleo_rust_sdk::{AleoAccount, AleoClient, AleoProgram};
use snarkvm::prelude::TestRng;

/// Minimal credits.aleo source with just `transfer_public` stub for local execution.
const HELLO_PROGRAM: &str = "program credits.aleo;\n\nfunction transfer_public:\n    input r0 as address.public;\n    input r1 as u64.public;\n";

// ── Construction ────────────────────────────────────────────────────────────

#[test]
fn test_client_new() {
    let client = AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    assert_eq!(
        client.network.base_url,
        "https://api.explorer.provable.com/v2/testnet"
    );
}

#[test]
fn test_client_new_with_rpc() {
    let client = AleoClient::new_with_rpc(
        "https://api.explorer.provable.com/v2/testnet",
        "https://testnetbeta.aleorpc.com",
    )
    .unwrap();
    assert_eq!(
        client.network.base_url,
        "https://api.explorer.provable.com/v2/testnet"
    );
}

#[test]
fn test_client_new_invalid_url() {
    // AleoClient::new doesn't validate URL format (just stores it)
    let result = AleoClient::new("not-a-valid-url");
    assert!(result.is_ok(), "constructor stores URL without validation");
    let client = result.unwrap();
    assert_eq!(client.network.base_url, "not-a-valid-url");
}

// ── Account management ──────────────────────────────────────────────────────

#[test]
fn test_set_account_from_private_key() {
    let mut rng = TestRng::default();
    let account = AleoAccount::new_random(&mut rng).unwrap();

    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    client.set_account_from_private_key_str(&account.private_key_str()).unwrap();
    assert!(client.require_account().is_ok());
}

#[test]
fn test_require_account_not_set() {
    let client = AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    let result = client.require_account();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("No account set") || err.contains("not set"),
        "expected 'No account set', got: {err}"
    );
}

#[test]
fn test_set_account_invalid_key() {
    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    let result = client.set_account_from_private_key_str("not-a-private-key");
    assert!(result.is_err());
}

#[test]
fn test_set_account_empty_key() {
    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    let result = client.set_account_from_private_key_str("");
    assert!(result.is_err());
}

// ── Program management ──────────────────────────────────────────────────────

#[test]
fn test_load_program_from_source() {
    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    client.load_program_from_source(HELLO_PROGRAM).unwrap();
    let program = client.require_program().unwrap();
    assert_eq!(program.id().to_string(), "credits.aleo");
}

#[test]
fn test_require_program_not_set() {
    let client = AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    let result = client.require_program();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("No program loaded"),
        "expected 'No program loaded', got: {err}"
    );
}

#[test]
fn test_set_program_directly() {
    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    let program = AleoProgram::credits().unwrap();
    client.set_program(program);
    let loaded = client.require_program().unwrap();
    assert_eq!(loaded.id().to_string(), "credits.aleo");
}

#[test]
fn test_load_invalid_program_source() {
    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    let result = client.load_program_from_source("not valid aleo source");
    assert!(result.is_err());
}

// ── Local execution (dry-run) ───────────────────────────────────────────────

#[test]
fn test_execute_local_transfer_public() {
    let mut rng = TestRng::default();
    let account = AleoAccount::new_random(&mut rng).unwrap();

    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    client.set_account_from_private_key_str(&account.private_key_str()).unwrap();

    // Use the account's own address as the recipient
    let addr = account.address_str();

    // credits.aleo is built-in; no need to pre-load
    let result = client.execute_local(
        "credits.aleo",
        "transfer_public",
        &[addr, "1000000u64".to_string()],
    );

    // Local execution should complete without proving/broadcasting
    assert!(result.is_ok(), "local execution failed: {:?}", result.err());
}

#[test]
fn test_execute_local_no_account() {
    let client = AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    let result = client.execute_local(
        "credits.aleo",
        "transfer_public",
        &["aleo1...".to_string(), "1".to_string()],
    );
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("account") || err.contains("No account"),
        "expected account error, got: {err}"
    );
}

#[test]
fn test_execute_local_invalid_program_id() {
    let mut rng = TestRng::default();
    let account = AleoAccount::new_random(&mut rng).unwrap();

    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    client.set_account_from_private_key_str(&account.private_key_str()).unwrap();

    let result = client.execute_local("nonexistent.aleo", "foo", &["1".to_string()]);
    assert!(result.is_err());
}

// ── Edge cases ──────────────────────────────────────────────────────────────

#[test]
fn test_double_set_account() {
    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    let mut rng = TestRng::default();

    let account1 = AleoAccount::new_random(&mut rng).unwrap();
    let account2 = AleoAccount::new_random(&mut rng).unwrap();

    client.set_account_from_private_key_str(&account1.private_key_str()).unwrap();
    let addr1 = client.require_account().unwrap().address_str();

    client.set_account_from_private_key_str(&account2.private_key_str()).unwrap();
    let addr2 = client.require_account().unwrap().address_str();

    assert_ne!(
        addr1, addr2,
        "addresses should differ after re-setting account"
    );
}

#[test]
fn test_overwrite_program() {
    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();

    let program1 = AleoProgram::credits().unwrap();
    client.set_program(program1);
    let id1 = client.require_program().unwrap().id().to_string();

    // credits.aleo has a specific ID; we just verify overwriting doesn't panic
    let program2 = AleoProgram::credits().unwrap();
    client.set_program(program2);
    let id2 = client.require_program().unwrap().id().to_string();

    assert_eq!(id1, id2, "same program type should keep same ID");
}

#[test]
fn test_credentials_program_has_correct_id() {
    let program = AleoProgram::credits().unwrap();
    assert_eq!(program.id().to_string(), "credits.aleo");
}

#[test]
fn test_client_send_sync() {
    // Compile-time check: AleoClient must implement Send + Sync
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<AleoClient>();
    assert_sync::<AleoClient>();
}
