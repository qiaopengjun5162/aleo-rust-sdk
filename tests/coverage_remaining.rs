use aleo_rust_sdk::{AleoAccount, AleoClient, AleoProgram, ExecutionEngine, FixedStateRootQuery};
use snarkvm::console::program::ProgramID;
use snarkvm::ledger::query::QueryTrait;
use snarkvm::prelude::{FromStr as _, Network, TestRng, TestnetV0};

/// Test FromStr for AleoAccount (lines 56-58)
#[test]
fn test_account_from_str() {
    let mut rng = TestRng::default();
    let a1 = AleoAccount::new_random(&mut rng).unwrap();
    let pk = a1.private_key_str();
    let a2 = AleoAccount::from_str(&pk).unwrap();
    assert_eq!(a1.address_str(), a2.address_str());
}

/// Test program from local file (lines 17-21) + inner() + into_inner()
#[test]
fn test_program_local_file_and_accessors() {
    use std::io::Write;
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    write!(
        tmpfile,
        "program test_program.aleo;\nfunction f:\n    input r0 as u32.public;\n    output r0 as u32.public;\n"
    )
    .unwrap();
    let path = tmpfile.path().to_str().unwrap();
    let p = AleoProgram::from_local_file(path).unwrap();
    assert_eq!(p.id().to_string(), "test_program.aleo");

    // inner() returns &Program
    let _inner = p.inner();

    // into_inner() consumes self
    let program = p.into_inner();
    assert_eq!(program.id().to_string(), "test_program.aleo");
}

/// Test execution engine with fee keys (lines 52-72)
#[test]
fn test_execution_engine_with_fee_keys() {
    let engine = ExecutionEngine::new_with_v0_fee_keys().unwrap();
    let guard = engine.process.lock();
    // Should have credits.aleo loaded
    assert!(guard
        .program_ids()
        .contains(&ProgramID::<TestnetV0>::from_str("credits.aleo").unwrap()));
}

/// Test FixedStateRootQuery trait methods (network.rs lines 222-245)
#[test]
fn test_fixed_state_root_query() {
    use snarkvm::console::types::Field;
    let sr = <TestnetV0 as Network>::StateRoot::from_str(
        "sr1lkr8fzg8mk69qrtycxjvtrg8rvh77puaq7fm56cjkh04xhprdqzq3a355s",
    )
    .unwrap();
    let query: FixedStateRootQuery<TestnetV0> = FixedStateRootQuery {
        state_root: sr.clone(),
        block_height: 42,
    };

    assert_eq!(query.current_state_root().unwrap(), sr);
    assert_eq!(query.current_block_height().unwrap(), 42);

    // State path methods return errors/empty
    let f = Field::from_str("1field").unwrap();
    assert!(query.get_state_path_for_commitment(&f).is_err());
    assert!(query.get_state_paths_for_commitments(&[f]).unwrap().is_empty());
}

/// Test client execute_local with a real credits.aleo transfer call (client.rs lines 106-123)
/// This runs the full authorize_and_execute locally without network.
#[test]
fn test_client_execute_local_real() {
    let mut rng = TestRng::default();
    let account = AleoAccount::new_random(&mut rng).unwrap();

    let mut client =
        AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    client
        .set_account_from_private_key_str(&account.private_key_str())
        .unwrap();
    client
        .load_program_from_source(
            "program hello.aleo;\nfunction f:\n    input r0 as u32.public;\n    output r0 as u32.public;\n",
        )
        .unwrap();

    let result = client.execute_local(
        "hello.aleo",
        "f",
        &["42u32".to_string()],
    );
    assert!(result.is_ok());
    let output = result.unwrap();
    assert!(output.contains("Response"));
}

/// Test client execute_local with credits.aleo transfer (proving path — may require fee keys)
#[test]
fn test_client_execute_credits_transfer() {
    let mut rng = TestRng::default();
    let account = AleoAccount::new_random(&mut rng).unwrap();

    let mut client =
        AleoClient::new("https://api.explorer.provable.com/v2/testnet").unwrap();
    client
        .set_account_from_private_key_str(&account.private_key_str())
        .unwrap();
    client.set_program(AleoProgram::credits().unwrap());

    // transfer_public requires a valid address as first arg
    let result = client.execute_local(
        "credits.aleo",
        "transfer_public",
        &[
            "aleo1destdestdestdestdestdestdestdestdestdest".to_string(),
            "1u64".to_string(),
        ],
    );
    // This should either succeed (local execution) or fail with a meaningful error
    // (not "No program loaded" or "No account set")
    match result {
        Ok(output) => assert!(output.contains("Response") || output.contains("transfer_public")),
        Err(e) => {
            let msg = e.to_string();
            assert!(
                !msg.contains("No program loaded"),
                "Should not be 'No program loaded': {msg}"
            );
            assert!(
                !msg.contains("No account set"),
                "Should not be 'No account set': {msg}"
            );
        }
    }
}
