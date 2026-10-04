use aleo_rust_sdk::{ExecutionEngine, FixedStateRootQuery};
use snarkvm::prelude::{ConsensusVersion, Network, PrivateKey, Program, TestRng, TestnetV0};
use std::str::FromStr;

/// Cover new_with_v0_fee_keys (lines 52-57)
#[test]
fn test_execution_engine_v0_fee_keys() {
    let engine = ExecutionEngine::new_with_v0_fee_keys().unwrap();
    let guard = engine.process.lock();
    let ids = guard.program_ids();
    assert!(!ids.is_empty());
    drop(guard);
}

/// Cover add_program (lines 75-78)
#[test]
fn test_execution_engine_add_program() {
    let engine = ExecutionEngine::new().unwrap();
    let credits = Program::<TestnetV0>::credits().unwrap();
    let r = engine.add_program(&credits);
    assert!(r.is_ok());
}

/// Cover inner() (lines 196-198)
#[test]
fn test_execution_engine_inner_with_credits() {
    let engine = ExecutionEngine::new().unwrap();
    let process_ref = engine.inner();
    let guard = process_ref.lock();
    assert!(!guard.program_ids().is_empty());
}

/// Minimal program source for deployment tests.
const HELLO_PROGRAM: &str = r"
program hello_deploy_test.aleo;

function hello:
    input r0 as u32.public;
    output r0 as u32.public;
";

/// Cover deploy_program — generate a pure deployment proof.
#[test]
fn test_deploy_program_generates_deployment() {
    let engine = ExecutionEngine::new_with_v0_fee_keys().unwrap();
    let program = Program::<TestnetV0>::from_str(HELLO_PROGRAM).unwrap();
    engine.add_program(&program).unwrap();

    let mut rng = TestRng::default();
    let deployment = engine.deploy_program(&program, &mut rng).unwrap();

    // Verify the deployment carries the expected program
    assert_eq!(
        deployment.program().id().to_string(),
        "hello_deploy_test.aleo"
    );
    assert!(
        !deployment.program().functions().is_empty(),
        "deployed program must have at least one function"
    );
}

/// Cover deployment_cost_minimum — compute min cost for a deployment.
#[test]
fn test_deployment_cost_minimum_computed() {
    let engine = ExecutionEngine::new_with_v0_fee_keys().unwrap();
    let program = Program::<TestnetV0>::from_str(HELLO_PROGRAM).unwrap();
    engine.add_program(&program).unwrap();

    let mut rng = TestRng::default();
    let deployment = engine.deploy_program(&program, &mut rng).unwrap();

    let min_cost = engine.deployment_cost_minimum(&deployment, ConsensusVersion::V14).unwrap();

    assert!(min_cost > 0, "deployment cost must be > 0, got {min_cost}");
    println!(
        "Minimum deployment cost: {min_cost} microcredits ({:.2} credits)",
        min_cost as f64 / 1_000_000.0
    );
}

/// Cover build_deployment_transaction — full pipeline without broadcast.
#[test]
fn test_build_deployment_transaction_local() {
    let engine = ExecutionEngine::new_with_v0_fee_keys().unwrap();
    let program = Program::<TestnetV0>::from_str(HELLO_PROGRAM).unwrap();
    engine.add_program(&program).unwrap();

    let mut rng = TestRng::default();
    let private_key = PrivateKey::new(&mut rng).unwrap();
    let deployment = engine.deploy_program(&program, &mut rng).unwrap();

    let min_cost = engine.deployment_cost_minimum(&deployment, ConsensusVersion::V14).unwrap();

    // Build a local-only transaction using a dummy state root
    let dummy_sr = <TestnetV0 as Network>::StateRoot::from_str(
        "sr1lkr8fzg8mk69qrtycxjvtrg8rvh77puaq7fm56cjkh04xhprdqzq3a355s",
    )
    .unwrap();
    let query = FixedStateRootQuery {
        state_root: dummy_sr,
        block_height: 42,
    };
    let tx = engine
        .build_deployment_transaction(
            &private_key,
            &program,
            &deployment,
            min_cost,
            0,
            ConsensusVersion::V14,
            &query,
            &mut rng,
        )
        .unwrap();

    // Verify the transaction wraps a deployment and is well-formed
    assert!(tx.is_deploy(), "expected a deployment transaction");

    // Verify the deployment inside matches
    let inner_deployment = tx.deployment().unwrap();
    assert_eq!(
        inner_deployment.program().id().to_string(),
        "hello_deploy_test.aleo",
        "deployment program ID mismatch"
    );

    println!("Deployment transaction built successfully");
}
