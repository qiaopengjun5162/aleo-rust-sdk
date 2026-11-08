use aleo_rust_sdk::{DeploymentKind, ExecutionEngine, FixedStateRootQuery};
use snarkvm::prelude::{ConsensusVersion, Network, PrivateKey, Program, TestRng, TestnetV0};
use std::str::FromStr;

/// Cover new_with_fee_keys (lines 52-57)
#[test]
fn test_execution_engine_v0_fee_keys() {
    let engine = ExecutionEngine::new_with_fee_keys().unwrap();
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
    let engine = ExecutionEngine::new_with_fee_keys().unwrap();
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
    let engine = ExecutionEngine::new_with_fee_keys().unwrap();
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
    let engine = ExecutionEngine::new_with_fee_keys().unwrap();
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

// ── Program upgrades (JS buildUpgradeTransaction) ──────────────────────────

/// Loading the deployed source at edition N makes the next deployment carry
/// edition N+1. Only `DeploymentKind::Fresh` resets that edition to zero.
///
/// The old and new sources are identical here on purpose: snarkVM 4.12 only
/// permits *different* source when the deployed program has a `constructor`
/// (`Stack::new` → `check_upgrade_is_valid`). Edition arithmetic is independent
/// of that rule, and this test isolates it.
#[test]
fn test_upgrade_deployment_edition_semantics() {
    let engine = ExecutionEngine::new_with_fee_keys().unwrap();
    let old = Program::<TestnetV0>::from_str(HELLO_PROGRAM).unwrap();
    let new = old.clone();
    assert_eq!(old.id(), new.id(), "an upgrade keeps the program id");

    engine.add_program_with_edition(&old, 3).unwrap();

    let mut rng = TestRng::default();
    let deployment = engine.deploy_program(&new, &mut rng).unwrap();
    assert_eq!(
        deployment.edition(),
        4,
        "deploy over an edition-3 stack must produce edition 4"
    );

    let private_key = PrivateKey::new(&mut rng).unwrap();
    let fresh = ExecutionEngine::prepare_deployment_metadata(
        &deployment,
        &private_key,
        DeploymentKind::Fresh,
    )
    .unwrap();
    let upgraded = ExecutionEngine::prepare_deployment_metadata(
        &deployment,
        &private_key,
        DeploymentKind::Upgrade,
    )
    .unwrap();

    assert_eq!(fresh.edition(), 0, "a fresh deploy must reset the edition");
    assert_eq!(
        upgraded.edition(),
        4,
        "an upgrade must keep the incremented edition"
    );
    assert_eq!(deployment.edition(), 4, "the input must not be mutated");
    assert!(fresh.program_owner().is_some());
    assert!(upgraded.program_owner().is_some());
    assert!(fresh.program_checksum().is_some());
    assert_eq!(upgraded.program_checksum(), fresh.program_checksum());
}

/// snarkVM 4.12 rejects a source change for programs without a `constructor`.
/// Recorded as an executable note: `upgrade_program` can fail before any fee
/// is paid, and the caller needs a constructor-enabled program to upgrade.
#[test]
fn test_upgrade_without_constructor_rejects_changed_source() {
    let engine = ExecutionEngine::new_with_fee_keys().unwrap();
    let old = Program::<TestnetV0>::from_str(HELLO_PROGRAM).unwrap();
    let changed = Program::<TestnetV0>::from_str(
        r"
program hello_deploy_test.aleo;

function hello_v2:
    input r0 as u32.public;
    output r0 as u32.public;
",
    )
    .unwrap();
    engine.add_program_with_edition(&old, 2).unwrap();

    let mut rng = TestRng::default();
    let err = engine.deploy_program(&changed, &mut rng).unwrap_err();
    assert!(
        format!("{err:#}").contains("already exists with different contents"),
        "unexpected error: {err:#}"
    );
}

/// An upgrade deployment must survive the full fee + packaging pipeline and
/// still carry its non-zero edition. Uses the same offline query as the fresh
/// deployment test.
#[test]
fn test_build_upgrade_transaction_local() {
    let engine = ExecutionEngine::new_with_fee_keys().unwrap();
    let program = Program::<TestnetV0>::from_str(HELLO_PROGRAM).unwrap();
    engine.add_program_with_edition(&program, 5).unwrap();

    let mut rng = TestRng::default();
    let private_key = PrivateKey::new(&mut rng).unwrap();
    let deployment = engine.deploy_program(&program, &mut rng).unwrap();
    assert_eq!(deployment.edition(), 6);

    let min_cost = engine.deployment_cost_minimum(&deployment, ConsensusVersion::V14).unwrap();
    let dummy_sr = <TestnetV0 as Network>::StateRoot::from_str(
        "sr1lkr8fzg8mk69qrtycxjvtrg8rvh77puaq7fm56cjkh04xhprdqzq3a355s",
    )
    .unwrap();
    let query = FixedStateRootQuery {
        state_root: dummy_sr,
        block_height: 42,
    };

    let tx = engine
        .build_upgrade_transaction(
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

    assert!(tx.is_deploy(), "expected a deployment transaction");
    assert_eq!(
        tx.deployment().unwrap().edition(),
        6,
        "packaging must not reset the upgrade edition"
    );
}

/// `add_program_with_edition` surfaces a bad program with useful context.
#[test]
fn test_add_program_with_edition_rejects_unresolved_import() {
    let engine = ExecutionEngine::new().unwrap();
    let bad = Program::<TestnetV0>::from_str(
        "import missing.aleo;\nprogram bad_edition.aleo;\nfunction foo:\n    input r0 as u32.public;\n    output r0 as u32.public;\n",
    )
    .unwrap();

    let err = engine.add_program_with_edition(&bad, 7).unwrap_err();
    let message = format!("{err:#}");
    assert!(
        message.contains("Failed to load") && message.contains("edition 7"),
        "expected loader context with the edition, got: {message}"
    );
}
