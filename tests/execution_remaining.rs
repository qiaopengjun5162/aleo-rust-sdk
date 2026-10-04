use aleo_rust_sdk::ExecutionEngine;
use snarkvm::prelude::{Program, TestnetV0};

/// Cover new_with_v0_fee_keys (lines 52-57)
#[test]
fn test_execution_engine_v0_fee_keys() {
    let engine = ExecutionEngine::new_with_v0_fee_keys().unwrap();
    // Just verify it doesn't panic
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
    // Adding credits again should succeed (idempotent)
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
