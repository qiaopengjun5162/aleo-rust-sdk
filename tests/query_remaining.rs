use aleo_rust_sdk::FixedStateRootQuery;
use snarkvm::console::types::Field;
use snarkvm::ledger::query::QueryTrait;
use snarkvm::prelude::{FromStr as _, Network, TestnetV0};

/// Cover QueryTrait methods (exact uncovered lines from network.rs)
#[test]
fn test_query_trait_method_coverage() {
    let sr = <TestnetV0 as Network>::StateRoot::from_str(
        "sr1lkr8fzg8mk69qrtycxjvtrg8rvh77puaq7fm56cjkh04xhprdqzq3a355s",
    )
    .unwrap();

    let q: FixedStateRootQuery<TestnetV0> = FixedStateRootQuery { state_root: sr, block_height: 42 };

    // current_state_root and current_block_height
    let got_root = q.current_state_root().unwrap();
    assert_eq!(got_root, sr);
    assert!(q.current_block_height().unwrap() >= 1);

    // state path methods return errors/empty
    let f = Field::from_str("1field").unwrap();
    assert!(q.get_state_path_for_commitment(&f).is_err());
    assert!(q.get_state_paths_for_commitments(&[f]).unwrap().is_empty());
}
