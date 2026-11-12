//! JS SDK `Utility Functions` parity.
//!
//! The JS page documents three module-level free functions exported from the
//! wasm package. Two are genuine computation / verification utilities that have a
//! native counterpart here; the third is a wasm-only thread-pool initializer
//! that has no meaning on a native target.
//!
//! | JS function | Rust equivalent | Notes |
//! |------------|------------------|-------|
//! | `getOrInitConsensusVersionTestHeights()` | [`consensus_version_test_heights`] | returns the consensus-version → block-height schedule |
//! | `verifyFunctionExecution(...)` | [`verify_function_execution`] | self-contained verifier over [`crate::execution::ExecutionEngine`] |
//! | `initThreadPool(num_threads)` | [`init_thread_pool`] | wasm-rayon only; native uses rayon / OS threads directly (see note) |
//!
//! # The wasm-only `initThreadPool`
//!
//! `initThreadPool` spins up the rayon thread pool that backs parallel wasm
//! execution (proof generation, …). On a native target the rayon pool (or the OS
//! thread scheduler) is already in place, so there is nothing to initialize.
//! [`init_thread_pool`] is kept as a **no-op** so the JS surface maps 1:1, but it
//! performs no work and `num_threads` is ignored.

use std::str::FromStr;

use anyhow::Context;
use indexmap::IndexMap;
use snarkvm::console::network::Network;
use snarkvm::ledger::block::Execution;
use snarkvm::prelude::{ConsensusVersion, Identifier, Program, ProgramID, TestnetV0, VerifyingKey};

use crate::execution::ExecutionEngine;

/// JS `getOrInitConsensusVersionTestHeights()` — the consensus-version →
/// block-height schedule.
///
/// With `None`, returns the network's canonical activation schedule via
/// `TestnetV0::CONSENSUS_VERSION_HEIGHTS()`. With `Some(csv)`, parses a
/// comma-separated list of `u32` block heights (one per consensus version) into
/// the same schedule shape.
///
/// > **Panics.** A malformed `csv` panics — matching the upstream wasm SDK,
/// > which surfaces an invalid list as `RuntimeError: unreachable`. The schedule
/// > must contain exactly one height per consensus version, be strictly
/// > increasing, and start at height `0`. Validate input before passing it in.
///
/// > **Note.** The wasm SDK's default returns a *devnet test* schedule (via a
/// > wasm-gated global). A native target has no such global, so the canonical
/// > network schedule is returned instead — it is the meaningful value outside a
/// > custom devnet.
pub fn consensus_version_test_heights(heights: Option<&str>) -> Vec<(ConsensusVersion, u32)> {
    match heights {
        None => TestnetV0::CONSENSUS_VERSION_HEIGHTS().to_vec(),
        Some(csv) => parse_consensus_heights(csv),
    }
}

/// Parse a CSV list of block heights (one per consensus version) into the
/// `(ConsensusVersion, height)` schedule.
///
/// Mirrors the upstream validation: exactly one height per version, strictly
/// increasing, first height must be `0`. Panics on invalid input, matching the
/// wasm SDK's behaviour.
fn parse_consensus_heights(csv: &str) -> Vec<(ConsensusVersion, u32)> {
    let heights: Vec<u32> = csv
        .split(',')
        .map(str::trim)
        .map(|s| s.parse::<u32>())
        .collect::<Result<_, _>>()
        .expect("consensus version heights must be a CSV list of u32 block heights");
    let versions = TestnetV0::CONSENSUS_VERSION_HEIGHTS().iter().map(|(v, _)| *v);
    let pairs: Vec<(ConsensusVersion, u32)> = versions.zip(heights).collect();
    assert_eq!(
        pairs.len(),
        TestnetV0::CONSENSUS_VERSION_HEIGHTS().len(),
        "expected exactly one height per consensus version"
    );
    assert_eq!(
        pairs[0].1, 0,
        "the first consensus version height must be 0"
    );
    for w in pairs.windows(2) {
        assert!(
            w[0].1 < w[1].1,
            "consensus version heights must be strictly increasing"
        );
    }
    pairs
}

/// JS `initThreadPool(num_threads)` — wasm-rayon thread-pool initializer.
///
/// Native Rust uses rayon / the OS thread scheduler directly, so there is no
/// pool to initialize. This is a **no-op**, retained only so the JS surface
/// maps 1:1. `num_threads` is ignored.
pub fn init_thread_pool(_num_threads: u32) {}

/// Map of imported program ID → its `(function ID, verifying key)` pairs, as
/// taken by the JS `verifyFunctionExecution` `importVerifyingKeys` argument.
type ImportVerifyingKeys =
    IndexMap<ProgramID<TestnetV0>, Vec<(Identifier<TestnetV0>, VerifyingKey<TestnetV0>)>>;

/// JS `verifyFunctionExecution(execution, verifying_key, program, function_id,
/// imports, import_verifying_keys, block_height)` — verify a single function
/// execution.
///
/// This is a self-contained variant: it builds a fresh [`ExecutionEngine`],
/// loads `program` together with its `verifying_key`, then the `imports`
/// (program sources) and `import_verifying_keys`, and finally verifies
/// `execution` at `block_height`.
///
/// Returns `Ok(false)` for an invalid proof — mirroring the JS SDK, which
/// swallows the verification error into a boolean — and `Err` for setup
/// failures (a malformed program source, a missing import, …).
///
/// > **Note.** [`ExecutionEngine::verify_execution_at_height`] is the
/// > lower-level primitive this delegates to. Use it directly (loading the
/// > program once via [`ExecutionEngine::add_program`]) when verifying many
/// > executions against the same engine.
pub fn verify_function_execution(
    execution: &Execution<TestnetV0>,
    verifying_key: &VerifyingKey<TestnetV0>,
    program: &Program<TestnetV0>,
    function_id: &Identifier<TestnetV0>,
    imports: &IndexMap<ProgramID<TestnetV0>, String>,
    import_verifying_keys: &ImportVerifyingKeys,
    block_height: u32,
) -> anyhow::Result<bool> {
    let engine = ExecutionEngine::new()?;
    engine.add_program(program)?;
    engine
        .process
        .lock()
        .insert_verifying_key(program.id(), function_id, verifying_key.clone())?;
    for (_, src) in imports {
        let imported = Program::<TestnetV0>::from_str(src)
            .with_context(|| "Failed to parse an imported program source")?;
        engine.add_program(&imported)?;
    }
    for (pid, vks) in import_verifying_keys {
        for (fid, vk) in vks {
            engine.process.lock().insert_verifying_key(pid, fid, vk.clone())?;
        }
    }
    engine.verify_execution_at_height(execution, block_height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::parameters::testnet::FeePublicVerifier;
    use snarkvm::prelude::FromBytes;

    const HELLO: &str = "program hello.aleo;\n\
        function hello:\n\
            input r0 as u32.public;\n\
            input r1 as u32.private;\n\
            add r0 r1 into r2;\n\
            output r2 as u32.private;\n";

    fn vk() -> VerifyingKey<TestnetV0> {
        VerifyingKey::from_bytes_le(&FeePublicVerifier::load_bytes().unwrap()).unwrap()
    }

    #[test]
    fn consensus_version_test_heights_default() {
        let heights = consensus_version_test_heights(None);
        assert!(!heights.is_empty());
        // The schedule must start at genesis (height 0).
        assert_eq!(heights[0].1, 0);
        // One entry per consensus version.
        assert!(heights.len() >= 2);
        // Heights are strictly increasing.
        for w in heights.windows(2) {
            assert!(w[0].1 < w[1].1, "consensus heights must increase");
        }
    }

    #[test]
    fn consensus_version_test_heights_explicit_csv() {
        // 22 consensus versions → 22 heights, strictly increasing from 0.
        let csv = (0u32..22).map(|i| (i * 10).to_string()).collect::<Vec<_>>().join(",");
        let heights = consensus_version_test_heights(Some(&csv));
        assert_eq!(heights.len(), 22);
        assert_eq!(heights[0].1, 0);
        assert_eq!(heights[21].1, 210);
    }

    #[test]
    fn init_thread_pool_is_noop() {
        // Must not panic and must do nothing.
        init_thread_pool(4);
        init_thread_pool(0);
    }

    #[test]
    fn verify_function_execution_rejects_empty_execution() {
        let program = Program::<TestnetV0>::from_str(HELLO).unwrap();
        let key = vk();
        let function_id = Identifier::<TestnetV0>::from_str("hello").unwrap();
        // Reuse the same verifying key (shape only — the empty execution never
        // reaches a real proof check) to also exercise the import_vks loop.
        let mut import_vks = IndexMap::new();
        import_vks.insert(
            ProgramID::<TestnetV0>::from_str("hello.aleo").unwrap(),
            vec![(
                Identifier::<TestnetV0>::from_str("hello").unwrap(),
                key.clone(),
            )],
        );
        let execution = Execution::<TestnetV0>::new();
        let result = verify_function_execution(
            &execution,
            &key,
            &program,
            &function_id,
            &IndexMap::new(),
            &import_vks,
            0,
        );
        // An execution with no transitions cannot verify: JS returns `false`
        // (not an error), and so does this function.
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn verify_function_execution_rejects_malformed_import() {
        let program = Program::<TestnetV0>::from_str(HELLO).unwrap();
        let key = vk();
        let function_id = Identifier::<TestnetV0>::from_str("hello").unwrap();
        let mut imports = IndexMap::new();
        imports.insert(
            ProgramID::<TestnetV0>::from_str("bad.aleo").unwrap(),
            "this is not a valid aleo program".to_string(),
        );
        let execution = Execution::<TestnetV0>::new();
        let result = verify_function_execution(
            &execution,
            &key,
            &program,
            &function_id,
            &imports,
            &IndexMap::new(),
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn verify_function_execution_loads_valid_import() {
        let program = Program::<TestnetV0>::from_str(HELLO).unwrap();
        let key = vk();
        let function_id = Identifier::<TestnetV0>::from_str("hello").unwrap();
        // A second, valid program source — exercises the `add_program(&imported)`
        // success path (the malformed-import test only covers the error path).
        let mut imports = IndexMap::new();
        imports.insert(
            ProgramID::<TestnetV0>::from_str("imported.aleo").unwrap(),
            "program imported.aleo;\n\
             function run:\n\
                 input r0 as u32.public;\n\
                 output r0 as u32.public;\n"
                .to_string(),
        );
        let execution = Execution::<TestnetV0>::new();
        let result = verify_function_execution(
            &execution,
            &key,
            &program,
            &function_id,
            &imports,
            &IndexMap::new(),
            0,
        );
        // Imports were loaded without error; the empty execution still can't verify.
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}
