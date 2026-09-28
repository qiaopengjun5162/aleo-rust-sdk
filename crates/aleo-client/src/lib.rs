//! Aleo Client — the top-level entry point for the SDK.
//!
//! Combines account, program, execution, and network modules into
//! a single, ergonomic `AleoClient` with a fluent API.
//!
//! # Example
//!
//! ```no_run
//! use aleo_client::AleoClient;
//! use aleo_account::AleoAccount;
//! use snarkvm::prelude::TestRng;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let mut rng = TestRng::default();
//!     let client = AleoClient::new("https://api.explorer.provable.com/v1")?;
//!
//!     let account = AleoAccount::new_random(&mut rng)?;
//!     println!("Address: {}", account.address_str());
//!
//!     Ok(())
//! }
//! ```

use aleo_execution::ExecutionEngine;
use aleo_network::{AleoHttpClient, FixedStateRootQuery};
use aleo_program::AleoProgram;
use anyhow::Result;
use snarkvm::console::program::ProgramID;
use snarkvm::ledger::block::Transaction;
use snarkvm::prelude::{PrivateKey, Response, TestRng, TestnetV0};
use snarkvm::synthesizer::process::Trace;

/// High-level Aleo client that orchestrates the full lifecycle.
#[derive(Clone)]
pub struct AleoClient {
    pub network: AleoHttpClient,
}

impl AleoClient {
    /// Create a new client pointing at an Aleo node.
    pub fn new(node_url: &str) -> Result<Self> {
        let network = AleoHttpClient::new(node_url)?;
        Ok(Self { network })
    }

    // ── High-level operations ──────────────────────────────────────────

    /// Full pipeline: authorize → execute → prove → broadcast.
    ///
    /// Returns the transaction ID on success.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_and_broadcast(
        &self,
        private_key: &PrivateKey<TestnetV0>,
        program_id: &ProgramID<TestnetV0>,
        function_name: &str,
        inputs: Vec<&str>,
        base_fee: u64,
        priority_fee: u64,
    ) -> Result<String> {
        let mut rng = TestRng::default();

        // Fetch program from network
        let program = self.network.fetch_program(&program_id.to_string()).await?;

        // Initialize engine
        let mut engine = ExecutionEngine::new(&program, true)?;

        // Authorize + execute locally
        let (_response, trace) = engine.authorize_and_execute(
            private_key,
            program_id,
            function_name,
            inputs,
            &mut rng,
        )?;

        // Fetch state root for proving
        let (state_root, block_height) = self.network.fetch_state_root().await?;
        let query = FixedStateRootQuery {
            state_root,
            block_height,
        };

        // Prove and package
        let tx = engine.prove_and_package(
            trace,
            private_key,
            program_id,
            function_name,
            base_fee,
            priority_fee,
            &query,
            &mut rng,
        )?;

        // Serialize and broadcast
        let tx_json = serde_json::to_string(&tx)?;
        let tx_id = self.network.broadcast_transaction(tx_json).await?;

        Ok(tx_id)
    }

    // ── Step-by-step pipeline ───────────────────────────────────────────

    /// Step 1: Fetch a program from the network.
    pub async fn fetch_program(&self, program_id: &str) -> Result<AleoProgram<TestnetV0>> {
        let source = self.network.fetch_program(program_id).await?;
        AleoProgram::from_source(&source.to_string())
    }

    /// Step 2: Authorize and execute locally.
    pub fn authorize_and_execute(
        engine: &mut ExecutionEngine<TestnetV0>,
        private_key: &PrivateKey<TestnetV0>,
        program_id: &ProgramID<TestnetV0>,
        function_name: &str,
        inputs: Vec<&str>,
        rng: &mut TestRng,
    ) -> Result<(Response<TestnetV0>, Trace<TestnetV0>)> {
        engine.authorize_and_execute(private_key, program_id, function_name, inputs, rng)
    }

    /// Step 3: Prove and package into a transaction.
    pub fn prove_and_package(
        engine: &mut ExecutionEngine<TestnetV0>,
        trace: Trace<TestnetV0>,
        private_key: &PrivateKey<TestnetV0>,
        program_id: &ProgramID<TestnetV0>,
        function_name: &str,
        base_fee: u64,
        priority_fee: u64,
        query: &FixedStateRootQuery<TestnetV0>,
        rng: &mut TestRng,
    ) -> Result<Transaction<TestnetV0>> {
        engine.prove_and_package(
            trace,
            private_key,
            program_id,
            function_name,
            base_fee,
            priority_fee,
            query,
            rng,
        )
    }

    /// Step 4: Broadcast a transaction.
    pub async fn broadcast(&self, tx: &Transaction<TestnetV0>) -> Result<String> {
        let tx_json = serde_json::to_string(tx)?;
        self.network.broadcast_transaction(tx_json).await
    }
}
