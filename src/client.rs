//! # Aleo Client — the top-level entry point for the SDK.
//!
//! Combines [`account`](crate::account), [`program`](crate::program),
//! [`execution`](crate::execution), and [`network`](crate::network) modules into
//! a single, ergonomic [`AleoClient`] with a fluent API.
//!
//! ## Lifecycle
//!
//! 1. **Create** — `AleoClient::new(node_url)`
//! 2. **Set account** — `client.set_account_from_private_key_str(pk)`
//! 3. **Load program** — `client.load_program_from_source(source)`
//! 4. **Query** — `client.get_block_height()`, `client.get_balance()`
//! 5. **Execute** — `client.execute_local(...)` or `client.execute_and_broadcast(...)`
//!
//! ## Example
//!
//! ```no_run
//! use aleo_rust_sdk::{AleoClient, AleoAccount};
//! use snarkvm::prelude::TestRng;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let mut rng = TestRng::default();
//!     let client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;
//!
//!     let account = AleoAccount::new_random(&mut rng)?;
//!     println!("Address: {}", account.address_str());
//!
//!     Ok(())
//! }
//! ```

use crate::execution::ExecutionEngine;
use crate::network::{AleoHttpClient, ProvableQuery};
use crate::program::AleoProgram;
use anyhow::Result;
use snarkvm::console::program::{ProgramID, Value};
use snarkvm::prelude::{Network, PrivateKey, TestRng, TestnetV0};

/// High-level Aleo client that orchestrates the full lifecycle.
#[derive(Clone)]
pub struct AleoClient {
    pub network: AleoHttpClient,
    account: Option<crate::account::AleoAccount>,
    program: Option<AleoProgram>,
}

impl AleoClient {
    /// Create a new client pointing at an Aleo node.
    pub fn new(node_url: &str) -> Result<Self> {
        let network = AleoHttpClient::new(node_url)?;
        Ok(Self {
            network,
            account: None,
            program: None,
        })
    }

    /// Create a client with a custom RPC URL (for testing with wiremock).
    pub fn new_with_rpc(rest_url: &str, rpc_url: &str) -> Result<Self> {
        let network = AleoHttpClient::new_with_rpc(rest_url, rpc_url)?;
        Ok(Self {
            network,
            account: None,
            program: None,
        })
    }

    // ── Account management ──────────────────────────────────────────────

    /// Set the account from a private key string.
    pub fn set_account_from_private_key_str(&mut self, pk_str: &str) -> Result<()> {
        let account = crate::account::AleoAccount::from_private_key_str(pk_str)?;
        self.account = Some(account);
        Ok(())
    }

    /// Get a reference to the current account, or error if not set.
    pub fn require_account(&self) -> Result<&crate::account::AleoAccount> {
        self.account.as_ref().ok_or_else(|| {
            anyhow::anyhow!("No account set. Call set_account_from_private_key_str() first.")
        })
    }

    // ── Program management ──────────────────────────────────────────────

    /// Load a program from source string and store it.
    pub fn load_program_from_source(&mut self, source: &str) -> Result<()> {
        let program = AleoProgram::from_source(source)?;
        self.program = Some(program);
        Ok(())
    }

    /// Directly set a program (e.g. from `AleoProgram::credits()`).
    pub fn set_program(&mut self, program: AleoProgram) {
        self.program = Some(program);
    }

    /// Get a reference to the stored program, or error if not set.
    pub fn require_program(&self) -> Result<&AleoProgram> {
        self.program.as_ref().ok_or_else(|| {
            anyhow::anyhow!("No program loaded. Call load_program_from_source() first.")
        })
    }

    // ── Local execution (dry-run) ───────────────────────────────────────

    /// Execute a function locally without proving or broadcasting.
    ///
    /// This is a dry-run: it authorizes and executes the function call
    /// using a temporary process with the loaded program, but does NOT
    /// generate proofs or submit anything to the network.
    ///
    /// If a program has been loaded via `load_program_from_source()`, it
    /// will be registered automatically. For built-in programs (credits.aleo),
    /// no pre-loading is needed.
    pub fn execute_local(
        &self,
        program_id: &str,
        function_name: &str,
        inputs: &[String],
    ) -> Result<String> {
        use snarkvm::prelude::{FromStr, TestRng};

        let account = self.require_account()?;
        let mut rng = TestRng::default();

        let pid = ProgramID::<TestnetV0>::from_str(program_id)?;

        // Initialize a fresh execution engine (credits.aleo loaded by default)
        let engine = ExecutionEngine::new()?;
        // Optionally register the user program if one was loaded
        if let Some(prog) = &self.program {
            engine.add_program(prog.inner())?;
        }

        let (response, _trace) = engine.authorize_and_execute(
            &account.private_key,
            &pid,
            function_name,
            inputs.iter().map(|s| s.as_str()).collect(),
            &mut rng,
        )?;

        Ok(format!("{response:?}"))
    }

    // ── High-level operations ──────────────────────────────────────────

    /// Full pipeline: authorize → execute → prove → return Transaction JSON (no broadcast).
    ///
    /// Equivalent to JS SDK `run(_, _, _, proveExecution=true)` without the broadcast step.
    /// Returns the serialized transaction as a JSON string.
    #[allow(clippy::too_many_arguments)]
    pub async fn prove_execution(
        &self,
        private_key: &PrivateKey<TestnetV0>,
        program_id: &ProgramID<TestnetV0>,
        function_name: &str,
        inputs: Vec<&str>,
        base_fee: u64,
        priority_fee: u64,
    ) -> Result<String> {
        let mut rng = TestRng::default();

        // Fetch program from network (needed for non-credits programs)
        let program = self.network.fetch_program(&program_id.to_string()).await?;

        // Initialize engine with V0 fee keys for testnet
        let engine = ExecutionEngine::new_with_v0_fee_keys()?;
        // Register the user program
        engine.add_program(&program)?;

        let (_response, trace) = engine.authorize_and_execute(
            private_key,
            program_id,
            function_name,
            inputs,
            &mut rng,
        )?;

        // Fetch state root for proving
        let (state_root, block_height) = self.network.fetch_state_root().await?;
        let query = ProvableQuery::new(
            state_root,
            block_height,
            "https://api.provable.com/v2/testnet",
        );

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

        Ok(serde_json::to_string(&tx)?)
    }

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

        // Initialize engine with V0 fee keys for testnet
        let engine = ExecutionEngine::new_with_v0_fee_keys()?;
        // Register the user program
        engine.add_program(&program)?;

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
        let query = ProvableQuery::new(
            state_root,
            block_height,
            "https://api.provable.com/v2/testnet",
        );

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
        let raw = self.network.broadcast_transaction(tx_json).await?;
        Ok(raw.trim_matches('"').to_string())
    }

    /// Full pipeline with pre-parsed snarkVM `Value` inputs.
    ///
    /// Use this when inputs include record ciphertexts — decrypt them first,
    /// wrap as `Value::Record`, and pass here instead of raw strings.
    /// Otherwise behaves identically to `execute_and_broadcast`.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_and_broadcast_with_values(
        &self,
        private_key: &PrivateKey<TestnetV0>,
        program_id: &ProgramID<TestnetV0>,
        function_name: &str,
        values: Vec<Value<TestnetV0>>,
        base_fee: u64,
        priority_fee: u64,
    ) -> Result<String> {
        use snarkvm::prelude::TestRng;

        let mut rng = TestRng::default();

        // Fetch program from network
        let program = self.network.fetch_program(&program_id.to_string()).await?;

        // Initialize engine with V0 fee keys for testnet
        let engine = ExecutionEngine::new_with_v0_fee_keys()?;
        // Register the user program
        engine.add_program(&program)?;

        // Authorize + execute locally with pre-parsed values
        let (_response, trace) = engine.authorize_and_execute_with_values(
            private_key,
            program_id,
            function_name,
            values,
            &mut rng,
        )?;

        // Fetch state root for proving
        let (state_root, block_height) = self.network.fetch_state_root().await?;
        let query = ProvableQuery::new(
            state_root,
            block_height,
            "https://api.provable.com/v2/testnet",
        );

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
        let raw = self.network.broadcast_transaction(tx_json).await?;
        Ok(raw.trim_matches('"').to_string())
    }

    // ── Deployment (program publishing) ─────────────────────────────────

    /// Full deployment pipeline: parse → prove → compute fee → fetch state root → build tx → broadcast.
    ///
    /// This is the equivalent of JS SDK's `ProgramManager.deploy()`.
    ///
    /// `program_source` is the raw `.aleo` program source code.
    /// `priority_fee_in_microcredits` adds priority over the minimum deployment cost.
    ///
    /// Returns the transaction ID on success.
    pub async fn deploy_program(
        &self,
        program_source: &str,
        priority_fee_in_microcredits: u64,
    ) -> Result<String> {
        use snarkvm::prelude::{ConsensusVersion, Program};
        use std::str::FromStr;

        let account = self.require_account()?;
        let mut rng = TestRng::default();

        // 1. Parse the program
        let program = Program::<TestnetV0>::from_str(program_source)
            .map_err(|e| anyhow::anyhow!("Failed to parse program: {e}"))?;

        // 2. Initialize engine with V0 fee keys
        let engine = ExecutionEngine::new_with_v0_fee_keys()?;
        // Register the program so its dependencies are available
        engine.add_program(&program)?;

        // 3. Generate deployment proof (pure proving, no fee yet)
        let deployment = engine.deploy_program(&program, &mut rng)?;

        // 4. Compute minimum deployment cost (TestnetV0 uses V14 consensus)
        let min_cost = engine.deployment_cost_minimum(&deployment, ConsensusVersion::V14)?;
        // Add a small buffer (5%) to account for node-level overhead that the static cost
        // calculation doesn't capture. This matches how the on-chain validator counts costs.
        let base_fee = min_cost.saturating_mul(105) / 100;

        // 5. Fetch state root for proving
        let (state_root, block_height) = self.network.fetch_state_root().await?;
        let query = ProvableQuery::new(
            state_root,
            block_height,
            "https://api.provable.com/v2/testnet",
        );

        // 6. Build full deployment transaction (prove fee + package)
        let tx = engine.build_deployment_transaction(
            &account.private_key,
            &program,
            &deployment,
            base_fee,
            priority_fee_in_microcredits,
            ConsensusVersion::V14,
            &query,
            &mut rng,
        )?;

        // 7. Serialize and broadcast
        let tx_json = serde_json::to_string(&tx)?;
        let raw = self.network.broadcast_transaction(tx_json).await?;
        Ok(raw.trim_matches('"').to_string())
    }

    // ── On-chain queries ────────────────────────────────────────────────

    /// Query the public balance of the current account from `credits.aleo`.
    ///
    /// Returns `None` if the account has never received credits (no mapping entry).
    pub async fn get_balance(&self) -> Result<Option<u64>> {
        let addr = self.require_account()?.address_str();
        // Try REST first (more reliable than JSON-RPC for mapping queries)
        if let Some(val) =
            self.network.fetch_mapping_value_rest("credits.aleo", "account", &addr).await?
        {
            return Ok(Some(val));
        }
        // Fallback: JSON-RPC path
        let val = self.network.fetch_mapping_value("credits.aleo", "account", &addr).await?;
        match val {
            Some(s) => Ok(Some(s.trim().parse::<u64>()?)),
            None => Ok(None),
        }
    }

    /// Fetch unspent records for the current account's view key.
    pub async fn fetch_unspent_records(&self) -> Result<String> {
        let account = self.require_account()?;
        self.network.fetch_records(&account.view_key.to_string()).await
    }

    /// Find unspent private credits records owned by the current account's view key.
    pub async fn find_private_credits_records(&self) -> Result<Vec<(String, u64)>> {
        let account = self.require_account()?;
        self.network.find_private_credits_records(&account.view_key.to_string()).await
    }

    /// Fetch the current block height.
    pub async fn get_block_height(&self) -> Result<u32> {
        self.network.fetch_block_height().await
    }

    /// Fetch latest state root.
    pub async fn get_state_root(&self) -> Result<<TestnetV0 as Network>::StateRoot> {
        self.network.fetch_state_root_only().await
    }

    // ── Verification ─────────────────────────────────────────────────────

    /// Fetch a transaction from the network and verify its proof.
    ///
    /// Equivalent to JS SDK's `verifyExecution()` — deserializes the on-chain
    /// transaction and runs the snarkVM proof verifier locally.
    ///
    /// - **Execute** transactions: verifies the execution proof.
    /// - **Deploy** transactions: verifies the deployment proof.
    pub async fn verify_execution(&self, tx_id: &str) -> Result<String> {
        use snarkvm::ledger::block::Transaction;

        // 1. Fetch + deserialize transaction
        let tx_json = self.network.fetch_transaction(tx_id).await?;
        let tx: Transaction<TestnetV0> = serde_json::from_str(&tx_json)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize transaction: {e}"))?;

        match tx {
            Transaction::Execute(ref _id, ref _exec_id, ref execution, ref _fee) => {
                // 2. Get the first transition for program/function info
                let transition = execution.transitions().next()
                    .ok_or_else(|| anyhow::anyhow!("Execution has no transitions"))?;
                let program_id = *transition.program_id();

                // 3. Fetch program and build engine
                let program = self.network.fetch_program(&program_id.to_string()).await?;
                let engine = ExecutionEngine::new()?;
                engine.add_program(&program)?;

                // 4. Verify execution proof
                tracing::info!("Verifying execution proof...");
                engine.verify_execution_transaction(execution)?;

                Ok(format!(
                    "✅ Execution proof VERIFIED\n   Program: {}\n   Function: {}\n   Transitions: {}",
                    program_id,
                    transition.function_name(),
                    execution.len(),
                ))
            }
            Transaction::Deploy(ref _id, ref _deploy_id, ref _owner, ref deployment, ref _fee) => {
                // Verify deployment proof using an empty engine (no user program loaded)
                tracing::info!("Verifying deployment proof...");
                let engine = ExecutionEngine::new()?;
                engine.verify_deployment_transaction(deployment, &mut TestRng::default())?;

                Ok(format!(
                    "✅ Deployment proof VERIFIED\n   Program: {}",
                    deployment.program_id(),
                ))
            }
            _ => Ok("⚠️  Transaction type does not contain a proof to verify".to_string()),
        }
    }
}
