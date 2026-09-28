//! Aleo Client — the top-level entry point for the SDK.
//!
//! Combines account, program, execution, and network modules into
//! a single, ergonomic `AleoClient` with a fluent API.
//!
//! # Example
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
use crate::network::{AleoHttpClient, FixedStateRootQuery};
use crate::program::AleoProgram;
use anyhow::Result;
use snarkvm::console::program::ProgramID;
use snarkvm::prelude::{Network, PrivateKey, TestRng, TestnetV0};

/// High-level Aleo client that orchestrates the full lifecycle.
#[derive(Clone)]
pub struct AleoClient {
    pub network: AleoHttpClient,
    account: Option<crate::account::AleoAccount>,
    program: Option<AleoProgram<TestnetV0>>,
}

impl AleoClient {
    /// Create a new client pointing at an Aleo node.
    pub fn new(node_url: &str) -> Result<Self> {
        let network = AleoHttpClient::new(node_url)?;
        Ok(Self { network, account: None, program: None })
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
    pub fn set_program(&mut self, program: AleoProgram<TestnetV0>) {
        self.program = Some(program);
    }

    /// Get a reference to the stored program, or error if not set.
    pub fn require_program(&self) -> Result<&AleoProgram<TestnetV0>> {
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
    pub fn execute_local(
        &self,
        program_id: &str,
        function_name: &str,
        inputs: &[String],
    ) -> Result<String> {
        use snarkvm::prelude::{FromStr, TestRng};

        let account = self.require_account()?;
        let program = self.require_program()?;
        let mut rng = TestRng::default();

        let pid = ProgramID::<TestnetV0>::from_str(program_id)?;

        // Initialize a fresh execution engine
        let mut engine = ExecutionEngine::new(program.inner(), false)?;

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
        let query = FixedStateRootQuery { state_root, block_height };

        // Prove and package
        let tx = engine.prove_and_package(
            trace, private_key, program_id, function_name,
            base_fee, priority_fee, &query, &mut rng,
        )?;

        // Serialize and broadcast
        let tx_json = serde_json::to_string(&tx)?;
        let tx_id = self.network.broadcast_transaction(tx_json).await?;

        Ok(tx_id)
    }

    // ── On-chain queries ────────────────────────────────────────────────

    /// Query the public balance of the current account from `credits.aleo`.
    ///
    /// Returns `None` if the account has never received credits (no mapping entry).
    pub async fn get_balance(&self) -> Result<Option<u64>> {
        let addr = self.require_account()?.address_str();
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

    /// Fetch the current block height.
    pub async fn get_block_height(&self) -> Result<u32> {
        self.network.fetch_block_height().await
    }

    /// Fetch latest state root.
    pub async fn get_state_root(&self) -> Result<<TestnetV0 as Network>::StateRoot> {
        self.network.fetch_state_root_only().await
    }
}
