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
}
