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

use crate::credits::{
    CreditsCall, TransferKind, plan_bond_public, plan_bond_validator, plan_claim_unbond_public,
    plan_join, plan_set_validator_state, plan_split, plan_transfer, plan_unbond_public,
};
use crate::execution::ExecutionEngine;
use crate::execution::consensus_version_to_varuna;
use crate::network::{AleoHttpClient, ProvableQuery};
use crate::program::AleoProgram;
use anyhow::Result;
use snarkvm::console::program::{ProgramID, Value};
use snarkvm::ledger::block::Transaction;
use snarkvm::prelude::{Network, PrivateKey, TestRng, TestnetV0};
use std::str::FromStr;

/// Inputs for the prove pipeline.
enum PipelineInputs<'a> {
    /// Raw string inputs — snarkVM parses them.
    Strings(Vec<&'a str>),
    /// Pre-parsed values, required when inputs contain record ciphertexts.
    Values(Vec<Value<TestnetV0>>),
}

/// How the prove pipeline pays for the transaction.
enum PipelineFee {
    /// `credits.aleo/fee_public` with this priority fee, in microcredits.
    Public(u64),
    /// No fee at all. Only `credits.aleo/split` may do this — see
    /// [`ExecutionEngine::prove_and_package_feeless`].
    None,
}

/// High-level Aleo client that orchestrates the full lifecycle.
#[derive(Clone, Debug)]
pub struct AleoClient {
    pub network: AleoHttpClient,
    account: Option<crate::account::AleoAccount>,
    program: Option<AleoProgram>,
}

impl AleoClient {
    /// Create a new client pointing at an Aleo node.
    pub fn new(node_url: &str) -> Result<Self> {
        Ok(Self::with_network(AleoHttpClient::new(node_url)?))
    }

    /// Create a client with a custom RPC URL (for testing with wiremock).
    pub fn new_with_rpc(rest_url: &str, rpc_url: &str) -> Result<Self> {
        let network = AleoHttpClient::new_with_rpc(rest_url, rpc_url)?;
        Ok(Self::with_network(network))
    }

    /// Wrap an already-built network client.
    ///
    /// Used by [`AleoNetworkOptions::client`](crate::AleoNetworkOptions::client),
    /// which resolves every endpoint from one configuration.
    pub fn with_network(network: AleoHttpClient) -> Self {
        Self {
            network,
            account: None,
            program: None,
        }
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

    /// Shared prove pipeline: fetch program → authorize → execute → prove → package.
    ///
    /// Every HTTP call goes through `self.network`, including the `statePath`
    /// lookups the prover needs. This is what keeps a client pointed at a
    /// non-default node (mainnet, local devnet) from silently proving against
    /// testnet's Merkle root.
    async fn prove_pipeline(
        &self,
        private_key: &PrivateKey<TestnetV0>,
        program_id: &ProgramID<TestnetV0>,
        function_name: &str,
        inputs: PipelineInputs<'_>,
        fee: PipelineFee,
    ) -> Result<Transaction<TestnetV0>> {
        let mut rng = TestRng::default();

        // Fetch the program: non-credits programs must be registered locally
        // before `authorize` can resolve them.
        let program = self.network.fetch_program(&program_id.to_string()).await?;

        // V0 fee keys are required for `fee_public` on testnet.
        let engine = ExecutionEngine::new_with_fee_keys()?;
        engine.add_program(&program)?;

        let (_response, trace) = match inputs {
            PipelineInputs::Strings(values) => engine.authorize_and_execute(
                private_key,
                program_id,
                function_name,
                values,
                &mut rng,
            )?,
            PipelineInputs::Values(values) => engine.authorize_and_execute_with_values(
                private_key,
                program_id,
                function_name,
                values,
                &mut rng,
            )?,
        };

        // State root + height decide the consensus version (hence the proving
        // keys and fee schedule) used for this transaction.
        let (state_root, block_height) = self.network.fetch_state_root().await?;
        let consensus_version = TestnetV0::CONSENSUS_VERSION(block_height)?;
        let varuna_version = consensus_version_to_varuna(consensus_version);
        let query = ProvableQuery::new(state_root, block_height, &self.network.base_url);

        match fee {
            PipelineFee::Public(priority_fee) => engine.prove_and_package(
                trace,
                private_key,
                program_id,
                function_name,
                priority_fee,
                consensus_version,
                varuna_version,
                &query,
                &mut rng,
            ),
            PipelineFee::None => engine.prove_and_package_feeless(
                trace,
                program_id,
                function_name,
                consensus_version,
                varuna_version,
                &query,
                &mut rng,
            ),
        }
    }

    /// Run a planned `credits.aleo` call through the prove pipeline and
    /// broadcast it. Returns the transaction ID.
    async fn run_credits_call(
        &self,
        account: &crate::account::AleoAccount,
        call: &CreditsCall,
        fee: PipelineFee,
    ) -> Result<String> {
        let program_id = ProgramID::<TestnetV0>::from_str("credits.aleo")?;
        let inputs: Vec<&str> = call.inputs.iter().map(String::as_str).collect();
        let tx = self
            .prove_pipeline(
                &account.private_key,
                &program_id,
                call.function,
                PipelineInputs::Strings(inputs),
                fee,
            )
            .await?;
        let raw = self.network.broadcast_transaction(serde_json::to_string(&tx)?).await?;
        Ok(raw.trim_matches('"').to_string())
    }

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
        priority_fee: u64,
    ) -> Result<String> {
        let tx = self
            .prove_pipeline(
                private_key,
                program_id,
                function_name,
                PipelineInputs::Strings(inputs),
                PipelineFee::Public(priority_fee),
            )
            .await?;

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
        priority_fee: u64,
    ) -> Result<String> {
        let tx = self
            .prove_pipeline(
                private_key,
                program_id,
                function_name,
                PipelineInputs::Strings(inputs),
                PipelineFee::Public(priority_fee),
            )
            .await?;

        let raw = self.network.broadcast_transaction(serde_json::to_string(&tx)?).await?;
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
        priority_fee: u64,
    ) -> Result<String> {
        let tx = self
            .prove_pipeline(
                private_key,
                program_id,
                function_name,
                PipelineInputs::Values(values),
                PipelineFee::Public(priority_fee),
            )
            .await?;

        let raw = self.network.broadcast_transaction(serde_json::to_string(&tx)?).await?;
        Ok(raw.trim_matches('"').to_string())
    }

    // ── credits.aleo value operations (JS ProgramManager parity) ────────

    /// Transfer credits — the JS `ProgramManager.transfer()` /
    /// `buildTransferTransaction()`.
    ///
    /// `amount_microcredits` is the amount sent; for the two private-in kinds
    /// ([`TransferKind::Private`], [`TransferKind::PrivateToPublic`]) pass the
    /// funding record as a **plaintext record literal** in `amount_record`
    /// (see [`crate::credits`] — decrypt ciphertexts first). The public kinds
    /// ignore it.
    ///
    /// `priority_fee_microcredits` is paid on top of the computed base fee,
    /// from the account's public balance (`fee_public`). Paying the fee from a
    /// private record (`fee_private`, the JS `privateFee` flag) is not yet
    /// supported here.
    ///
    /// Returns the transaction ID, like the JS `transfer()` rather than the
    /// raw `Transaction` of `buildTransferTransaction()`.
    pub async fn transfer(
        &self,
        kind: TransferKind,
        amount_microcredits: u64,
        recipient: &str,
        amount_record: Option<&str>,
        priority_fee_microcredits: u64,
    ) -> Result<String> {
        let account = self.require_account()?;
        let call = plan_transfer(kind, amount_microcredits, recipient, amount_record)?;
        self.run_credits_call(
            account,
            &call,
            PipelineFee::Public(priority_fee_microcredits),
        )
        .await
    }

    /// Join two credits records into one — the JS `ProgramManager.join()`.
    ///
    /// Both records are plaintext record literals (see [`crate::credits`]).
    /// The fee is `fee_public` with `priority_fee_microcredits` on top.
    pub async fn join(
        &self,
        record_one: &str,
        record_two: &str,
        priority_fee_microcredits: u64,
    ) -> Result<String> {
        let account = self.require_account()?;
        let call = plan_join(record_one, record_two)?;
        self.run_credits_call(
            account,
            &call,
            PipelineFee::Public(priority_fee_microcredits),
        )
        .await
    }

    /// Split one credits record into two — the JS `ProgramManager.split()`.
    ///
    /// `split_amount_microcredits` is carved out of `amount_record` (a
    /// plaintext record literal) into a new record; the remainder returns as
    /// change. `credits.aleo/split` is the one call the protocol allows
    /// **without a fee**, so there is no priority-fee parameter — matching the
    /// JS `split()`, which packages with a `None` fee.
    pub async fn split(
        &self,
        split_amount_microcredits: u64,
        amount_record: &str,
    ) -> Result<String> {
        let account = self.require_account()?;
        let call = plan_split(split_amount_microcredits, amount_record)?;
        self.run_credits_call(account, &call, PipelineFee::None).await
    }

    /// Bond credits as a delegator to a validator — the JS
    /// `ProgramManager.bondPublic()`.
    ///
    /// `validator_address` must be a different address than the account: the
    /// program refuses self-bonding (`bond_public` is the delegator entry;
    /// bond as a validator with [`Self::bond_validator`]). `withdrawal_address`
    /// receives the credits on unbond. The function asserts the amount is at
    /// least 1 credit; committee-level minimums are finalize-time chain rules
    /// (see [`crate::credits`]).
    ///
    /// The fee is `fee_public` with `priority_fee_microcredits` on top.
    pub async fn bond_public(
        &self,
        validator_address: &str,
        withdrawal_address: &str,
        amount_microcredits: u64,
        priority_fee_microcredits: u64,
    ) -> Result<String> {
        let account = self.require_account()?;
        let call = plan_bond_public(validator_address, withdrawal_address, amount_microcredits)?;
        self.run_credits_call(
            account,
            &call,
            PipelineFee::Public(priority_fee_microcredits),
        )
        .await
    }

    /// Bond credits as a validator (self-bond) with a commission rate —
    /// the JS `ProgramManager.bondValidator()`, minus one wrong argument.
    ///
    /// The account is the validator (the transaction signer); the deployed
    /// `credits.aleo` takes only `(withdrawal_address, amount, commission)`.
    /// The JS wrapper prepends a validator address — four inputs for a
    /// three-input function; see [`crate::credits`] for the divergence.
    /// `withdrawal_address` must differ from the account. `commission` is the
    /// validator's take in percent; the program asserts it is at most 100.
    pub async fn bond_validator(
        &self,
        withdrawal_address: &str,
        amount_microcredits: u64,
        commission: u8,
        priority_fee_microcredits: u64,
    ) -> Result<String> {
        let account = self.require_account()?;
        let call = plan_bond_validator(withdrawal_address, amount_microcredits, commission)?;
        self.run_credits_call(
            account,
            &call,
            PipelineFee::Public(priority_fee_microcredits),
        )
        .await
    }

    /// Unbond staked credits from a validator — the JS
    /// `ProgramManager.unbondPublic()`.
    ///
    /// Shrinks the stake of `staker_address` by `amount_microcredits`; the
    /// chain enforces what may remain bonded.
    pub async fn unbond_public(
        &self,
        staker_address: &str,
        amount_microcredits: u64,
        priority_fee_microcredits: u64,
    ) -> Result<String> {
        let account = self.require_account()?;
        let call = plan_unbond_public(staker_address, amount_microcredits)?;
        self.run_credits_call(
            account,
            &call,
            PipelineFee::Public(priority_fee_microcredits),
        )
        .await
    }

    /// Claim unbonded credits to a public balance — the JS
    /// `ProgramManager.claimUnbondPublic()`.
    ///
    /// Run after [`Self::unbond_public`] and the unbonding period.
    pub async fn claim_unbond_public(
        &self,
        staker_address: &str,
        priority_fee_microcredits: u64,
    ) -> Result<String> {
        let account = self.require_account()?;
        let call = plan_claim_unbond_public(staker_address)?;
        self.run_credits_call(
            account,
            &call,
            PipelineFee::Public(priority_fee_microcredits),
        )
        .await
    }

    /// Open or close the validator to new stakers — the JS
    /// `ProgramManager.setValidatorState()`.
    ///
    /// `validator_state: true` opens the validator to new bonds; `false`
    /// closes it (existing stakers can still bond and unbond).
    pub async fn set_validator_state(
        &self,
        validator_state: bool,
        priority_fee_microcredits: u64,
    ) -> Result<String> {
        let account = self.require_account()?;
        let call = plan_set_validator_state(validator_state)?;
        self.run_credits_call(
            account,
            &call,
            PipelineFee::Public(priority_fee_microcredits),
        )
        .await
    }

    /// Check that the current account's public balance covers a fee —
    /// the JS `ProgramManager.checkFee()`.
    ///
    /// `fee_amount_microcredits` is compared against the account's public
    /// `credits.aleo` balance; an account with no mapping entry counts as 0.
    pub async fn check_fee(&self, fee_amount_microcredits: u64) -> Result<()> {
        let address = self.require_account()?.address_str();
        self.network.check_fee(&address, fee_amount_microcredits).await
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
        use snarkvm::prelude::Program;
        use std::str::FromStr;

        let account = self.require_account()?;
        let mut rng = TestRng::default();

        // 1. Parse the program
        let program = Program::<TestnetV0>::from_str(program_source)
            .map_err(|e| anyhow::anyhow!("Failed to parse program: {e}"))?;

        // 2. Initialize engine with V0 fee keys
        let engine = ExecutionEngine::new_with_fee_keys()?;
        // Register the program so its dependencies are available
        engine.add_program(&program)?;

        // 3. Generate deployment proof (pure proving, no fee yet)
        let deployment = engine.deploy_program(&program, &mut rng)?;

        // 4. Compute minimum deployment cost (using consensus version from current height)
        let (state_root, block_height) = self.network.fetch_state_root().await?;
        let consensus_version = TestnetV0::CONSENSUS_VERSION(block_height)?;
        let min_cost = engine.deployment_cost_minimum(&deployment, consensus_version)?;
        // Add a small buffer (5%) to account for node-level overhead that the static cost
        // calculation doesn't capture. This matches how the on-chain validator counts costs.
        let base_fee = min_cost.saturating_mul(105) / 100;

        // 5. Build full deployment transaction (prove fee + package)
        let query = ProvableQuery::new(state_root, block_height, &self.network.base_url);

        // 6. Build full deployment transaction (prove fee + package)
        let tx = engine.build_deployment_transaction(
            &account.private_key,
            &program,
            &deployment,
            base_fee,
            priority_fee_in_microcredits,
            consensus_version,
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
    ///
    /// There is only one endpoint for this (`GET .../mapping/account/{addr}`), so
    /// there is only one call. An earlier version re-issued the identical request
    /// as a "JSON-RPC fallback" — same URL, same 404 handling — which bought an
    /// extra round trip on every empty account and turned a parse failure that
    /// the first call logged as `None` into a hard error on the second.
    pub async fn get_balance(&self) -> Result<Option<u64>> {
        let addr = self.require_account()?.address_str();
        self.network.fetch_mapping_value_rest("credits.aleo", "account", &addr).await
    }

    /// Fetch unspent records for the current account's view key.
    pub async fn fetch_unspent_records(&self) -> Result<String> {
        let account = self.require_account()?;
        self.network.fetch_records(&account.view_key.to_string()).await
    }

    /// Find unspent private credits records owned by the current account's view key.
    ///
    /// Scans the last ~100K blocks and returns `(ciphertext, microcredits)` pairs
    /// for `credits.aleo` records, largest first.
    ///
    /// The decryption itself lives in [`RecordScanner`](crate::record::RecordScanner),
    /// which is the single implementation of "decrypt a ciphertext and check
    /// whether it is mine". Keeping a second copy here (or in the HTTP client)
    /// is how the two versions drift apart on edge cases like private owners.
    pub async fn find_private_credits_records(&self) -> Result<Vec<(String, u64)>> {
        use crate::record::RecordScanner;

        let account = self.require_account()?;
        let scanner = RecordScanner::new(self.network.clone());
        let records = scanner.scan_recent(&account.view_key.to_string(), 100_000).await?;

        // `scan_blocks` returns records for every program owned by this view key
        // and sorts them by amount descending, so filtering preserves the order.
        Ok(records
            .into_iter()
            .filter(|r| r.program_id == "credits.aleo")
            .map(|r| (r.ciphertext, r.microcredits))
            .collect())
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
    ///
    /// The consensus version is taken from the **latest** block height. That is
    /// only correct for transactions mined under the current consensus rules;
    /// for anything older use [`verify_execution_at`](Self::verify_execution_at).
    pub async fn verify_execution(&self, tx_id: &str) -> Result<String> {
        self.verify_transaction(tx_id, None).await
    }

    /// Verify a transaction's proof against the consensus rules in force at
    /// `block_height`.
    ///
    /// Pass the height the transaction was **mined** at. A proof is only valid
    /// under the Varuna version of its own era, and `ConsensusVersion →
    /// VarunaVersion` is not backward compatible (V4..=V20 → V2, V21.. → V3),
    /// so checking an old transaction against today's height reports
    /// `verification FAILED` for a perfectly valid proof.
    pub async fn verify_execution_at(&self, tx_id: &str, block_height: u32) -> Result<String> {
        self.verify_transaction(tx_id, Some(block_height)).await
    }

    /// The height to derive a consensus version from: the caller's, or the
    /// network's latest.
    ///
    /// Only the arms that actually verify a proof call this, so a transaction
    /// without a proof is still answered when the node is unreachable.
    async fn resolve_height(&self, override_height: Option<u32>) -> Result<u32> {
        match override_height {
            Some(height) => Ok(height),
            None => self.network.fetch_block_height().await,
        }
    }

    async fn verify_transaction(
        &self,
        tx_id: &str,
        override_height: Option<u32>,
    ) -> Result<String> {
        use snarkvm::ledger::block::Transaction;

        // 1. Fetch + deserialize transaction
        let tx_json = self.network.fetch_transaction(tx_id).await?;
        let tx: Transaction<TestnetV0> = serde_json::from_str(&tx_json)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize transaction: {e}"))?;

        match tx {
            Transaction::Execute(ref _id, ref _exec_id, ref execution, ref _fee) => {
                // 2. Get the first transition for program/function info
                let transition = execution
                    .transitions()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("Execution has no transitions"))?;
                let program_id = *transition.program_id();

                // 3. Fetch program and build engine
                let program = self.network.fetch_program(&program_id.to_string()).await?;
                let engine = ExecutionEngine::new()?;
                engine.add_program(&program)?;

                // 4. Consensus version from the height the transaction belongs to.
                let block_height = self.resolve_height(override_height).await?;
                let consensus_version = TestnetV0::CONSENSUS_VERSION(block_height)?;

                // 5. Verify execution proof
                tracing::info!("Verifying execution proof (height={block_height})...");
                engine.verify_execution_transaction(execution, consensus_version)?;

                Ok(format!(
                    "✅ Execution proof VERIFIED\n   Program: {}\n   Function: {}\n   Transitions: {}",
                    program_id,
                    transition.function_name(),
                    execution.len(),
                ))
            }
            Transaction::Deploy(ref _id, ref _deploy_id, ref _owner, ref deployment, ref _fee) => {
                // Verify deployment proof using an empty engine (no user program loaded)
                let block_height = self.resolve_height(override_height).await?;
                tracing::info!("Verifying deployment proof (height={block_height})...");
                let engine = ExecutionEngine::new()?;
                let consensus_version = TestnetV0::CONSENSUS_VERSION(block_height)?;
                engine.verify_deployment_transaction(
                    deployment,
                    consensus_version,
                    &mut TestRng::default(),
                )?;

                Ok(format!(
                    "✅ Deployment proof VERIFIED\n   Program: {}",
                    deployment.program_id(),
                ))
            }
            _ => Ok("⚠️  Transaction type does not contain a proof to verify".to_string()),
        }
    }
}
