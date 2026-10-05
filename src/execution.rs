//! # Aleo Execution — authorization, proving, and transaction packaging pipeline.
//!
//! The execution pipeline has three phases:
//!
//! 1. **Authorize** — build authorization for a function call
//! 2. **Execute** — run locally, getting response + trace
//! 3. **Prove + package** — prepare trace, prove execution + fee, verify, package into `Transaction`
//!
//! ## Usage
//!
//! ```no_run
//! use aleo_rust_sdk::ExecutionEngine;
//!
//! let engine = ExecutionEngine::new_with_v0_fee_keys().unwrap();
//! // see AleoClient::execute_and_broadcast() for a full pipeline example
//! ```

use anyhow::{Context, Result};
use indexmap::IndexMap;
use snarkvm::algorithms::snark::varuna::VarunaVersion;
use snarkvm::circuit::AleoTestnetV0;
use snarkvm::console::program::{Identifier, ProgramID, ProgramOwner};
use snarkvm::ledger::block::{Deployment, Transaction};
use snarkvm::prelude::{
    Address, ConsensusVersion, CryptoRng, InclusionVersion, PrivateKey, Process, Program, Response,
    Rng, TestRng, TestnetV0,
};
use snarkvm::synthesizer::process::{Stack, Trace, deployment_cost};
use std::str::FromStr;
use std::sync::Arc;

/// Custom query trait for state root fetching.
pub use snarkvm::ledger::query::QueryTrait;

/// Fee key loader — injects V0 proving/verifying keys for testnet fee_public.
mod fee_keys {
    use snarkvm::parameters::testnet::{FeePublicV0Prover, FeePublicV0Verifier};
    use snarkvm::prelude::FromBytes as _;
    use snarkvm::synthesizer::snark::{ProvingKey, VerifyingKey};

    pub fn load_pk() -> Result<ProvingKey<snarkvm::prelude::TestnetV0>, anyhow::Error> {
        ProvingKey::from_bytes_le(&FeePublicV0Prover::load_bytes()?)
    }

    pub fn load_vk() -> Result<VerifyingKey<snarkvm::prelude::TestnetV0>, anyhow::Error> {
        VerifyingKey::from_bytes_le(&FeePublicV0Verifier::load_bytes()?)
    }
}

/// Execution engine wrapping a snarkVM `Process`.
pub struct ExecutionEngine {
    pub process: Process<TestnetV0>,
}

impl ExecutionEngine {
    /// Initialize a new process using `Process::load()` (credits loaded by default).
    pub fn new() -> Result<Self> {
        let process = Process::<TestnetV0>::load()?;
        Ok(Self { process })
    }

    /// Initialize with explicit V0 fee keys injected.
    pub fn new_with_v0_fee_keys() -> Result<Self> {
        let mut engine = Self::new()?;
        engine.inject_v0_fee_keys()?;
        Ok(engine)
    }

    /// Inject V0 fee proving/verifying keys for testnet fee_public support.
    pub fn inject_v0_fee_keys(&mut self) -> Result<()> {
        tracing::info!("Loading V0 fee keys from testnet parameters...");
        let fee_pk = fee_keys::load_pk().context("Failed to deserialize V0 fee proving key")?;
        let fee_vk = fee_keys::load_vk().context("Failed to deserialize V0 fee verifying key")?;

        let credits_id = ProgramID::<TestnetV0>::from_str("credits.aleo")?;
        let fee_fn = Identifier::<TestnetV0>::from_str("fee_public")?;
        let guard = self.process.lock();
        guard.insert_proving_key(&credits_id, &fee_fn, fee_pk)?;
        guard.insert_verifying_key(&credits_id, &fee_fn, fee_vk)?;
        drop(guard);
        tracing::info!("V0 fee keys injected");
        Ok(())
    }

    /// Add a program to the engine.
    pub fn add_program(&self, program: &Program<TestnetV0>) -> Result<()> {
        // `add_program` is on ProcessExclusiveGuard, accessed via lock()
        self.process.lock().add_program(program)?;
        Ok(())
    }

    /// Authorize and execute locally. Returns response + trace.
    pub fn authorize_and_execute(
        &self,
        private_key: &PrivateKey<TestnetV0>,
        program_id: &ProgramID<TestnetV0>,
        function_name: &str,
        inputs: Vec<&str>,
        rng: &mut TestRng,
    ) -> Result<(Response<TestnetV0>, Trace<TestnetV0>)> {
        tracing::info!("Authorizing...");
        let fn_id = Identifier::<TestnetV0>::from_str(function_name)?;
        let authorization = self
            .process
            .authorize::<AleoTestnetV0, _>(private_key, *program_id, fn_id, inputs.into_iter(), rng)
            .context("Authorization failed")?;

        tracing::info!("Executing locally...");
        let (response, trace) = self
            .process
            .execute::<AleoTestnetV0, _>(authorization, rng)
            .context("Local execution failed")?;

        Ok((response, trace))
    }

    /// Prove execution + fee, verify, package into `Transaction`.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_and_package(
        &self,
        trace: Trace<TestnetV0>,
        private_key: &PrivateKey<TestnetV0>,
        program_id: &ProgramID<TestnetV0>,
        function_name: &str,
        base_fee: u64,
        priority_fee: u64,
        query: &impl QueryTrait<TestnetV0>,
        rng: &mut TestRng,
    ) -> Result<Transaction<TestnetV0>> {
        let locator = format!("{program_id}/{function_name}");

        // Prove execution
        let mut exec_trace = trace;
        exec_trace.prepare(query).context("Failed to prepare execution trace")?;
        let execution = exec_trace
            .prove_execution::<AleoTestnetV0, _>(&locator, VarunaVersion::V2, rng)
            .context("Failed to generate execution proof")?;

        // Fee authorization + proving
        let execution_id = execution.to_execution_id()?;
        let fee_authorization = self
            .process
            .authorize_fee_public::<AleoTestnetV0, _>(
                private_key,
                base_fee,
                priority_fee,
                execution_id,
                rng,
            )
            .context("Failed to authorize fee")?;

        let (_fee_response, mut fee_trace) = self
            .process
            .execute::<AleoTestnetV0, _>(fee_authorization, rng)
            .context("Failed to execute fee")?;

        fee_trace.prepare(query).context("Failed to prepare fee trace")?;
        let fee = fee_trace
            .prove_fee::<AleoTestnetV0, _>(VarunaVersion::V2, rng)
            .context("Failed to generate fee proof")?;

        // Build execution_stacks for verification (needed by 4.10 API)
        let mut execution_stacks: IndexMap<ProgramID<TestnetV0>, Arc<Stack<TestnetV0>>> =
            IndexMap::new();
        let guard = self.process.lock();
        for transition in execution.transitions() {
            let pid = *transition.program_id();
            if !execution_stacks.contains_key(&pid) {
                let stack = guard.get_stack(pid).context("Missing stack for verification")?;
                execution_stacks.insert(pid, stack.clone());
            }
        }
        drop(guard);

        // Local verification (associated function in 4.10)
        tracing::info!("Verifying proofs locally...");
        Process::<TestnetV0>::verify_execution(
            ConsensusVersion::V14,
            VarunaVersion::V2,
            InclusionVersion::V0,
            &execution,
            &execution_stacks,
        )
        .context("Local execution verification FAILED")?;

        self.process
            .verify_fee(
                ConsensusVersion::V14,
                VarunaVersion::V2,
                InclusionVersion::V0,
                &fee,
                execution_id,
            )
            .context("Local fee verification FAILED")?;

        Transaction::<TestnetV0>::from_execution(execution, Some(fee))
            .context("Failed to package transaction")
    }

    /// Reference to the inner `Process`.
    pub fn inner(&self) -> &Process<TestnetV0> {
        &self.process
    }

    // ── Deployment (program publishing) ─────────────────────────────────

    /// Pure program deployment proof — generates a `Deployment` from source.
    ///
    /// This only proves the program circuit. Fee and transaction packaging
    /// must be done separately via [`build_deployment_transaction`](Self::build_deployment_transaction).
    pub fn deploy_program<R: Rng + CryptoRng>(
        &self,
        program: &Program<TestnetV0>,
        rng: &mut R,
    ) -> Result<Deployment<TestnetV0>> {
        self.process
            .deploy::<AleoTestnetV0, R>(program, rng)
            .context("Failed to generate program deployment")
    }

    /// Full deployment pipeline: prove program → authorize fee → prove fee →
    /// verify → package into [`Transaction`].
    ///
    /// This is the equivalent of JS SDK's `buildDeploymentTransaction`.
    ///
    /// `base_fee` is the minimum deployment cost (use [`ExecutionEngine::deployment_cost_minimum`] to compute it).
    /// `priority_fee_in_microcredits` is an additional fee on top.
    /// `consensus_version` determines which cost formula applies (TestnetV0 uses V14).
    /// `query` supplies the current state root (from [`AleoHttpClient::fetch_state_root`](crate::network::AleoHttpClient::fetch_state_root)).
    #[allow(clippy::too_many_arguments)]
    pub fn build_deployment_transaction<R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<TestnetV0>,
        _program: &Program<TestnetV0>,
        deployment: &Deployment<TestnetV0>,
        base_fee: u64,
        priority_fee_in_microcredits: u64,
        _consensus_version: ConsensusVersion,
        query: &impl QueryTrait<TestnetV0>,
        rng: &mut R,
    ) -> Result<Transaction<TestnetV0>> {
        // Ensure the program has functions.
        if deployment.program().functions().is_empty() {
            anyhow::bail!("Attempted to create an empty deployment");
        }

        // Compute deployment ID and owner.
        // NOTE: Process::deploy returns a deployment with edition set by Stack::new(process, program),
        // which gives a non-zero edition. The on-chain validator checks `deployment.edition() == 0` for
        // new deployments (non-zero edition → amendment path). Reset it to 0 for a fresh deploy.
        let mut deployment = deployment.clone();
        deployment.set_edition_raw(0);
        let addr = Address::try_from(private_key)?;
        deployment.set_program_owner_raw(Some(addr));
        deployment.set_program_checksum_raw(Some(deployment.program().to_checksum()));

        let deployment_id = deployment.to_deployment_id()?;
        let owner = ProgramOwner::new(private_key, deployment_id, rng)?;

        // Authorize the fee.
        let fee_authorization = self
            .process
            .authorize_fee_public::<AleoTestnetV0, R>(
                private_key,
                base_fee,
                priority_fee_in_microcredits,
                deployment_id,
                rng,
            )
            .context("Failed to authorize deployment fee")?;

        // Execute + prove the fee.
        let (_, mut fee_trace) = self
            .process
            .execute::<AleoTestnetV0, R>(fee_authorization, rng)
            .context("Failed to execute fee")?;

        fee_trace.prepare(query).context("Failed to prepare fee trace")?;

        let fee = fee_trace
            .prove_fee::<AleoTestnetV0, R>(VarunaVersion::V2, rng)
            .context("Failed to prove fee")?;

        // Package into transaction.
        Transaction::<TestnetV0>::from_deployment(owner, deployment.clone(), fee)
            .context("Failed to package deployment transaction")
    }

    /// Compute the minimum deployment cost for a deployment at the given consensus version.
    pub fn deployment_cost_minimum(
        &self,
        deployment: &Deployment<TestnetV0>,
        _consensus_version: ConsensusVersion,
    ) -> Result<u64> {
        let (min_cost, _details) = deployment_cost(&self.process, deployment, _consensus_version)?;
        Ok(min_cost)
    }

    // ── Verification ─────────────────────────────────────────────────────

    /// Verify an **execute** transaction's proof.
    ///
    /// The program must already be registered in this engine via `add_program()`.
    pub fn verify_execution_transaction(
        &self,
        execution: &snarkvm::ledger::block::Execution<TestnetV0>,
    ) -> Result<()> {
        // Build execution stacks from the process
        let mut execution_stacks: IndexMap<ProgramID<TestnetV0>, Arc<Stack<TestnetV0>>> =
            IndexMap::new();
        let guard = self.process.lock();
        for t in execution.transitions() {
            let pid = *t.program_id();
            if !execution_stacks.contains_key(&pid) {
                let stack = guard.get_stack(pid).context("Missing stack for verification")?;
                execution_stacks.insert(pid, stack.clone());
            }
        }
        drop(guard);

        Process::<TestnetV0>::verify_execution(
            ConsensusVersion::V14,
            VarunaVersion::V2,
            InclusionVersion::V0,
            execution,
            &execution_stacks,
        )
        .context("Execution proof verification FAILED")
    }

    /// Verify a **deploy** transaction's proof.
    /// Uses an empty engine (no user programs loaded) to avoid edition-zero collision.
    pub fn verify_deployment_transaction(
        &self,
        deployment: &Deployment<TestnetV0>,
        rng: &mut TestRng,
    ) -> Result<()> {
        self.process
            .verify_deployment::<AleoTestnetV0, _>(ConsensusVersion::V14, deployment, rng)
            .context("Deployment proof verification FAILED")
    }
}
