/// Aleo Execution — authorization, proving, and transaction packaging pipeline.
///
/// 1. Authorize — build authorization for a function call
/// 2. Execute — run locally, getting response + trace
/// 3. Prove + package — prepare trace, prove execution + fee, verify, package into Transaction

use anyhow::{Context, Result};
use snarkvm::algorithms::snark::varuna::VarunaVersion;
use snarkvm::circuit::AleoTestnetV0;
use snarkvm::console::program::ProgramID;
use snarkvm::ledger::block::Transaction;
use snarkvm::parameters::testnet::{FeePublicV0Prover, FeePublicV0Verifier};
use snarkvm::prelude::{
    ConsensusVersion, FromBytes as _, Identifier, InclusionVersion, Network, PrivateKey, Process,
    Program, Response, TestRng, TestnetV0,
};
use snarkvm::synthesizer::process::Trace;
use snarkvm::synthesizer::snark::{ProvingKey, VerifyingKey};
use std::marker::PhantomData;
use std::str::FromStr;

/// Custom query trait abstraction for state root fetching.
pub use snarkvm::ledger::query::QueryTrait;

/// Execution engine wrapping a snarkVM `Process`.
pub struct ExecutionEngine<N: Network> {
    pub process: Process<N>,
    _network: PhantomData<N>,
}

impl ExecutionEngine<TestnetV0> {
    /// Initialize a new process, loading credits + a user program.
    ///
    /// Optionally injects V0 fee keys (required for testnet deployments).
    pub fn new(program: &Program<TestnetV0>, inject_v0_fee_keys: bool) -> Result<Self> {
        let mut process = Process::<TestnetV0>::load()?;

        let credits_program = Program::<TestnetV0>::credits()?;
        process.add_program(&credits_program)?;
        process.add_program(program)?;

        if inject_v0_fee_keys {
            tracing::info!("Loading V0 fee keys from testnet parameters...");
            let fee_pk = ProvingKey::<TestnetV0>::from_bytes_le(&FeePublicV0Prover::load_bytes()?)
                .context("Failed to deserialize V0 fee proving key")?;
            let fee_vk =
                VerifyingKey::<TestnetV0>::from_bytes_le(&FeePublicV0Verifier::load_bytes()?)
                    .context("Failed to deserialize V0 fee verifying key")?;

            let credits_id = credits_program.id();
            let fee_fn = Identifier::<TestnetV0>::from_str("fee_public")?;
            process.insert_proving_key(credits_id, &fee_fn, fee_pk)?;
            process.insert_verifying_key(credits_id, &fee_fn, fee_vk)?;
            tracing::info!("V0 fee keys injected");
        }

        Ok(Self { process, _network: PhantomData })
    }

    /// Add a program to the engine.
    pub fn add_program(&mut self, program: &Program<TestnetV0>) -> Result<()> {
        self.process.add_program(program)?;
        Ok(())
    }

    /// Authorize and execute locally. Returns response + trace.
    pub fn authorize_and_execute(
        &mut self,
        private_key: &PrivateKey<TestnetV0>,
        program_id: &ProgramID<TestnetV0>,
        function_name: &str,
        inputs: Vec<&str>,
        rng: &mut TestRng,
    ) -> Result<(Response<TestnetV0>, Trace<TestnetV0>)> {
        tracing::info!("Authorizing...");
        let authorization = self
            .process
            .authorize::<AleoTestnetV0, _>(private_key, *program_id, function_name, inputs.into_iter(), rng)
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
        &mut self,
        trace: Trace<TestnetV0>,
        private_key: &PrivateKey<TestnetV0>,
        program_id: &ProgramID<TestnetV0>,
        function_name: &str,
        base_fee: u64,
        priority_fee: u64,
        query: &impl QueryTrait<TestnetV0>,
        rng: &mut TestRng,
    ) -> Result<Transaction<TestnetV0>> {
        let locator = format!("{}/{}", program_id, function_name);

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
            .authorize_fee_public::<AleoTestnetV0, _>(private_key, base_fee, priority_fee, execution_id, rng)
            .context("Failed to authorize fee")?;

        let (_fee_response, mut fee_trace) = self
            .process
            .execute::<AleoTestnetV0, _>(fee_authorization, rng)
            .context("Failed to execute fee")?;

        fee_trace.prepare(query).context("Failed to prepare fee trace")?;
        let fee = fee_trace
            .prove_fee::<AleoTestnetV0, _>(VarunaVersion::V2, rng)
            .context("Failed to generate fee proof")?;

        // Local verification
        tracing::info!("Verifying proofs locally...");
        self.process
            .verify_execution(
                ConsensusVersion::V14,
                VarunaVersion::V2,
                InclusionVersion::V0,
                &execution,
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
}
