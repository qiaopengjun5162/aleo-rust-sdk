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
//! let engine = ExecutionEngine::new_with_fee_keys().unwrap();
//! // see AleoClient::execute_and_broadcast() for a full pipeline example
//! ```

use anyhow::{Context, Result};
use indexmap::IndexMap;
use snarkvm::algorithms::snark::varuna::VarunaVersion;
use snarkvm::circuit::AleoTestnetV0;
use snarkvm::console::program::{
    Identifier, Plaintext, ProgramID, ProgramOwner, Record, RegisterType, Value, ValueType,
};
use snarkvm::ledger::block::{Deployment, Execution, Transaction};
use snarkvm::prelude::{
    Address, Authorization, ComputeKey, ConsensusVersion, CryptoRng, Field, InclusionVersion,
    PrivateKey, Process, Program, Response, Rng, TestRng, TestnetV0,
};
use snarkvm::synthesizer::process::{
    Stack, Trace, deployment_cost, execution_cost, execution_cost_for_authorization,
    minimum_cost_in_microcredits_v2,
};
use snarkvm::synthesizer::program::StackTrait;
use std::str::FromStr;
use std::sync::Arc;

/// Custom query trait for state root fetching.
pub use snarkvm::ledger::query::QueryTrait;

/// Fee key loader — injects proving/verifying keys for testnet fee_public.
mod fee_keys {
    use snarkvm::parameters::testnet::{FeePublicProver, FeePublicVerifier};
    use snarkvm::prelude::FromBytes as _;
    use snarkvm::synthesizer::snark::{ProvingKey, VerifyingKey};

    pub fn load_pk() -> Result<ProvingKey<snarkvm::prelude::TestnetV0>, anyhow::Error> {
        ProvingKey::from_bytes_le(&FeePublicProver::load_bytes()?)
    }

    pub fn load_vk() -> Result<VerifyingKey<snarkvm::prelude::TestnetV0>, anyhow::Error> {
        VerifyingKey::from_bytes_le(&FeePublicVerifier::load_bytes()?)
    }
}

/// Helper: map a `ConsensusVersion` to the corresponding `VarunaVersion`.
/// Logic mirrors `snarkvm::console::network::varuna_version_from_consensus`.
pub fn consensus_version_to_varuna(cv: ConsensusVersion) -> VarunaVersion {
    use snarkvm::console::network::varuna_version_from_consensus;
    varuna_version_from_consensus(cv)
}

/// Whether a deployment publishes a new program or upgrades an existing one.
///
/// The on-wire difference is the program `edition`: a fresh deployment must
/// carry edition 0, while an upgrade carries `on_chain_edition + 1`. snarkVM
/// computes the latter when the currently deployed source was loaded first
/// with [`ExecutionEngine::add_program_with_edition`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentKind {
    /// First deployment of a program; the edition is reset to 0.
    Fresh,
    /// Upgrade of an already deployed program; the edition is preserved.
    Upgrade,
}

/// Execution engine wrapping a snarkVM `Process`.
pub struct ExecutionEngine {
    pub process: Process<TestnetV0>,
}

impl ExecutionEngine {
    /// Initialize using `Process::load()` (loads current consensus version keys).
    pub fn new() -> Result<Self> {
        let process = Process::<TestnetV0>::load()?;
        Ok(Self { process })
    }

    /// Initialize using `Process::load_v0()` (V0 credits keys) with explicit
    /// V0 fee proving/verifying key injection.
    pub fn new_with_fee_keys() -> Result<Self> {
        let mut engine = Self::new()?;
        engine.inject_fee_keys()?;
        Ok(engine)
    }

    /// Inject fee proving/verifying keys for testnet fee_public support.
    pub fn inject_fee_keys(&mut self) -> Result<()> {
        tracing::info!("Loading fee keys from testnet parameters...");
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

    /// Add a program **at a known on-chain edition**.
    ///
    /// This is the first half of a program upgrade: the currently deployed
    /// source is fetched from the node, then loaded at its real edition with
    /// [`AleoHttpClient::fetch_latest_program_edition`](crate::network::AleoHttpClient::fetch_latest_program_edition).
    /// A subsequent [`ExecutionEngine::deploy_program`] of the *new* source sees
    /// that the program already exists and produces a deployment whose edition
    /// is `edition + 1` (snarkVM `Stack::initialize`), which is what marks the
    /// deployment as an upgrade rather than a fresh program.
    ///
    /// Plain [`ExecutionEngine::add_program`] always starts at edition 0 and is
    /// therefore wrong for this path.
    ///
    /// > **Protocol constraint.** snarkVM 4.12 only accepts *changed* source
    /// > on the next [`ExecutionEngine::deploy_program`] when the deployed
    /// > program declares a `constructor` (`Stack::new` →
    /// > `check_upgrade_is_valid`). Legacy programs without one fail with
    /// > "already exists with different contents" — that is a chain rule,
    /// > not something the SDK can bypass.
    ///
    /// # Errors
    ///
    /// Returns an error if the program is malformed, its imports are missing,
    /// or the existing stack fails snarkVM's consistency check.
    pub fn add_program_with_edition(
        &self,
        program: &Program<TestnetV0>,
        edition: u16,
    ) -> Result<()> {
        self.process
            .lock()
            .add_program_with_edition(program, edition)
            .with_context(|| format!("Failed to load {} at edition {edition}", program.id()))?;
        Ok(())
    }

    /// Synthesize the proving and verifying key for one function.
    ///
    /// This is the Rust counterpart of pre-warming a JS `FunctionKeyProvider`:
    /// the first execution of a function otherwise builds its circuit on
    /// demand, which is the expensive part of authorizing and proving.
    ///
    /// The keys live in **this engine's** [`Process`] only. A fresh
    /// [`ExecutionEngine::new`] starts with a new process, so it needs its own
    /// synthesis pass — there is no on-disk key cache here. `rng` is supplied
    /// by the caller for the same reason it is on the rest of this API: snarkVM
    /// samples a burner key and input values while constructing the circuit.
    ///
    /// Calling this twice is cheap: snarkVM returns `Ok(())` immediately when
    /// both keys already exist.
    ///
    /// # Errors
    ///
    /// Returns an error if `function_name` is not a valid Aleo identifier, the
    /// program is not loaded in this process, or circuit synthesis fails.
    pub fn synthesize_key(
        &self,
        program_id: &ProgramID<TestnetV0>,
        function_name: &str,
        rng: &mut TestRng,
    ) -> Result<()> {
        let fn_id = Identifier::<TestnetV0>::from_str(function_name)
            .with_context(|| format!("Invalid function name: {function_name}"))?;
        self.synthesize_key_by_id(program_id, &fn_id, rng)
    }

    /// Synthesize the keys for **every function** in `program`.
    ///
    /// The JS `ProgramManager.synthesizeKeys` equivalent. The program is added
    /// to the process first if this engine has not seen it yet, so one call can
    /// pre-warm a program that was never executed here. Returns the number of
    /// functions processed — already-present keys count, they are not rebuilt.
    ///
    /// # Errors
    ///
    /// Returns an error if the program cannot be loaded, or if any function's
    /// circuit synthesis fails. Keys synthesized before the failure stay in
    /// this engine's process; the call is not transactional.
    pub fn synthesize_keys(
        &self,
        program: &Program<TestnetV0>,
        rng: &mut TestRng,
    ) -> Result<usize> {
        let program_id = program.id();
        if !self.process.contains_program(program_id) {
            self.add_program(program)
                .with_context(|| format!("Failed to load {program_id} for key synthesis"))?;
        }

        let mut count = 0;
        for fn_id in program.functions().keys() {
            self.synthesize_key_by_id(program_id, fn_id, rng)?;
            count += 1;
        }
        Ok(count)
    }

    /// Shared implementation, so both public entry points report the failing
    /// locator instead of a bare snarkVM error.
    fn synthesize_key_by_id(
        &self,
        program_id: &ProgramID<TestnetV0>,
        fn_id: &Identifier<TestnetV0>,
        rng: &mut TestRng,
    ) -> Result<()> {
        self.process
            .synthesize_key::<AleoTestnetV0, _>(program_id, fn_id, rng)
            .with_context(|| format!("Failed to synthesize key for {program_id}/{fn_id}"))
    }

    /// Authorize and execute locally using pre-parsed snarkVM `Value` inputs.
    /// Use this variant when the caller already built `Value`s — e.g. a record
    /// input wrapped as [`snarkvm::prelude::Value::Record`], which holds a
    /// **plaintext** record (the decrypted form, not the `record1...` string).
    pub fn authorize_and_execute_with_values(
        &self,
        private_key: &PrivateKey<TestnetV0>,
        program_id: &ProgramID<TestnetV0>,
        function_name: &str,
        values: Vec<Value<TestnetV0>>,
        rng: &mut TestRng,
    ) -> Result<(Response<TestnetV0>, Trace<TestnetV0>)> {
        tracing::info!("Authorizing with pre-parsed values...");
        let fn_id = Identifier::<TestnetV0>::from_str(function_name)?;
        let authorization = self
            .process
            .authorize::<AleoTestnetV0, _>(private_key, *program_id, fn_id, values.into_iter(), rng)
            .context("Authorization failed")?;

        tracing::info!("Executing locally...");
        let (response, trace) = self
            .process
            .execute::<AleoTestnetV0, _>(authorization, rng)
            .context("Local execution failed")?;

        tracing::info!("Execution succeeded");
        Ok((response, trace))
    }

    /// Authorize a function call and return the `Authorization` itself.
    ///
    /// This is what delegated proving needs: the DPS proves an authorization
    /// server-side, so the local side stops after authorization and never pays
    /// the proving cost. [`authorize_and_execute`](Self::authorize_and_execute)
    /// is the local-execution path and builds on this.
    pub fn authorize(
        &self,
        private_key: &PrivateKey<TestnetV0>,
        program_id: &ProgramID<TestnetV0>,
        function_name: &str,
        inputs: Vec<&str>,
        rng: &mut TestRng,
    ) -> Result<Authorization<TestnetV0>> {
        let fn_id = Identifier::<TestnetV0>::from_str(function_name)?;
        self.process
            .authorize::<AleoTestnetV0, _>(private_key, *program_id, fn_id, inputs.into_iter(), rng)
            .context("Authorization failed")
    }

    /// Derive the `(program_id, function_name)` locator from an authorization.
    ///
    /// An [`Authorization`] carries its own requests, so a caller that saved
    /// one offline does not need to remember which call produced it. Requests
    /// are stored in pre-order (parents before children), so the first one is
    /// the root call — exactly the locator the proving and fee steps need.
    ///
    /// This is the Rust counterpart of the JS `ProgramManager` remembering the
    /// call behind `buildAuthorization`.
    pub fn authorization_locator(
        authorization: &Authorization<TestnetV0>,
    ) -> Result<(ProgramID<TestnetV0>, String)> {
        let request = authorization.peek_next().context("Authorization contains no requests")?;
        Ok((*request.program_id(), request.function_name().to_string()))
    }

    // ── Fee estimation (JS ProgramManager `estimate*` family) ────────────
    //
    // All three are offline computations — no network, no account, and no
    // Varuna proving. They return the **base fee in microcredits**; add the
    // priority fee on top when building the transaction.

    /// Estimate the execution fee for a function call — the JS
    /// `ProgramManager.estimateExecutionFee`.
    ///
    /// Authorizes a throwaway call with a fresh burner key and synthetic
    /// inputs (every input type is sampled, records included) and prices the
    /// resulting [`Authorization`] with
    /// `execution_cost_for_authorization`. The sampled values do not change
    /// the outcome: the cost is driven by the function's circuit shapes and
    /// record counts, not by the data.
    ///
    /// The fee is computed at [`ConsensusVersion::latest()`], which is what a
    /// transaction broadcast now will pay — later blocks only move the price
    /// forward (verifying a past transaction must instead use the consensus
    /// version of its block; see `verify_execution_at`).
    ///
    /// The program must be in the engine's process; it is added when missing
    /// (the JS version likewise accepts the source and resolves it). Its own
    /// imports must already be loaded — add them first with
    /// [`add_program`](Self::add_program) if it has any.
    pub fn estimate_execution_fee(
        &self,
        program: &Program<TestnetV0>,
        function_name: &str,
    ) -> Result<u64> {
        let mut rng = TestRng::default();
        let program_id = *program.id();
        let fn_id = Identifier::<TestnetV0>::from_str(function_name)?;

        // A burner key: the authorization is priced and discarded.
        let burner_private_key = PrivateKey::new(&mut rng)?;
        let burner_address = Address::try_from(&ComputeKey::try_from(&burner_private_key)?)?;

        if !self.process.contains_program(&program_id) {
            self.add_program(program)?;
        }

        let function = program.get_function(&fn_id)?;
        let mut sampled = Vec::new();
        for input_type in function.input_types() {
            let value = match &input_type {
                ValueType::ExternalRecord(locator) => {
                    // Sample the foreign record from its own program's stack.
                    let stack = self.process.get_stack(locator.program_id())?;
                    stack.sample_value(
                        &burner_address,
                        &RegisterType::from(ValueType::Record(*locator.resource())),
                        &mut rng,
                    )?
                }
                other => {
                    let stack = self.process.get_stack(program_id)?;
                    stack.sample_value(
                        &burner_address,
                        &RegisterType::from(other.clone()),
                        &mut rng,
                    )?
                }
            };
            sampled.push(value);
        }

        let authorization = self.process.authorize::<AleoTestnetV0, _>(
            &burner_private_key,
            program_id,
            fn_id,
            sampled.into_iter(),
            &mut rng,
        )?;
        self.estimate_fee_for_authorization(&authorization)
    }

    /// Price an existing [`Authorization`] — the JS
    /// `ProgramManager.estimateFeeForAuthorization`.
    ///
    /// The authorization's program must already be in the process (add it
    /// with [`add_program`](Self::add_program) first). Computed at
    /// [`ConsensusVersion::latest()`], like
    /// [`estimate_execution_fee`](Self::estimate_execution_fee).
    pub fn estimate_fee_for_authorization(
        &self,
        authorization: &Authorization<TestnetV0>,
    ) -> Result<u64> {
        let (minimum_cost, _) = execution_cost_for_authorization(
            &self.process,
            authorization,
            ConsensusVersion::latest(),
        )?;
        Ok(minimum_cost)
    }

    /// Estimate the finalize fee component of a function — the JS
    /// `ProgramManager.estimateFinalizeFee`.
    ///
    /// Only the finalize half: 0 for a function without a finalize step,
    /// nonzero for an `async` function (its finalize cost). A lower bound for
    /// dynamic futures, which cannot be priced statically — the JS docs mark
    /// the whole estimate experimental and this shares the caveat.
    ///
    /// Unlike the JS version (which looks the stack up without ever loading
    /// the program), the program is added to the process when missing.
    pub fn estimate_finalize_fee(
        &self,
        program: &Program<TestnetV0>,
        function_name: &str,
    ) -> Result<u64> {
        let program_id = *program.id();
        if !self.process.contains_program(&program_id) {
            self.add_program(program)?;
        }
        let fn_id = Identifier::<TestnetV0>::from_str(function_name)?;
        let stack = self.process.get_stack(program_id)?;
        minimum_cost_in_microcredits_v2(&stack, &fn_id)
    }

    /// Authorize and execute locally. Returns response + trace.
    ///
    /// Inputs are parsed as snarkVM `Value`s. Record inputs must be **plaintext
    /// record literals** (`{ owner: ...private, microcredits: ...u64.private,
    /// _nonce: ...group.public }`) — snarkVM's `Value` parser has no arm for
    /// `record1...` ciphertexts, so a record must be decrypted before it can be
    /// spent. See [`crate::credits`] for callers that format these.
    pub fn authorize_and_execute(
        &self,
        private_key: &PrivateKey<TestnetV0>,
        program_id: &ProgramID<TestnetV0>,
        function_name: &str,
        inputs: Vec<&str>,
        rng: &mut TestRng,
    ) -> Result<(Response<TestnetV0>, Trace<TestnetV0>)> {
        tracing::info!("Authorizing...");
        let authorization = self.authorize(private_key, program_id, function_name, inputs, rng)?;
        self.execute_authorization(authorization, rng)
    }

    /// Execute an **already-built authorization** locally, returning its
    /// response and trace.
    ///
    /// This is the second half of [`Self::authorize_and_execute`]
    /// and the Rust counterpart of the JS `buildTransactionFromAuthorization`:
    /// build an authorization with [`authorize`](Self::authorize) (offline,
    /// possibly on another machine), persist it — `Authorization`'s `Display`
    /// is JSON and its `FromStr` parses that JSON back — then hand it here
    /// later. Feed the resulting trace to
    /// [`prove_and_package`](Self::prove_and_package) to finish the transaction,
    /// or use `AleoClient::build_transaction_from_authorization` to do both in
    /// one call with network/state-root handling.
    ///
    /// The program behind the authorization must already be loaded in this
    /// engine's process (see [`add_program`](Self::add_program)).
    pub fn execute_authorization(
        &self,
        authorization: Authorization<TestnetV0>,
        rng: &mut TestRng,
    ) -> Result<(Response<TestnetV0>, Trace<TestnetV0>)> {
        tracing::info!("Executing authorization locally...");
        let (response, trace) = self
            .process
            .execute::<AleoTestnetV0, _>(authorization, rng)
            .context("Local execution failed")?;
        Ok((response, trace))
    }

    /// Prove execution + fee, verify, package into `Transaction`.
    ///
    /// Dynamically computes the correct `base_fee` via `execution_cost()` using
    /// the given `consensus_version`, instead of expecting a hardcoded value.
    /// This fixes broadcast failures that occur when the consensus version advances
    /// (e.g. V14→V20 changed the minimum cost from 100_000 to 2_725).
    /// Prove an execution trace and compute its dynamic base fee.
    ///
    /// Shared by the public and private fee packagers — the only part that
    /// differs between them is how the fee authorization is built. Returns the
    /// proven `Execution` plus the fee inputs the authorization needs.
    #[allow(clippy::too_many_arguments)]
    fn prepare_proven_execution(
        &self,
        trace: Trace<TestnetV0>,
        program_id: &ProgramID<TestnetV0>,
        function_name: &str,
        consensus_version: ConsensusVersion,
        varuna_version: VarunaVersion,
        query: &impl QueryTrait<TestnetV0>,
        rng: &mut TestRng,
    ) -> Result<(Execution<TestnetV0>, u64, Field<TestnetV0>)> {
        let locator = format!("{program_id}/{function_name}");
        let mut exec_trace = trace;
        exec_trace.prepare(query).context("Failed to prepare execution trace")?;
        let execution = exec_trace
            .prove_execution::<AleoTestnetV0, _>(&locator, varuna_version, rng)
            .context("Failed to generate execution proof")?;
        let execution_id = execution.to_execution_id()?;
        let (minimum_cost, _) = execution_cost(&self.process, &execution, consensus_version)?;
        Ok((execution, minimum_cost, execution_id))
    }

    /// Prove the fee transition for an already-proven execution, verify both
    /// proofs locally, and package them into a `Transaction`.
    ///
    /// Shared by [`prove_and_package`](Self::prove_and_package) and
    /// [`prove_and_package_with_private_fee`](Self::prove_and_package_with_private_fee) —
    /// the two only differ in how the fee authorization is built.
    #[allow(clippy::too_many_arguments)]
    fn prove_fee_and_package(
        &self,
        execution: Execution<TestnetV0>,
        fee_authorization: Authorization<TestnetV0>,
        consensus_version: ConsensusVersion,
        varuna_version: VarunaVersion,
        query: &impl QueryTrait<TestnetV0>,
        rng: &mut TestRng,
    ) -> Result<Transaction<TestnetV0>> {
        let execution_id = execution.to_execution_id()?;

        let (_fee_response, mut fee_trace) = self
            .process
            .execute::<AleoTestnetV0, _>(fee_authorization, rng)
            .context("Failed to execute fee")?;

        fee_trace.prepare(query).context("Failed to prepare fee trace")?;
        let fee = fee_trace
            .prove_fee::<AleoTestnetV0, _>(varuna_version, rng)
            .context("Failed to generate fee proof")?;

        // Build execution_stacks for verification
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

        // Local verification with the same consensus_version the chain uses
        tracing::info!("Verifying proofs locally (consensus={consensus_version:?})...");
        Process::<TestnetV0>::verify_execution(
            consensus_version,
            varuna_version,
            InclusionVersion::V1,
            &execution,
            &execution_stacks,
        )
        .context("Local execution verification FAILED")?;

        tracing::info!("Fee proof verification...");
        self.process
            .verify_fee(
                consensus_version,
                varuna_version,
                InclusionVersion::V1,
                &fee,
                execution_id,
            )
            .context("Local fee verification FAILED")?;

        Transaction::<TestnetV0>::from_execution(execution, Some(fee))
            .context("Failed to package transaction")
    }

    /// Prove execution + fee, verify, package into `Transaction`.
    ///
    /// Dynamically computes the correct `base_fee` via `execution_cost()` using
    /// the given `consensus_version`, instead of expecting a hardcoded value.
    /// This fixes broadcast failures that occur when the consensus version advances
    /// (e.g. V14→V20 changed the minimum cost from 100_000 to 2_725).
    #[allow(clippy::too_many_arguments)]
    pub fn prove_and_package(
        &self,
        trace: Trace<TestnetV0>,
        private_key: &PrivateKey<TestnetV0>,
        program_id: &ProgramID<TestnetV0>,
        function_name: &str,
        priority_fee: u64,
        consensus_version: ConsensusVersion,
        varuna_version: VarunaVersion,
        query: &impl QueryTrait<TestnetV0>,
        rng: &mut TestRng,
    ) -> Result<Transaction<TestnetV0>> {
        let (execution, minimum_cost, execution_id) = self.prepare_proven_execution(
            trace,
            program_id,
            function_name,
            consensus_version,
            varuna_version,
            query,
            rng,
        )?;
        tracing::info!(
            "Dynamic fee: minimum_cost={minimum_cost} (hardcoded was 100_000), priority_fee={priority_fee}"
        );

        let fee_authorization = self
            .process
            .authorize_fee_public::<AleoTestnetV0, _>(
                private_key,
                minimum_cost,
                priority_fee,
                execution_id,
                rng,
            )
            .context("Failed to authorize fee")?;

        self.prove_fee_and_package(
            execution,
            fee_authorization,
            consensus_version,
            varuna_version,
            query,
            rng,
        )
    }

    /// Prove execution and package a transaction **without a fee**.
    ///
    /// `credits.aleo/split` is the one call the protocol lets through unpaid —
    /// the JS SDK's `buildSplitTransaction` packages with `None` where every
    /// other builder passes a fee. Everything else must go through
    /// [`prove_and_package`](Self::prove_and_package), which authorizes and
    /// proves a `fee_public`.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_and_package_feeless(
        &self,
        trace: Trace<TestnetV0>,
        program_id: &ProgramID<TestnetV0>,
        function_name: &str,
        consensus_version: ConsensusVersion,
        varuna_version: VarunaVersion,
        query: &impl QueryTrait<TestnetV0>,
        rng: &mut TestRng,
    ) -> Result<Transaction<TestnetV0>> {
        let locator = format!("{program_id}/{function_name}");

        // 1. Prove execution
        let mut exec_trace = trace;
        exec_trace.prepare(query).context("Failed to prepare execution trace")?;
        let execution = exec_trace
            .prove_execution::<AleoTestnetV0, _>(&locator, varuna_version, rng)
            .context("Failed to generate execution proof")?;

        // 2. Build execution_stacks for verification
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

        // 3. Local verification with the same consensus_version the chain uses
        Process::<TestnetV0>::verify_execution(
            consensus_version,
            varuna_version,
            InclusionVersion::V1,
            &execution,
            &execution_stacks,
        )
        .context("Local execution verification FAILED")?;

        Transaction::<TestnetV0>::from_execution(execution, None)
            .context("Failed to package transaction")
    }

    /// Prove execution + **private** fee, verify, package into `Transaction`.
    ///
    /// Identical to [`prove_and_package`](Self::prove_and_package) except the
    /// fee transition spends `record` (a plaintext `credits.aleo` record
    /// literal owned by `private_key`) rather than drawing from the public
    /// balance. Use this when the caller wants the fee to be paid privately —
    /// the JS SDK's `privateFee` path. The record must cover the dynamically
    /// computed `base_fee` plus `priority_fee` in microcredits.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_and_package_with_private_fee(
        &self,
        trace: Trace<TestnetV0>,
        private_key: &PrivateKey<TestnetV0>,
        program_id: &ProgramID<TestnetV0>,
        function_name: &str,
        record: &str,
        priority_fee: u64,
        consensus_version: ConsensusVersion,
        varuna_version: VarunaVersion,
        query: &impl QueryTrait<TestnetV0>,
        rng: &mut TestRng,
    ) -> Result<Transaction<TestnetV0>> {
        let (execution, minimum_cost, execution_id) = self.prepare_proven_execution(
            trace,
            program_id,
            function_name,
            consensus_version,
            varuna_version,
            query,
            rng,
        )?;
        tracing::info!(
            "Dynamic fee (private): minimum_cost={minimum_cost}, priority_fee={priority_fee}"
        );

        // Private fee authorization: spend `record` instead of public balance.
        let credits_record: Record<TestnetV0, Plaintext<TestnetV0>> = Record::from_str(record)
            .context("Failed to parse the fee record as a plaintext credits record")?;
        let fee_authorization = self
            .process
            .authorize_fee_private::<AleoTestnetV0, _>(
                private_key,
                credits_record,
                minimum_cost,
                priority_fee,
                execution_id,
                rng,
            )
            .context("Failed to authorize private fee")?;

        self.prove_fee_and_package(
            execution,
            fee_authorization,
            consensus_version,
            varuna_version,
            query,
            rng,
        )
    }

    /// Authorize a **public fee** against an existing authorization.
    ///
    /// Delegated proving needs the fee authorization *before* the proof exists,
    /// so the execution ID is derived from the (unproven) transitions of
    /// `authorization` via `Authorization::to_execution_id()`. That is the same
    /// ID the prover will commit to when it proves the execution, which is why
    /// this stays valid end-to-end.
    ///
    /// `base_fee` is not computed here: the real cost is only knowable from a
    /// proven execution. Pass the value from
    /// [`ExecutionEngine::deployment_cost_minimum`] for deployments, or a value
    /// obtained from a prior local run; the chain rejects anything below the
    /// minimum for the current consensus version.
    pub fn authorize_fee_public_authorization(
        &self,
        private_key: &PrivateKey<TestnetV0>,
        base_fee: u64,
        priority_fee: u64,
        authorization: &Authorization<TestnetV0>,
        rng: &mut TestRng,
    ) -> Result<Authorization<TestnetV0>> {
        let execution_id =
            authorization.to_execution_id().context("Failed to derive execution ID")?;
        self.process
            .authorize_fee_public::<AleoTestnetV0, _>(
                private_key,
                base_fee,
                priority_fee,
                execution_id,
                rng,
            )
            .context("Failed to authorize fee")
    }

    /// Authorize a **private fee** against an existing authorization.
    ///
    /// This is the private-record counterpart of
    /// [`authorize_fee_public_authorization`](Self::authorize_fee_public_authorization):
    /// instead of drawing the fee from the caller's public `credits.aleo`
    /// balance, the fee transition spends `record` — a plaintext
    /// `credits.aleo` record literal owned by `private_key`. The record must
    /// hold at least `base_fee + priority_fee` microcredits or the chain
    /// rejects the transaction.
    ///
    /// Only the authorize step runs here — no proving — so this is cheap and
    /// fully offline. The resulting authorization is the fee half of
    /// [`prove_and_package_with_private_fee`](Self::prove_and_package_with_private_fee).
    pub fn authorize_fee_private_authorization(
        &self,
        private_key: &PrivateKey<TestnetV0>,
        record: &str,
        base_fee: u64,
        priority_fee: u64,
        authorization: &Authorization<TestnetV0>,
        rng: &mut TestRng,
    ) -> Result<Authorization<TestnetV0>> {
        let credits_record: Record<TestnetV0, Plaintext<TestnetV0>> = Record::from_str(record)
            .context("Failed to parse the fee record as a plaintext credits record")?;
        let execution_id =
            authorization.to_execution_id().context("Failed to derive execution ID")?;
        self.process
            .authorize_fee_private::<AleoTestnetV0, _>(
                private_key,
                credits_record,
                base_fee,
                priority_fee,
                execution_id,
                rng,
            )
            .context("Failed to authorize private fee")
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

    /// Fill in the deployment metadata that snarkVM leaves to the caller.
    ///
    /// Pure and offline: no proving and no network access. A **fresh**
    /// deployment must carry edition 0 — the on-chain validator rejects a
    /// non-zero edition when the program does not exist yet. An **upgrade**
    /// keeps the edition produced by [`ExecutionEngine::deploy_program`], which
    /// is `on_chain_edition + 1` when the deployed source was loaded first with
    /// [`ExecutionEngine::add_program_with_edition`].
    ///
    /// Returns a clone; the input is never mutated.
    ///
    /// # Errors
    ///
    /// Returns an error if the program has no functions or the private key
    /// cannot be converted to an address.
    pub fn prepare_deployment_metadata(
        deployment: &Deployment<TestnetV0>,
        private_key: &PrivateKey<TestnetV0>,
        kind: DeploymentKind,
    ) -> Result<Deployment<TestnetV0>> {
        if deployment.program().functions().is_empty() {
            anyhow::bail!("Attempted to create an empty deployment");
        }

        let mut deployment = deployment.clone();
        // `Process::deploy` computes its edition via `Stack::new`: when the
        // program is already in the process (the usual SDK flow) that is 1 for
        // a fresh deploy. Reset only for the fresh case — an upgrade must keep
        // the incremented edition.
        if kind == DeploymentKind::Fresh {
            deployment.set_edition_raw(0);
        }
        let addr = Address::try_from(private_key)?;
        deployment.set_program_owner_raw(Some(addr));
        deployment.set_program_checksum_raw(Some(deployment.program().to_checksum()));
        Ok(deployment)
    }

    /// Full deployment pipeline: prove program → authorize fee → prove fee →
    /// verify → package into [`Transaction`].
    ///
    /// This is the equivalent of JS SDK's `buildDeploymentTransaction`.
    ///
    /// `base_fee` is the minimum deployment cost (use [`ExecutionEngine::deployment_cost_minimum`] to compute it).
    /// `priority_fee_in_microcredits` is an additional fee on top.
    /// `consensus_version` determines which fee proving key to use.
    /// `query` supplies the current state root (from [`AleoHttpClient::fetch_state_root`](crate::network::AleoHttpClient::fetch_state_root)).
    #[allow(clippy::too_many_arguments)]
    pub fn build_deployment_transaction<R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<TestnetV0>,
        _program: &Program<TestnetV0>,
        deployment: &Deployment<TestnetV0>,
        base_fee: u64,
        priority_fee_in_microcredits: u64,
        consensus_version: ConsensusVersion,
        query: &impl QueryTrait<TestnetV0>,
        rng: &mut R,
    ) -> Result<Transaction<TestnetV0>> {
        self.build_deployment_transaction_with_kind(
            private_key,
            deployment,
            base_fee,
            priority_fee_in_microcredits,
            consensus_version,
            query,
            rng,
            DeploymentKind::Fresh,
        )
    }

    /// Full **upgrade** pipeline — the Rust counterpart of JS
    /// `ProgramManager.buildUpgradeTransaction`.
    ///
    /// Identical to [`Self::build_deployment_transaction`] except that the
    /// deployment's non-zero edition is **preserved** instead of reset to 0.
    /// Before calling, load the currently deployed source with
    /// [`Self::add_program_with_edition`] (using the node's
    /// `latest_edition`), then generate the deployment from the *new* source
    /// with [`Self::deploy_program`]. Skipping that step yields edition 1 and
    /// the node will reject the upgrade.
    #[allow(clippy::too_many_arguments)]
    pub fn build_upgrade_transaction<R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<TestnetV0>,
        _program: &Program<TestnetV0>,
        deployment: &Deployment<TestnetV0>,
        base_fee: u64,
        priority_fee_in_microcredits: u64,
        consensus_version: ConsensusVersion,
        query: &impl QueryTrait<TestnetV0>,
        rng: &mut R,
    ) -> Result<Transaction<TestnetV0>> {
        self.build_deployment_transaction_with_kind(
            private_key,
            deployment,
            base_fee,
            priority_fee_in_microcredits,
            consensus_version,
            query,
            rng,
            DeploymentKind::Upgrade,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_deployment_transaction_with_kind<R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<TestnetV0>,
        deployment: &Deployment<TestnetV0>,
        base_fee: u64,
        priority_fee_in_microcredits: u64,
        consensus_version: ConsensusVersion,
        query: &impl QueryTrait<TestnetV0>,
        rng: &mut R,
        kind: DeploymentKind,
    ) -> Result<Transaction<TestnetV0>> {
        let deployment = Self::prepare_deployment_metadata(deployment, private_key, kind)?;
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

        let varuna_version = consensus_version_to_varuna(consensus_version);
        let fee = fee_trace
            .prove_fee::<AleoTestnetV0, R>(varuna_version, rng)
            .context("Failed to prove fee")?;

        // Package into transaction.
        Transaction::<TestnetV0>::from_deployment(owner, deployment, fee)
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
        consensus_version: ConsensusVersion,
    ) -> Result<()> {
        let varuna_version = consensus_version_to_varuna(consensus_version);
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
            consensus_version,
            varuna_version,
            InclusionVersion::V1,
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
        consensus_version: ConsensusVersion,
        rng: &mut TestRng,
    ) -> Result<()> {
        self.process
            .verify_deployment::<AleoTestnetV0, _>(consensus_version, deployment, rng)
            .context("Deployment proof verification FAILED")
    }
}
