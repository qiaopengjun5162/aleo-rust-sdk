//! `ExecutionResponse` — parity with the JS SDK's wasm `ExecutionResponse` class.
//!
//! Unlike [`crate::address`], [`crate::boolean`] or [`crate::ciphertext`], this
//! page has **no snarkVM equivalent**. The wasm `ExecutionResponse` is a
//! purpose-built bundle that `ProgramManager.run()` returns from an *off-chain*
//! execution: it packages the [`Execution`], the [`Response`], the [`Program`],
//! the function name, and the function's proving/verifying keys into one object.
//! snarkVM keeps those values separate, so this module adds the container.
//!
//! ## JS `ExecutionResponse` → Rust mapping
//!
//! | # | JS method                  | Rust equivalent                          | Contract |
//! |---|----------------------------|------------------------------------------|----------|
//! | 1 | `getOutputs()` → `Array`   | [`ExecutionResponse::get_outputs`]        | `Vec<String>`, one per output, in order |
//! | 2 | `getProgram()` → `Program` | [`ExecutionResponse::get_program`]        | `&Program<N>` (borrow, not a clone) |
//! | 3 | `getExecution()` → `Execution \| null` | [`ExecutionResponse::get_execution`] | `Option<&Execution<N>>` |
//! | 4 | `getFunctionId()` → `string` | [`ExecutionResponse::get_function_id`]  | `Identifier<N>` rendered as a string |
//! | 5 | `getProvingKey()` → `ProvingKey \| null` | [`ExecutionResponse::take_proving_key`] | **consumes** the cached key |
//! | 6 | `getVerifyingKey()` → `VerifyingKey` | [`ExecutionResponse::get_verifying_key`] | `&VerifyingKey<N>` |
//! | 7 | `getKeys()` → `KeyPair`    | [`ExecutionResponse::take_keys`]          | `Result<ExecutionKeys<N>>`, **consumes** |
//!
//! Plus [`std::ops::Deref<Target = Response<N>>`], matching the wasm
//! `Deref<Target = ResponseNative>`: native `Response` methods such as
//! [`Response::outputs`] and `Response::output_ids` work directly on the bundle.
//!
//! ## The two traps this page hides
//!
//! 1. **`getProvingKey()` and `getKeys()` are not getters.** The wasm class
//!    stores `proving_key: Option<ProvingKeyNative>` and both methods call
//!    `Option::take()`. The first call wins; every later call sees `None`.
//!    `getKeys()` additionally returns the *error* `"No proving key found"`
//!    when the slot is empty, rather than a nullable pair. The Rust methods are
//!    named [`take_proving_key`](ExecutionResponse::take_proving_key) and
//!    [`take_keys`](ExecutionResponse::take_keys) — and take `&mut self` — so
//!    the consumption is visible in the signature instead of being a surprise.
//!    The two also compete for the *same* slot: calling `take_keys()` first
//!    makes `take_proving_key()` return `None`, and vice versa.
//! 2. **`getOutputs()` returns strings, not values.** The wasm implementation
//!    maps each `Value` through `Display` (`"10u32"`, `"true"`, …), so the
//!    array is `Array<string>` — no type information survives except the Aleo
//!    literal suffix. It is *not* fields, bits, or a JSON round-trip. In
//!    particular `Value::to_fields()` is a different encoding entirely.
//!
//! The upstream test vector (`sdk/tests/program-manager.test.ts`) executes
//! `helloProgram/hello` with `5u32 + 5u32` and asserts
//! `execution_result.getOutputs()[0] === "10u32"`; the tests below reproduce
//! that literal cross-language.
//!
//! ## Construction
//!
//! [`ExecutionResponse::new`] mirrors the wasm constructor exactly: it parses
//! the program source, then asks a [`Process`] for the verifying key of
//! `(program.id(), function_id)`. [`ExecutionResponse::from_parts`] is the
//! offline-friendly variant that takes the pieces directly — useful when the
//! keys came from [`crate::keys::OfflineKeyProvider`] or a cache rather than a
//! live `Process`. [`ExecutionResponse::add_proving_key`] corresponds to the
//! wasm `add_proving_key`, which is a separate step: the constructor leaves the
//! proving key *unset*, and `getKeys()` errors until it has been cached.

use anyhow::{Context, Result};
use snarkvm::console::network::Network;
use snarkvm::console::program::{Identifier, ProgramID};
use snarkvm::ledger::block::Execution;
use snarkvm::prelude::{Process, Program, Response};
use snarkvm::synthesizer::snark::{ProvingKey, VerifyingKey};
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

/// The `(proving, verifying)` pair returned by [`ExecutionResponse::take_keys`].
///
/// This is the Rust counterpart of the JS `KeyPair` object *as returned by
/// `getKeys()`. The standalone wasm `KeyPair` class is a separate API surface.
#[derive(Clone)]
pub struct ExecutionKeys<N: Network> {
    proving_key: ProvingKey<N>,
    verifying_key: VerifyingKey<N>,
}

impl<N: Network> ExecutionKeys<N> {
    /// Wrap a proving/verifying key pair.
    pub fn new(proving_key: ProvingKey<N>, verifying_key: VerifyingKey<N>) -> Self {
        Self {
            proving_key,
            verifying_key,
        }
    }

    /// The proving key (JS `KeyPair.provingKey()`).
    pub fn proving_key(&self) -> &ProvingKey<N> {
        &self.proving_key
    }

    /// The verifying key (JS `KeyPair.verifyingKey()`).
    pub fn verifying_key(&self) -> &VerifyingKey<N> {
        &self.verifying_key
    }

    /// Unwrap into `(proving_key, verifying_key)`.
    ///
    /// For `N = TestnetV0` this is shape-compatible with
    /// [`crate::keys::FunctionKeyPair`].
    pub fn into_parts(self) -> (ProvingKey<N>, VerifyingKey<N>) {
        (self.proving_key, self.verifying_key)
    }
}

/// Hand-written: snarkVM's key types implement neither `Debug` nor `Display`,
/// and serializing a proving key into a log would be wasteful and misleading.
impl<N: Network> fmt::Debug for ExecutionKeys<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutionKeys").finish_non_exhaustive()
    }
}

/// The result bundle of an off-chain program execution (JS `ExecutionResponse`).
///
/// Clone is cheap where it matters: both key types wrap an `Arc` in snarkVM.
#[derive(Clone)]
pub struct ExecutionResponse<N: Network> {
    execution: Option<Execution<N>>,
    function_id: Identifier<N>,
    response: Response<N>,
    program: Program<N>,
    proving_key: Option<ProvingKey<N>>,
    verifying_key: VerifyingKey<N>,
}

impl<N: Network> ExecutionResponse<N> {
    /// Build the bundle the way the wasm constructor does: parse `program` and
    /// resolve its verifying key from `process` for `function_id`.
    ///
    /// The proving key starts **unset** — call [`Self::add_proving_key`] (or
    /// [`Self::set_proving_key`]) before [`Self::take_keys`] can succeed.
    ///
    /// # Errors
    ///
    /// Returns an error if `program` is not valid Aleo source, if
    /// `function_id` is not a valid identifier, or if `process` has no
    /// verifying key for `(program.id(), function_id)` — the latter matches
    /// the wasm `"Could not find verifying key for …"` failure.
    pub fn new(
        execution: Option<Execution<N>>,
        function_id: &str,
        response: Response<N>,
        process: &Process<N>,
        program: &str,
    ) -> Result<Self> {
        let program = Program::<N>::from_str(program)
            .map_err(|e| anyhow::anyhow!("Failed to parse program: {e}"))?;
        let verifying_key =
            process.get_verifying_key(program.id(), function_id).with_context(|| {
                format!(
                    "Could not find verifying key for {}/{}",
                    program.id(),
                    function_id
                )
            })?;
        let function_id = Identifier::<N>::from_str(function_id)
            .map_err(|e| anyhow::anyhow!("Invalid function name: {e}"))?;
        Ok(Self {
            execution,
            function_id,
            response,
            program,
            proving_key: None,
            verifying_key,
        })
    }

    /// Build the bundle directly from its parts, with no `Process` involved.
    ///
    /// This is the offline path: keys typically come from
    /// [`crate::keys::OfflineKeyProvider`] (embedded parameter bytes) or a
    /// cache. `proving_key` may be `None`, which is the state the JS object is
    /// in right after construction.
    ///
    /// # Errors
    ///
    /// Returns an error if `function_id` is not a valid Aleo identifier.
    pub fn from_parts(
        execution: Option<Execution<N>>,
        function_id: &str,
        response: Response<N>,
        program: Program<N>,
        proving_key: Option<ProvingKey<N>>,
        verifying_key: VerifyingKey<N>,
    ) -> Result<Self> {
        let function_id = Identifier::<N>::from_str(function_id)
            .map_err(|e| anyhow::anyhow!("Invalid function name: {e}"))?;
        Ok(Self {
            execution,
            function_id,
            response,
            program,
            proving_key,
            verifying_key,
        })
    }

    /// Cache the proving key from `process`, matching the wasm
    /// `add_proving_key` step that runs after proving has been requested.
    ///
    /// # Errors
    ///
    /// Returns an error if `process` has no proving key for
    /// `(program_id, function_id)`.
    pub fn add_proving_key(
        &mut self,
        process: &Process<N>,
        function_id: &str,
        program_id: &ProgramID<N>,
    ) -> Result<()> {
        let proving_key = process.get_proving_key(program_id, function_id).with_context(|| {
            format!("Could not find proving key for {program_id}/{function_id}")
        })?;
        self.proving_key = Some(proving_key);
        Ok(())
    }

    /// Cache an already-loaded proving key (offline counterpart of
    /// [`Self::add_proving_key`]). Overwrites any previously cached key.
    pub fn set_proving_key(&mut self, proving_key: ProvingKey<N>) {
        self.proving_key = Some(proving_key);
    }

    /// Whether a proving key is still cached, **without consuming it**.
    ///
    /// The wasm class has no such probe — the only way to ask is
    /// `getProvingKey()`, which destroys the answer. Rust can do better.
    pub fn has_proving_key(&self) -> bool {
        self.proving_key.is_some()
    }

    // ── The seven JS getters ───────────────────────────────────────────────

    /// JS `getOutputs()` — every output rendered with `Value`'s `Display`.
    ///
    /// The result is a `Vec<String>` of Aleo literals (`["10u32"]`), not
    /// `Value`s, fields, or bytes. Output order is preserved.
    pub fn get_outputs(&self) -> Vec<String> {
        self.response.outputs().iter().map(ToString::to_string).collect()
    }

    /// JS `getProgram()` — the executed program.
    ///
    /// The wasm binding clones; Rust borrows. Call `.clone()` when ownership
    /// is needed.
    pub fn get_program(&self) -> &Program<N> {
        &self.program
    }

    /// JS `getExecution()` — the proof-bearing execution, if one was produced.
    ///
    /// `None` for a pure off-chain execution that has not been proved yet.
    pub fn get_execution(&self) -> Option<&Execution<N>> {
        self.execution.as_ref()
    }

    /// JS `getFunctionId()` — the function name as a string.
    pub fn get_function_id(&self) -> String {
        self.function_id.to_string()
    }

    /// JS `getVerifyingKey()` — the function's verifying key.
    ///
    /// Unlike the proving key this is **not** consumed: the wasm getter
    /// clones on every call.
    pub fn get_verifying_key(&self) -> &VerifyingKey<N> {
        &self.verifying_key
    }

    /// JS `getProvingKey()` — **take** the cached proving key, if any.
    ///
    /// The wasm method is `Option::take()` under a getter-shaped name: the
    /// first call returns the key and every later call returns `null`. This
    /// method keeps that contract but makes the mutation explicit in both the
    /// name and the `&mut self` receiver. It shares the slot with
    /// [`Self::take_keys`], so calling either one drains it for both.
    pub fn take_proving_key(&mut self) -> Option<ProvingKey<N>> {
        self.proving_key.take()
    }

    /// JS `getKeys()` — **take** the proving key and pair it with a clone of
    /// the verifying key.
    ///
    /// # Errors
    ///
    /// Errors with exactly `"No proving key found"` when no proving key is
    /// cached (including after a prior [`Self::take_proving_key`] or
    /// [`Self::take_keys`] call). The wasm binding returns this string rather
    /// than a nullable pair — an absent key is an error here, whereas an
    /// absent `getProvingKey()` result is a normal value.
    pub fn take_keys(&mut self) -> Result<ExecutionKeys<N>> {
        let proving_key = self.proving_key.take().context("No proving key found")?;
        Ok(ExecutionKeys::new(proving_key, self.verifying_key.clone()))
    }
}

/// Hand-written for the same reason as [`ExecutionKeys`]: the bundled keys
/// cannot be printed by the derive, and only the shape of the bundle matters
/// when it shows up in a test failure.
impl<N: Network> fmt::Debug for ExecutionResponse<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutionResponse")
            .field("function_id", &self.function_id)
            .field("program_id", &self.program.id())
            .field("num_outputs", &self.response.outputs().len())
            .field("has_execution", &self.execution.is_some())
            .field("has_proving_key", &self.proving_key.is_some())
            .finish_non_exhaustive()
    }
}

/// Deref to the native [`Response`], matching the wasm `Deref` implementation.
/// Native response methods (`outputs()`, `output_ids()`, …) stay available on
/// the bundle without a getter.
impl<N: Network> Deref for ExecutionResponse<N> {
    type Target = Response<N>;

    fn deref(&self) -> &Self::Target {
        &self.response
    }
}

/// Build a `Response` from a list of output literals.
///
/// snarkVM only exposes `From<(Vec<OutputID<N>>, Vec<Value<N>>)>` (used to
/// eject from a circuit); every other constructor recomputes output IDs from
/// transition data. Since the JS getters only read `Response::outputs()`, an
/// empty `output_ids` vector is enough for offline construction.
#[cfg(test)]
fn response_with_outputs<N: Network>(literals: &[&str]) -> Result<Response<N>> {
    use snarkvm::console::program::{OutputID, Value};

    let outputs = literals
        .iter()
        .map(|s| Value::<N>::from_str(s).map_err(|e| anyhow::anyhow!("bad literal {s}: {e}")))
        .collect::<Result<Vec<_>>>()?;
    Ok(Response::<N>::from((Vec::<OutputID<N>>::new(), outputs)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::TestnetV0;

    const HELLO: &str = "program hello.aleo;\n\
        function hello:\n\
            input r0 as u32.public;\n\
            input r1 as u32.private;\n\
            add r0 r1 into r2;\n\
            output r2 as u32.private;\n";

    // `FeePublic` matches the parameter already exercised by `keys.rs`'s
    // checksum test, so CI needs no *new* download. The prover is ~29 MB and
    // deserializing it is expensive, so load it at most once for the whole
    // test binary and clone the `Arc`-backed handle. Tests that only need a
    // verifying key never touch it.
    static PROVING_KEY: std::sync::LazyLock<ProvingKey<TestnetV0>> =
        std::sync::LazyLock::new(|| {
            use snarkvm::parameters::testnet as params;
            use snarkvm::prelude::FromBytes as _;

            let bytes = params::FeePublicProver::load_bytes().expect("fee_public prover bytes");
            ProvingKey::from_bytes_le(&bytes).expect("valid fee_public proving key")
        });

    fn offline_verifying_key() -> VerifyingKey<TestnetV0> {
        use snarkvm::parameters::testnet as params;
        use snarkvm::prelude::FromBytes as _;

        let bytes = params::FeePublicVerifier::load_bytes().expect("fee_public verifier bytes");
        VerifyingKey::from_bytes_le(&bytes).expect("valid fee_public verifying key")
    }

    fn bundle(literals: &[&str], with_proving_key: bool) -> ExecutionResponse<TestnetV0> {
        let program = Program::<TestnetV0>::from_str(HELLO).unwrap();
        ExecutionResponse::from_parts(
            None,
            "hello",
            response_with_outputs::<TestnetV0>(literals).unwrap(),
            program,
            with_proving_key.then(|| PROVING_KEY.clone()),
            offline_verifying_key(),
        )
        .unwrap()
    }

    /// Upstream `program-manager.test.ts`: `hello(5u32, 5u32)` yields
    /// `getOutputs()[0] === "10u32"`. Reproduce the exact literal, and check
    /// that a second output keeps its own suffix and position.
    #[test]
    fn get_outputs_returns_display_strings_in_order() {
        let r = bundle(&["10u32", "true"], false);
        assert_eq!(
            r.get_outputs(),
            vec!["10u32".to_string(), "true".to_string()]
        );
    }

    #[test]
    fn get_outputs_is_empty_for_no_outputs() {
        let r = bundle(&[], false);
        assert!(r.get_outputs().is_empty());
    }

    #[test]
    fn get_program_returns_the_executed_program() {
        let r = bundle(&["10u32"], false);
        assert_eq!(r.get_program().id().to_string(), "hello.aleo");
    }

    #[test]
    fn get_execution_reflects_presence_or_absence() {
        let mut r = bundle(&["10u32"], false);
        assert!(r.get_execution().is_none());

        // A proved execution is Some; an empty Execution is enough to test the
        // branch without synthesizing a circuit.
        r.execution = Some(Execution::<TestnetV0>::new());
        assert!(r.get_execution().is_some());
    }

    #[test]
    fn get_function_id_is_the_name_string() {
        let r = bundle(&["10u32"], false);
        assert_eq!(r.get_function_id(), "hello");
    }

    #[test]
    fn get_verifying_key_is_not_consumed() {
        let r = bundle(&["10u32"], false);
        let vk = offline_verifying_key();
        // snarkVM's `VerifyingKey` has no `Debug` impl, so compare explicitly.
        assert!(r.get_verifying_key() == &vk);
        assert!(r.get_verifying_key() == &vk);
    }

    /// The core trap: the wasm "getter" is `Option::take()`.
    #[test]
    fn take_proving_key_consumes_the_slot() {
        let mut r = bundle(&["10u32"], true);
        assert!(r.has_proving_key());
        assert!(r.take_proving_key().is_some());
        assert!(!r.has_proving_key());
        assert!(r.take_proving_key().is_none());
    }

    #[test]
    fn take_proving_key_is_none_when_never_cached() {
        let mut r = bundle(&["10u32"], false);
        assert!(!r.has_proving_key());
        assert!(r.take_proving_key().is_none());
    }

    #[test]
    fn take_keys_returns_both_halves_and_consumes() {
        let mut r = bundle(&["10u32"], true);
        let vk = offline_verifying_key();
        let keys = r.take_keys().unwrap();
        assert!(keys.verifying_key() == &vk);
        let (pk, vk2) = keys.into_parts();
        assert!(vk2 == vk);
        assert!(!r.has_proving_key());
        // Re-cache deliberately, to prove the getter shape still works.
        r.set_proving_key(pk);
        assert!(r.has_proving_key());
    }

    #[test]
    fn take_keys_errors_with_the_upstream_message_when_empty() {
        let mut r = bundle(&["10u32"], false);
        let err = r.take_keys().expect_err("take_keys must fail without a cached key");
        assert_eq!(err.to_string(), "No proving key found");
    }

    /// The two "getters" share one slot — draining it through either path
    /// disables the other. Easy to miss when reading only the docs page.
    #[test]
    fn take_keys_and_take_proving_key_compete_for_one_slot() {
        let mut a = bundle(&["10u32"], true);
        assert!(a.take_keys().is_ok());
        assert!(a.take_proving_key().is_none());
        let err = a.take_keys().expect_err("slot was drained by take_keys");
        assert_eq!(err.to_string(), "No proving key found");

        let mut b = bundle(&["10u32"], true);
        assert!(b.take_proving_key().is_some());
        let err = b.take_keys().expect_err("slot was drained by take_proving_key");
        assert_eq!(err.to_string(), "No proving key found");
    }

    /// Deref exposes the native Response methods, as in the wasm class.
    #[test]
    fn deref_exposes_native_response() {
        let r = bundle(&["10u32", "7u8"], false);
        assert_eq!(r.outputs().len(), 2);
        assert_eq!(r.outputs()[1].to_string(), "7u8");
        assert!(r.output_ids().is_empty());
    }

    #[test]
    fn from_parts_rejects_an_invalid_function_name() {
        let vk = offline_verifying_key();
        let err = ExecutionResponse::from_parts(
            None,
            "1not_an_identifier",
            response_with_outputs::<TestnetV0>(&["10u32"]).unwrap(),
            Program::<TestnetV0>::from_str(HELLO).unwrap(),
            None,
            vk,
        )
        .expect_err("an invalid identifier must be rejected");
        assert!(err.to_string().contains("Invalid function name"));
    }

    /// `new` mirrors wasm construction. With an unloaded program the process
    /// cannot resolve a verifying key, which is the documented failure path.
    #[test]
    fn new_reports_missing_verifying_key() {
        let process = Process::<TestnetV0>::load().unwrap();
        let err = ExecutionResponse::<TestnetV0>::new(
            None,
            "hello",
            response_with_outputs::<TestnetV0>(&["10u32"]).unwrap(),
            &process,
            HELLO,
        )
        .expect_err("an unloaded program has no verifying key");
        assert!(
            err.to_string().contains("Could not find verifying key for hello.aleo/hello"),
            "unexpected error: {err}"
        );
    }

    /// The hand-written `Debug` impls must not serialize the (huge) key bytes,
    /// which is why they cannot be derived.
    #[test]
    fn debug_impls_are_redacted_and_describe_the_bundle() {
        let r = bundle(&["10u32", "7u8"], true);
        let text = format!("{r:?}");
        assert!(text.contains("ExecutionResponse"));
        assert!(text.contains("hello.aleo"));
        assert!(text.contains("num_outputs: 2"));
        assert!(text.contains("has_proving_key: true"));
        // Only scalar shape fields are present; no nested key object is printed.
        assert!(!text.contains("ProvingKey"));
        assert!(!text.contains("VerifyingKey"));

        let keys = ExecutionKeys::new(PROVING_KEY.clone(), offline_verifying_key());
        let text = format!("{keys:?}");
        assert!(text.contains("ExecutionKeys"));
        assert!(!text.contains("ProvingKey"));
        assert!(!text.contains("VerifyingKey"));
    }

    /// `ExecutionKeys::new` is the standalone pair wrapper used by `take_keys`.
    #[test]
    fn execution_keys_new_exposes_both_halves() {
        use snarkvm::prelude::ToBytes as _;

        let vk = offline_verifying_key();
        let expected = PROVING_KEY.clone();
        let keys = ExecutionKeys::new(expected.clone(), vk.clone());
        assert!(keys.verifying_key() == &vk);
        assert!(keys.proving_key().to_bytes_le().unwrap() == expected.to_bytes_le().unwrap());
    }

    /// Build a `Process` holding one small custom program with a proving key
    /// inserted directly into the stack.
    ///
    /// Do **not** ask `Process` for a `credits.aleo` proving key here: snarkVM's
    /// `get_proving_key` calls `try_insert_credits_function_proving_key`, which
    /// downloads the entire credits parameter set (hundreds of MB) the first
    /// time. Injecting via `insert_proving_key` skips that path and keeps the
    /// test fully offline and sub-second.
    fn process_with_injected_key() -> (Process<TestnetV0>, ProgramID<TestnetV0>) {
        let process = Process::<TestnetV0>::load().unwrap();
        let program = Program::<TestnetV0>::from_str(HELLO).unwrap();
        let program_id = *program.id();
        process.lock().add_program(&program).unwrap();
        process
            .insert_proving_key(
                &program_id,
                &Identifier::<TestnetV0>::from_str("hello").unwrap(),
                PROVING_KEY.clone(),
            )
            .unwrap();
        (process, program_id)
    }

    /// `add_proving_key` is the wasm post-construction step: it pulls the key
    /// out of `Process` and makes `takeKeys()` work.
    #[test]
    fn add_proving_key_loads_from_process_and_enables_take_keys() {
        use snarkvm::prelude::ToBytes as _;

        let (process, program_id) = process_with_injected_key();
        let mut r = bundle(&[], false);
        assert!(!r.has_proving_key());

        r.add_proving_key(&process, "hello", &program_id).unwrap();
        assert!(r.has_proving_key());
        let keys = r.take_keys().unwrap();
        assert!(keys.proving_key().to_bytes_le().unwrap() == PROVING_KEY.to_bytes_le().unwrap());
        assert!(!r.has_proving_key());
    }

    #[test]
    fn add_proving_key_reports_missing_key() {
        let (process, program_id) = process_with_injected_key();
        let mut r = bundle(&[], false);
        let err = r
            .add_proving_key(&process, "no_such_function", &program_id)
            .expect_err("an unknown function has no proving key");
        assert!(
            err.to_string()
                .contains("Could not find proving key for hello.aleo/no_such_function"),
            "unexpected error: {err}"
        );
    }

    /// `Process::load()` ships the verifying keys for `credits.aleo`, so this
    /// needs no circuit synthesis. The wasm constructor takes *source text*,
    /// not a loaded `Program`, so a minimal source with the right program ID
    /// is enough: key lookup is keyed by `(program.id(), function_id)`.
    #[test]
    fn new_resolves_verifying_key_for_a_loaded_program() {
        const CREDITS_STUB: &str = "program credits.aleo;\n\
            function transfer_public:\n\
                input r0 as address.public;\n\
                input r1 as u64.public;\n";

        let process = Process::<TestnetV0>::load().unwrap();
        let r = ExecutionResponse::<TestnetV0>::new(
            None,
            "transfer_public",
            response_with_outputs::<TestnetV0>(&[]).unwrap(),
            &process,
            CREDITS_STUB,
        )
        .unwrap();
        assert_eq!(r.get_function_id(), "transfer_public");
        assert_eq!(r.get_program().id().to_string(), "credits.aleo");
        let expected = process
            .get_verifying_key(
                ProgramID::<TestnetV0>::from_str("credits.aleo").unwrap(),
                "transfer_public",
            )
            .unwrap();
        assert!(r.get_verifying_key() == &expected);
    }
}
