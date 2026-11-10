//! Aleo `KeyPair` — parity with the JS SDK's wasm `KeyPair` class.
//!
//! This page is the **standalone** `KeyPair` class: a two-slot bag holding a
//! function's proving and verifying keys. snarkVM has no equivalent type —
//! the keys live separately — so, as with [`crate::execution_response`], this
//! module adds the container. Note that
//! [`ExecutionKeys`](crate::execution_response::ExecutionKeys) (the pair
//! returned by `ExecutionResponse::take_keys`) is a *different* type with a
//! non-consuming contract; the wasm class here is all about **take-and-err**.
//!
//! ## JS `KeyPair` → Rust mapping
//!
//! | # | JS `KeyPair` | Rust equivalent | Contract |
//! |---|--------------|-----------------|----------|
//! | 1 | `new KeyPair(pk, vk)` | [`KeyPair::new`] / `From<(pk, vk)>` | infallible; fills both slots |
//! | 2 | `kp.provingKey()` | [`KeyPair::take_proving_key`] | **consumes** the slot, then errors |
//! | 3 | `kp.verifyingKey()` | [`KeyPair::take_verifying_key`] | **consumes** the slot, then errors |
//!
//! Plus [`KeyPair::has_proving_key`] / [`KeyPair::has_verifying_key`]:
//! read-only probes the wasm class lacks (the same addition as
//! [`crate::execution_response::ExecutionResponse::has_proving_key`]).
//!
//! ## The two traps
//!
//! 1. **The getters are not getters.** Both `provingKey()` and
//!    `verifyingKey()` are `Option::take()` under getter-shaped names. The
//!    docs say *"This method will remove the proving key from the key pair"*
//!    but do not say what a second call does — it **errors**, and the return
//!    type shown (`ProvingKey`) is a lie in that case. The two methods also
//!    compete for independent slots: taking one leaves the other intact. In
//!    Rust the consumption is visible in both the `take_*` names and the
//!    `&mut self` receivers.
//! 2. 🔴 **The verifying-key error message is an upstream copy-paste bug.**
//!    When the *verifying* key slot is empty, the wasm class errors with
//!    `"Proving key has already been removed"` — literally the proving-key
//!    string. We return the accurate `"Verifying key has already been
//!    removed"` instead, and pin both messages in the tests so the
//!    divergence is deliberate and visible.
//!
//! ## Usage
//!
//! ```
//! use aleo_rust_sdk::keypair::KeyPair;
//! use snarkvm::parameters::testnet as params;
//! use snarkvm::prelude::{FromBytes as _, TestnetV0};
//! use snarkvm::synthesizer::snark::{ProvingKey, VerifyingKey};
//!
//! let pk_bytes = params::FeePublicProver::load_bytes().unwrap();
//! let vk_bytes = params::FeePublicVerifier::load_bytes().unwrap();
//! let pk = ProvingKey::<TestnetV0>::from_bytes_le(&pk_bytes).unwrap();
//! let vk = VerifyingKey::<TestnetV0>::from_bytes_le(&vk_bytes).unwrap();
//!
//! let mut keys = KeyPair::new(pk, vk);
//! assert!(keys.has_proving_key() && keys.has_verifying_key());
//!
//! // JS: keys.provingKey() — takes the key out of the pair.
//! let pk = keys.take_proving_key().unwrap();
//! assert!(!keys.has_proving_key() && keys.has_verifying_key());
//! // The second call errors, exactly like the JS class.
//! assert!(keys.take_proving_key().is_err());
//! ```

use anyhow::Result;
use snarkvm::console::network::Network;
use snarkvm::synthesizer::snark::{ProvingKey, VerifyingKey};
use std::fmt;

/// The standalone wasm `KeyPair`: a proving key and a verifying key, each in
/// a take-once slot.
///
/// Not to be confused with
/// [`ExecutionKeys`](crate::execution_response::ExecutionKeys) — that one is
/// the non-consuming pair `ExecutionResponse::take_keys` hands out.
#[derive(Clone)]
pub struct KeyPair<N: Network> {
    proving_key: Option<ProvingKey<N>>,
    verifying_key: Option<VerifyingKey<N>>,
}

impl<N: Network> KeyPair<N> {
    /// Creates a key pair with both slots filled — the JS constructor.
    ///
    /// # Arguments
    /// * `proving_key` - The proving key of a program function.
    /// * `verifying_key` - The verifying key of the same function.
    pub fn new(proving_key: ProvingKey<N>, verifying_key: VerifyingKey<N>) -> Self {
        Self {
            proving_key: Some(proving_key),
            verifying_key: Some(verifying_key),
        }
    }

    /// Whether the proving key is still in the pair, **without consuming it**.
    ///
    /// The wasm class has no such probe — its only way to ask is
    /// `provingKey()`, which destroys the answer.
    pub fn has_proving_key(&self) -> bool {
        self.proving_key.is_some()
    }

    /// Whether the verifying key is still in the pair, **without consuming it**.
    pub fn has_verifying_key(&self) -> bool {
        self.verifying_key.is_some()
    }

    /// JS `provingKey()` — **take** the proving key out of the pair.
    ///
    /// # Errors
    ///
    /// Errors with `"Proving key has already been removed"` when the slot is
    /// empty (including after a prior [`Self::take_proving_key`] call).
    pub fn take_proving_key(&mut self) -> Result<ProvingKey<N>> {
        self.proving_key
            .take()
            .ok_or_else(|| anyhow::anyhow!("Proving key has already been removed"))
    }

    /// JS `verifyingKey()` — **take** the verifying key out of the pair.
    ///
    /// # Errors
    ///
    /// Errors with `"Verifying key has already been removed"` when the slot
    /// is empty. 🔴 Upstream returns the *proving*-key message here
    /// (`"Proving key has already been removed"` — a copy-paste bug); this
    /// crate reports the right slot instead.
    pub fn take_verifying_key(&mut self) -> Result<VerifyingKey<N>> {
        self.verifying_key
            .take()
            .ok_or_else(|| anyhow::anyhow!("Verifying key has already been removed"))
    }
}

impl<N: Network> From<(ProvingKey<N>, VerifyingKey<N>)> for KeyPair<N> {
    fn from((proving_key, verifying_key): (ProvingKey<N>, VerifyingKey<N>)) -> Self {
        Self::new(proving_key, verifying_key)
    }
}

/// Hand-written for the same reason as
/// [`ExecutionKeys`](crate::execution_response::ExecutionKeys): the bundled
/// keys cannot be printed by the derive, and only the slot shape matters when
/// the pair shows up in a test failure.
impl<N: Network> fmt::Debug for KeyPair<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("has_proving_key", &self.proving_key.is_some())
            .field("has_verifying_key", &self.verifying_key.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::{FromBytes as _, TestnetV0};

    type CurrentNetwork = TestnetV0;

    static PROVING_KEY: std::sync::LazyLock<ProvingKey<CurrentNetwork>> =
        std::sync::LazyLock::new(|| {
            use snarkvm::parameters::testnet as params;

            let bytes = params::FeePublicProver::load_bytes().expect("fee_public prover bytes");
            ProvingKey::from_bytes_le(&bytes).expect("valid fee_public proving key")
        });

    fn verifying_key() -> VerifyingKey<CurrentNetwork> {
        use snarkvm::parameters::testnet as params;

        let bytes = params::FeePublicVerifier::load_bytes().expect("fee_public verifier bytes");
        VerifyingKey::from_bytes_le(&bytes).expect("valid fee_public verifying key")
    }

    fn sample() -> KeyPair<CurrentNetwork> {
        KeyPair::new(PROVING_KEY.clone(), verifying_key())
    }

    // ── take-and-err semantics ────────────────────────────────────────

    #[test]
    fn take_proving_key_consumes_and_errors_on_second_call() {
        let mut keys = sample();
        assert!(keys.has_proving_key());

        let pk = keys.take_proving_key().expect("first call wins");
        // ProvingKey has no PartialEq (see execution_response tests) —
        // compare the serialization instead.
        use snarkvm::prelude::ToBytes as _;
        assert_eq!(
            pk.to_bytes_le().unwrap(),
            PROVING_KEY.to_bytes_le().unwrap()
        );

        // The slot is gone: the second call errors with the upstream string.
        assert!(!keys.has_proving_key());
        let err = keys.take_proving_key().unwrap_err().to_string();
        assert_eq!(err, "Proving key has already been removed");
    }

    #[test]
    fn take_verifying_key_consumes_and_reports_the_right_slot() {
        let mut keys = sample();
        assert!(keys.has_verifying_key());

        let _vk = keys.take_verifying_key().expect("first call wins");
        assert!(!keys.has_verifying_key());

        // 🔴 Upstream copy-paste bug: the wasm class says "Proving key has
        // already been removed" here. We report the right slot instead.
        let err = keys.take_verifying_key().unwrap_err().to_string();
        assert_eq!(err, "Verifying key has already been removed");
    }

    #[test]
    fn the_two_slots_are_independent() {
        // Taking the proving key leaves the verifying key intact.
        let mut keys = sample();
        let _pk = keys.take_proving_key().unwrap();
        assert!(!keys.has_proving_key());
        assert!(keys.has_verifying_key());
        let _vk = keys.take_verifying_key().unwrap();

        // And the other way around.
        let mut keys = sample();
        let _vk = keys.take_verifying_key().unwrap();
        assert!(keys.has_proving_key());
        assert!(!keys.has_verifying_key());
        let _pk = keys.take_proving_key().unwrap();
    }

    // ── construction ──────────────────────────────────────────────────

    #[test]
    fn from_native_tuple_fills_both_slots() {
        let keys = KeyPair::from((PROVING_KEY.clone(), verifying_key()));
        assert!(keys.has_proving_key());
        assert!(keys.has_verifying_key());
    }

    #[test]
    fn debug_is_redacted_but_shaped() {
        let keys = sample();
        let rendered = format!("{keys:?}");
        assert!(rendered.contains("KeyPair"));
        assert!(rendered.contains("has_proving_key: true"));
        assert!(rendered.contains("has_verifying_key: true"));

        let mut keys = keys;
        let _pk = keys.take_proving_key().unwrap();
        assert!(format!("{keys:?}").contains("has_proving_key: false"));
    }
}
