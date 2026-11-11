//! Aleo `ComputeKey` — parity with the JS SDK's wasm `ComputeKey` class.
//!
//! Like [`crate::view_key`], this is a thin account-page parity: snarkVM's
//! [`ComputeKey<N>`] **already implements every method** on the JS page
//! natively. [`ComputeKey<N>`] is `Copy` and bundles the three public
//! components of an account's key chain — `pk_sig` (signature public key),
//! `pr_sig` (signature randomizer), and `sk_prf` (PRF secret key) — and
//! derives the address from them. The wasm binding wraps it as
//! `ComputeKey(ComputeKeyNative)` and adds a `Drop` that zeroizes the raw
//! bytes (the native type does not derive `Zeroize`); since we expose the
//! native `Copy` type directly, no wrapper is needed here.
//!
//! ## JS `ComputeKey` → Rust mapping
//!
//! | # | JS `ComputeKey` | Rust equivalent | Where |
//! |---|---|---|---|
//! | 1 | `ComputeKey.fromPrivateKey(pk)` | [`from_private_key`] / `ComputeKey::try_from(&pk)` | snarkVM (`TryFrom`) |
//! | 2 | `computeKey.toAddress()` | [`to_address`] / `ck.to_address()` | snarkVM (method) |
//! | 3 | `computeKey.skPrf()` | [`sk_prf`] / `ck.sk_prf()` | snarkVM (`const fn`) |
//! | 4 | `computeKey.pkSig()` | [`pk_sig`] / `ck.pk_sig()` | snarkVM (`const fn`) |
//! | 5 | `computeKey.prSig()` | [`pr_sig`] / `ck.pr_sig()` | snarkVM (`const fn`) |
//!
//! ## Address derivation
//!
//! The address is `pk_sig + pr_sig + G^sk_prf`. [`to_address`] returns it
//! directly; equivalently `Address::try_from(&ck)` yields the same value, and
//! both equal the address derived from the private key. The three components
//! are what lets a holder *sign* (via the private key) without exposing the
//! spending key — the compute key is the public half of the signing material.
//!
//! ## Usage
//!
//! ```
//! use aleo_rust_sdk::compute_key;
//! use snarkvm::prelude::{Address, FromStr, PrivateKey, TestnetV0};
//!
//! let pk = PrivateKey::<TestnetV0>::from_str(
//!     "APrivateKey1zkp4RyQ8Utj7aRcJgPQGEok8RMzWwUZzBhhgX6rhmBT8dcP",
//! )
//! .unwrap();
//!
//! // JS: ComputeKey.fromPrivateKey(pk)
//! let ck = compute_key::from_private_key(&pk).unwrap();
//!
//! // JS: computeKey.toAddress() — same address as the private key.
//! assert_eq!(compute_key::to_address(&ck), Address::try_from(&pk).unwrap());
//!
//! // JS: computeKey.skPrf() / pkSig() / prSig() — the public components.
//! let _prf = compute_key::sk_prf(&ck);
//! let _sig = compute_key::pk_sig(&ck);
//! let _rnd = compute_key::pr_sig(&ck);
//! ```
//!
//! [`ComputeKey<N>`]: snarkvm::prelude::ComputeKey

use anyhow::Result;
use snarkvm::prelude::{Address, ComputeKey, Group, Network, PrivateKey, Scalar};

/// Derives the compute key from a private key — JS `ComputeKey.fromPrivateKey(pk)`.
///
/// The compute key carries the public signing material (`pk_sig`, `pr_sig`) and
/// the PRF secret key (`sk_prf`). Deriving it never fails for a valid private
/// key; the only error path is a malformed key.
///
/// # Arguments
/// * `private_key` - The private key to derive from.
pub fn from_private_key<N: Network>(private_key: &PrivateKey<N>) -> Result<ComputeKey<N>> {
    ComputeKey::try_from(private_key)
}

/// Returns the address this compute key maps to — JS `computeKey.toAddress()`.
///
/// Equivalent to `Address::try_from(&ck)` and to the address derived from the
/// source private key.
///
/// # Arguments
/// * `compute_key` - The compute key.
pub fn to_address<N: Network>(compute_key: &ComputeKey<N>) -> Address<N> {
    compute_key.to_address()
}

/// Returns the PRF secret key — JS `computeKey.skPrf()`.
///
/// `sk_prf` is a scalar; it seeds the account's pseudorandom functions (e.g.
/// record nonces) without revealing the spending key.
///
/// # Arguments
/// * `compute_key` - The compute key.
pub fn sk_prf<N: Network>(compute_key: &ComputeKey<N>) -> Scalar<N> {
    compute_key.sk_prf()
}

/// Returns the signature public key — JS `computeKey.pkSig()`.
///
/// `pk_sig` is the group element `G^sk_sig`; it is one of the three components
/// summed to derive the address.
///
/// # Arguments
/// * `compute_key` - The compute key.
pub fn pk_sig<N: Network>(compute_key: &ComputeKey<N>) -> Group<N> {
    compute_key.pk_sig()
}

/// Returns the signature randomizer — JS `computeKey.prSig()`.
///
/// `pr_sig` is the group element `G^r_sig`; together with `pk_sig` and
/// `G^sk_prf` it sums to the account address.
///
/// # Arguments
/// * `compute_key` - The compute key.
pub fn pr_sig<N: Network>(compute_key: &ComputeKey<N>) -> Group<N> {
    compute_key.pr_sig()
}

#[cfg(test)]
mod tests {
    use super::*;

    use snarkvm::prelude::{FromStr, PrivateKey, TestnetV0, Zero};

    type CurrentNetwork = TestnetV0;

    /// Upstream wasm test vector (`wasm/src/account/compute_key.rs`) plus the
    /// canonical key used across the account parity pages for determinism.
    const PRIVATE_KEY: &str = "APrivateKey1zkp4RyQ8Utj7aRcJgPQGEok8RMzWwUZzBhhgX6rhmBT8dcP";

    fn pk(s: &str) -> PrivateKey<CurrentNetwork> {
        PrivateKey::from_str(s).expect("literal private key parses")
    }

    // ── from_private_key / to_address ──────────────────────────────────

    #[test]
    fn from_private_key_address_matches_private_key() {
        let compute_key = from_private_key(&pk(PRIVATE_KEY)).unwrap();

        // `toAddress()` must equal the address derived from the private key.
        let address = Address::try_from(&pk(PRIVATE_KEY)).unwrap();
        assert_eq!(to_address(&compute_key), address);

        // And it must equal the address derived directly from the compute key.
        assert_eq!(Address::try_from(&compute_key).unwrap(), address);
    }

    // ── the three public components ────────────────────────────────────

    #[test]
    fn components_are_retrievable_and_non_trivial() {
        let compute_key = from_private_key(&pk(PRIVATE_KEY)).unwrap();

        let prf = sk_prf(&compute_key);
        let sig = pk_sig(&compute_key);
        let rnd = pr_sig(&compute_key);

        // All three components are derived material, not the identity/zero
        // element — guarding against a silently-defaulted compute key.
        assert_ne!(prf, Scalar::zero());
        assert_ne!(sig, Group::zero());
        assert_ne!(rnd, Group::zero());

        // `pk_sig` and `pr_sig` are distinct group elements.
        assert_ne!(sig, rnd);
    }

    #[test]
    fn address_recombination_is_consistent() {
        // The address is `pk_sig + pr_sig + G^sk_prf`. `to_address` performs
        // that sum internally; assert it equals the address obtained through
        // the dedicated `TryFrom<&ComputeKey>` path (the upstream test's
        // `Address::from_compute_key` equivalent in snarkVM).
        let compute_key = from_private_key(&pk(PRIVATE_KEY)).unwrap();
        assert_eq!(
            to_address(&compute_key),
            Address::try_from(&compute_key).unwrap()
        );
    }
}
