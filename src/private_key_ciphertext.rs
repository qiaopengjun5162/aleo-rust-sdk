//! # PrivateKeyCiphertext — parity with the JS SDK's wasm `PrivateKeyCiphertext`.
//!
//! Represents an **encrypted private key**: a symmetric ciphertext that can be
//! stored safely and reopened with the passphrase used at encryption time.
//!
//! ## JS `PrivateKeyCiphertext` → Rust mapping
//!
//! | # | JS | Rust equivalent | Where |
//! |---|---|---|---|
//! | 1 | `encryptPrivateKey(privateKey, secret)` | [`PrivateKeyCiphertext::encrypt_with_rng`] | **this module** (delegates to [`crate::private_key`]) |
//! | 2 | `ct.decryptToPrivateKey(secret)` | [`PrivateKeyCiphertext::decrypt_to_private_key`] | **this module** |
//! | 3 | `ct.toString()` | [`PrivateKeyCiphertext::to_string`] | snarkVM `Display` on the inner [`Ciphertext`] |
//! | 4 | `PrivateKeyCiphertext.fromString(s)` | [`PrivateKeyCiphertext::from_string`] | snarkVM `FromStr` |
//!
//! ## Why this is a new type, not a thin wrapper
//!
//! The JS class is `PrivateKeyCiphertext(CiphertextNative)` — a wasm-owned
//! newtype over a generic ciphertext, giving the *semantic* guarantee "this
//! ciphertext holds a private-key seed". snarkVM has no such type, so this
//! module defines a generic container rather than exposing raw `Ciphertext<N>`.
//! It derefs to the inner ciphertext so all native inspection stays available.
//!
//! ## 🔴 The two encrypted-key formats are wire-incompatible
//!
//! The JS SDK's `ciphertext1…` bech32m form (Poseidon `hash_psd2` blinding +
//! `encrypt_symmetric`) is **not** the format of
//! [`crate::account::AleoAccount::to_ciphertext`] (`aleo-enc-v1:` AES-GCM).
//! This module implements the upstream scheme via [`crate::private_key`], so
//! Rust and JS ciphertexts interoperate. See that module's docs for the
//! derivation (`hash_psd2([domain, nonce, secret]) * seed`).
//!
//! ## Randomness
//!
//! The JS binding draws the blinding nonce from its own OS RNG. Rust keeps the
//! RNG **injected**: [`PrivateKeyCiphertext::encrypt_with_rng`] takes any
//! `R: Rng + CryptoRng`, which makes the output deterministic under a seeded
//! test RNG and lets production callers supply a cryptographically secure RNG.
//! (snarkVM 4.12 uses rand 0.10's `CryptoRng`, so a rand 0.8 `OsRng` cannot be
//! passed here.) Encrypting the same key twice yields different ciphertexts;
//! both decrypt.
//!
//! ## Example
//!
//! ```
//! use aleo_rust_sdk::private_key_ciphertext::PrivateKeyCiphertext;
//! use snarkvm::prelude::{PrivateKey, TestRng, TestnetV0};
//!
//! let rng = &mut TestRng::fixed(7);
//! let pk = PrivateKey::<TestnetV0>::new(rng).unwrap();
//! let ct = PrivateKeyCiphertext::encrypt_with_rng(&pk, "correct horse battery staple", rng).unwrap();
//! assert_eq!(ct.decrypt_to_private_key("correct horse battery staple").unwrap(), pk);
//! assert!(ct.decrypt_to_private_key("wrong secret").is_err());
//! ```

use anyhow::Result;
use snarkvm::prelude::{Ciphertext, CryptoRng, Network, PrivateKey, Rng};
use std::{fmt, ops::Deref, str::FromStr};

/// An encrypted private key, in the JS SDK's `ciphertext1…` wire format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateKeyCiphertext<N: Network>(Ciphertext<N>);

impl<N: Network> Deref for PrivateKeyCiphertext<N> {
    type Target = Ciphertext<N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<N: Network> From<Ciphertext<N>> for PrivateKeyCiphertext<N> {
    fn from(ciphertext: Ciphertext<N>) -> Self {
        Self(ciphertext)
    }
}

impl<N: Network> From<PrivateKeyCiphertext<N>> for Ciphertext<N> {
    fn from(ciphertext: PrivateKeyCiphertext<N>) -> Self {
        ciphertext.0
    }
}

impl<N: Network> FromStr for PrivateKeyCiphertext<N> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(Self(Ciphertext::<N>::from_str(s)?))
    }
}

impl<N: Network> fmt::Display for PrivateKeyCiphertext<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<N: Network> PrivateKeyCiphertext<N> {
    /// Parses a `ciphertext1…` string — JS `PrivateKeyCiphertext.fromString`.
    pub fn from_string(s: &str) -> Result<Self> {
        Self::from_str(s)
    }

    /// Renders as the canonical bech32m string — JS `ct.toString()`.
    #[allow(clippy::inherent_to_string, clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }

    /// Encrypts a private key with a passphrase — JS
    /// `PrivateKeyCiphertext.encryptPrivateKey(pk, secret)`.
    ///
    /// The RNG is injected on purpose: a seeded test RNG makes the ciphertext
    /// reproducible, while production callers supply a secure RNG. Note that
    /// snarkVM 4.12 uses rand 0.10's `CryptoRng`, so a rand 0.8 `OsRng` is not
    /// accepted.
    pub fn encrypt_with_rng<R: Rng + CryptoRng>(
        private_key: &PrivateKey<N>,
        secret: &str,
        rng: &mut R,
    ) -> Result<Self> {
        Ok(Self(crate::private_key::encrypt_private_key(
            private_key, secret, rng,
        )?))
    }

    /// Decrypts back into the private key — JS `ct.decryptToPrivateKey(secret)`.
    ///
    /// A wrong secret fails: symmetric decryption rejects the tag, or the
    /// recovered seed is not a valid private key.
    pub fn decrypt_to_private_key(&self, secret: &str) -> Result<PrivateKey<N>> {
        crate::private_key::decrypt_private_key(&self.0, secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::{TestRng, TestnetV0};

    type N = TestnetV0;

    /// Produced by the JS SDK wasm binding with secret `"mypassword"`.
    const CIPHERTEXT: &str = "ciphertext1qvqg7rgvam3xdcu55pwu6sl8rxwefxaj5gwthk0yzln6jv5fastzup0qn0qftqlqq7jcckyx03fzv9kke0z9puwd7cl7jzyhxfy2f2juplz39dkqs6p24urhxymhv364qm3z8mvyklv5gr52n4fxr2z59jgqytyddj8";
    /// The private key the upstream ciphertext decrypts to.
    const PRIVATE_KEY: &str = "APrivateKey1zkpAYS46Dq4rnt9wdohyWMwdmjmTeMJKPZdp5AhvjXZDsVG";
    /// Same as `CIPHERTEXT` with one character changed (invalid checksum).
    const BAD_CIPHERTEXT: &str = "ciphertext1qvqg7rgvam3xdcu55pwu6sl8rxwefxaj5gwthk0yzln6jv5fastzup0qn0qftqlqq7jcckyx03fzv9kke0z9puwd7cl7jzyhxfy2f2juplz39dkqs6p24urhxymhv364qm3z8mvyklv5er52n4fxr2z59jgqytyddj8";

    fn ct() -> PrivateKeyCiphertext<N> {
        PrivateKeyCiphertext::<N>::from_string(CIPHERTEXT).unwrap()
    }

    #[test]
    fn decrypts_upstream_js_ciphertext_literal() {
        // Proves interop with the JS SDK, not just a local round-trip.
        assert_eq!(ct().decrypt_to_private_key("mypassword").unwrap().to_string(), PRIVATE_KEY);
        assert!(ct().decrypt_to_private_key("badpassword").is_err());
    }

    #[test]
    fn string_round_trip_is_canonical() {
        assert_eq!(ct().to_string(), CIPHERTEXT);
        assert_eq!(PrivateKeyCiphertext::<N>::from_string(&ct().to_string()).unwrap(), ct());
    }

    #[test]
    fn rejects_malformed_ciphertext() {
        assert!(PrivateKeyCiphertext::<N>::from_string(BAD_CIPHERTEXT).is_err());
        assert!(PrivateKeyCiphertext::<N>::from_string("not-a-ciphertext").is_err());
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let rng = &mut TestRng::fixed(7);
        let pk = PrivateKey::<N>::new(rng).unwrap();
        let ciphertext = PrivateKeyCiphertext::encrypt_with_rng(&pk, "mypassword", rng).unwrap();
        assert_eq!(ciphertext.decrypt_to_private_key("mypassword").unwrap(), pk);
        assert!(ciphertext.decrypt_to_private_key("wrong").is_err());
    }

    #[test]
    fn nonce_is_random_both_ciphertexts_decrypt() {
        let rng = &mut TestRng::fixed(11);
        let pk = PrivateKey::<N>::new(rng).unwrap();
        let a = PrivateKeyCiphertext::encrypt_with_rng(&pk, "secret", rng).unwrap();
        let b = PrivateKeyCiphertext::encrypt_with_rng(&pk, "secret", rng).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.decrypt_to_private_key("secret").unwrap(), b.decrypt_to_private_key("secret").unwrap());
    }

    #[test]
    fn deref_exposes_native_ciphertext() {
        // `Deref` keeps every native inspection method reachable.
        assert!(!ct().is_empty());
    }
}
