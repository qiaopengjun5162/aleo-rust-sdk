//! # ProvingKey — parity with the JS SDK's wasm `ProvingKey`.
//!
//! A proving key for one function of one program. Unlike
//! `crate::execution_response`, this page is **not** a wasm-only bundle:
//! snarkVM already has `ProvingKey<N>`, and the upstream wasm class is a
//! one-field newtype over it. This module keeps that shape, generic over
//! `Network`, and adds the six JS methods.
//!
//! ## JS `ProvingKey` → Rust mapping
//!
//! | # | JS | Rust equivalent | Where |
//! |---|---|---|---|
//! | 1 | `checksum()` | [`ProvingKey::checksum`] | `SHA-256(to_bytes_le())` hex |
//! | 2 | `copy()` | [`ProvingKey::copy`] | derived `Clone` |
//! | 3 | `fromBytes(bytes)` | [`ProvingKey::from_bytes`] | native `FromBytes` |
//! | 4 | `fromString(string)` | [`ProvingKey::from_string`] | native `FromStr` |
//! | 5 | `toBytes()` | [`ProvingKey::to_bytes`] | native `ToBytes` |
//! | 6 | `toString()` | `key.to_string()` | `Display` (blanket `ToString`) |
//!
//! ## Reuse, not reimplementation
//!
//! `checksum` delegates to the crate's shared `SHA-256(key.to_bytes_le())`
//! helper in `keys` (the same formula already used to validate the embedded
//! credits parameters). The upstream wasm test downloads
//! `Metadata::transfer_public().prover` and pins its SHA-256 as
//! `846f86cabf…`; the test module checks that literal against the embedded
//! parameter metadata and then exercises the formula offline with the
//! `fee_public` prover, so no network download is needed.
//!
//! `toString` and `copy` are traits (`Display` / `Clone`) rather than inherent
//! methods, which avoids the clippy lints the upstream wasm source silences
//! with `#[allow(clippy::inherent_to_string)]`.
//!
//! ## Differences from the JS page
//!
//! * Every fallible method returns `anyhow::Result`, as elsewhere in this
//!   crate. The wasm class unwraps internally for `checksum()` and returns
//!   `Result<_, String>` for the others; serialization and parsing can fail,
//!   so the Rust API does not hide that.
//! * `checksum()` hashes the **canonical bytes** (`toBytes`), not the string
//!   form. Both forms are available, but `SHA-256(toString())` is not the
//!   upstream checksum.
//!
//! ## Example
//!
//! ```
//! use aleo_rust_sdk::proving_key::ProvingKey;
//! use snarkvm::parameters::testnet as params;
//! use snarkvm::prelude::TestnetV0;
//!
//! let bytes = params::FeePublicProver::load_bytes().unwrap();
//! let key = ProvingKey::<TestnetV0>::from_bytes(&bytes).unwrap();
//! assert_eq!(key.to_bytes().unwrap(), bytes);
//!
//! // JS: key.checksum()
//! assert_eq!(key.checksum().unwrap().len(), 64);
//!
//! // JS: key.toString() / ProvingKey.fromString(string)
//! let string = key.to_string();
//! assert!(string.starts_with("prover1"));
//! let restored = ProvingKey::<TestnetV0>::from_string(&string).unwrap();
//! assert!(restored == key);
//! ```

use anyhow::{Context, Result};
use snarkvm::prelude::{FromBytes, Network, ToBytes};
use snarkvm::synthesizer::snark::ProvingKey as NativeProvingKey;
use std::{fmt, ops::Deref, str::FromStr};

/// A proving key for a function within an Aleo program — the Rust shape of
/// the JS SDK's wasm `ProvingKey` (a newtype over snarkVM's native key).
#[derive(Clone)]
pub struct ProvingKey<N: Network>(NativeProvingKey<N>);

impl<N: Network> ProvingKey<N> {
    /// Returns the checksum of the proving key — JS `checksum()`.
    ///
    /// This is `hex(SHA-256(to_bytes_le()))`, exactly the upstream wasm
    /// formula, shared with the credits-key validation in `keys`.
    pub fn checksum(&self) -> Result<String> {
        crate::keys::key_checksum(&self.0)
    }

    /// Creates a copy of the proving key — JS `copy()`.
    ///
    /// The native key is an `Arc` internally, so this is cheap.
    pub fn copy(&self) -> Self {
        Self(self.0.clone())
    }

    /// Constructs a proving key from its canonical bytes — JS `fromBytes`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        NativeProvingKey::from_bytes_le(bytes)
            .map(Self)
            .context("Failed to deserialize proving key bytes")
    }

    /// Parses a proving key from its bech32m `prover1…` string — JS
    /// `fromString`.
    pub fn from_string(string: &str) -> Result<Self> {
        NativeProvingKey::<N>::from_str(string)
            .map(Self)
            .context("Failed to parse proving key string")
    }

    /// Returns the canonical byte representation — JS `toBytes`.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.0.to_bytes_le().context("Failed to serialize proving key")
    }
}

impl<N: Network> Deref for ProvingKey<N> {
    type Target = NativeProvingKey<N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<N: Network> fmt::Display for ProvingKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl<N: Network> fmt::Debug for ProvingKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl<N: Network> FromStr for ProvingKey<N> {
    type Err = anyhow::Error;

    fn from_str(string: &str) -> Result<Self> {
        Self::from_string(string)
    }
}

impl<N: Network> From<NativeProvingKey<N>> for ProvingKey<N> {
    fn from(key: NativeProvingKey<N>) -> Self {
        Self(key)
    }
}

impl<N: Network> From<ProvingKey<N>> for NativeProvingKey<N> {
    fn from(key: ProvingKey<N>) -> Self {
        key.0
    }
}

impl<N: Network> AsRef<NativeProvingKey<N>> for ProvingKey<N> {
    fn as_ref(&self) -> &NativeProvingKey<N> {
        &self.0
    }
}

impl<N: Network> PartialEq for ProvingKey<N> {
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use snarkvm::parameters::testnet as params;
    use snarkvm::prelude::TestnetV0;
    use std::sync::LazyLock;

    /// The checksum the upstream wasm `test_proving_key` pins for the
    /// `transfer_public` prover on testnet (`wasm/src/programs/proving_key/mod.rs`).
    const UPSTREAM_TESTNET_TRANSFER_PUBLIC_CHECKSUM: &str =
        "846f86cabf9fa50e5abe347e559a8e9f3018459b5af9fdf52f1c44892b05f7e5";

    /// `fee_public` is the same prover the rest of this crate's offline tests
    /// already load, so no new parameter download is needed in CI.
    static FEE_PUBLIC_BYTES: LazyLock<Vec<u8>> =
        LazyLock::new(|| params::FeePublicProver::load_bytes().expect("fee_public prover bytes"));

    fn fee_public_key() -> ProvingKey<TestnetV0> {
        ProvingKey::from_bytes(&FEE_PUBLIC_BYTES).expect("valid fee_public proving key")
    }

    fn official_checksum() -> String {
        let metadata: serde_json::Value = serde_json::from_str(params::FeePublicProver::METADATA)
            .expect("valid fee_public metadata");
        metadata["prover_checksum"]
            .as_str()
            .expect("prover_checksum in metadata")
            .to_string()
    }

    #[test]
    fn upstream_transfer_public_checksum_literal_matches_embedded_metadata() {
        let metadata: serde_json::Value =
            serde_json::from_str(params::TransferPublicProver::METADATA)
                .expect("valid transfer_public metadata");
        assert_eq!(
            metadata["prover_checksum"].as_str().unwrap(),
            UPSTREAM_TESTNET_TRANSFER_PUBLIC_CHECKSUM
        );
    }

    #[test]
    fn from_bytes_to_bytes_roundtrip_and_official_checksum() {
        let key = fee_public_key();
        assert_eq!(key.to_bytes().unwrap(), *FEE_PUBLIC_BYTES);
        let checksum = key.checksum().unwrap();
        assert_eq!(checksum.len(), 64);
        assert_eq!(checksum, hex::encode(Sha256::digest(&*FEE_PUBLIC_BYTES)));
        assert_eq!(checksum, official_checksum());
    }

    #[test]
    fn string_roundtrip_is_bech32m() {
        let key = fee_public_key();
        let string = key.to_string();
        assert!(string.starts_with("prover1"));
        let restored = ProvingKey::<TestnetV0>::from_string(&string).unwrap();
        assert!(restored == key);
        assert_eq!(restored.checksum().unwrap(), key.checksum().unwrap());
        let via_trait: ProvingKey<TestnetV0> = string.parse().unwrap();
        assert!(via_trait == key);
    }

    #[test]
    fn copy_returns_an_equal_independent_key() {
        let key = fee_public_key();
        let copy = key.copy();
        assert!(copy == key);
        assert_eq!(copy.checksum().unwrap(), key.checksum().unwrap());
        assert_eq!(copy.to_string(), key.to_string());
    }

    #[test]
    fn invalid_bytes_and_string_are_rejected() {
        assert!(ProvingKey::<TestnetV0>::from_bytes(&[]).is_err());
        assert!(ProvingKey::<TestnetV0>::from_bytes(&[0u8; 4]).is_err());
        assert!(ProvingKey::<TestnetV0>::from_string("").is_err());
        assert!(ProvingKey::<TestnetV0>::from_string("not-a-proving-key").is_err());
        assert!(ProvingKey::<TestnetV0>::from_string("prover1qqqqqq").is_err());
    }

    #[test]
    fn deref_from_and_as_ref_keep_native_access() {
        let native = NativeProvingKey::<TestnetV0>::from_bytes_le(&FEE_PUBLIC_BYTES).unwrap();
        let key: ProvingKey<TestnetV0> = native.into();
        assert_eq!(key.to_bytes().unwrap(), *FEE_PUBLIC_BYTES);
        // `to_bytes_le` is reached through `Deref` to the native key.
        assert_eq!(key.to_bytes_le().unwrap(), *FEE_PUBLIC_BYTES);
        let as_ref: &NativeProvingKey<TestnetV0> = key.as_ref();
        assert_eq!(as_ref.to_bytes_le().unwrap(), *FEE_PUBLIC_BYTES);
        let back: NativeProvingKey<TestnetV0> = key.into();
        assert_eq!(back.to_bytes_le().unwrap(), *FEE_PUBLIC_BYTES);
    }

    #[test]
    fn debug_matches_display() {
        let key = fee_public_key();
        assert_eq!(format!("{key:?}"), key.to_string());
    }
}
