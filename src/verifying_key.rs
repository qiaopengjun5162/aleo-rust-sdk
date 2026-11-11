//! # VerifyingKey — parity with the JS SDK's wasm `VerifyingKey`.
//!
//! A verifying key for one function of one program. Like
//! `crate::proving_key`, this page is a one-field newtype over a native
//! snarkVM type, so the module keeps that shape (generic over `Network`) and
//! adds the nine JS methods.
//!
//! ## JS `VerifyingKey` → Rust mapping
//!
//! | # | JS | Rust equivalent | Notes |
//! |---|---|---|---|
//! | 1 | `checksum()` | [`VerifyingKey::checksum`] | `SHA-256(to_bytes_le())` hex |
//! | 2 | `copy()` | [`VerifyingKey::copy`] | derived `Clone` (`Arc`-backed) |
//! | 3 | `fromBytes(bytes)` | [`VerifyingKey::from_bytes`] | native `FromBytes` |
//! | 4 | `fromString(string)` | [`VerifyingKey::from_string`] | native `FromStr` (bech32m `verifier1…`) |
//! | 5 | `numConstraints()` | [`VerifyingKey::num_constraints`] | `circuit_info.num_constraints` |
//! | 6 | `toBytes()` | [`VerifyingKey::to_bytes`] | native `ToBytes` |
//! | 7 | `toString()` | `key.to_string()` | `Display` (blanket `ToString`) |
//! | 8 | `verify(inputs, proof)` | [`VerifyingKey::verify`] | latest consensus rules, like upstream |
//! | 9 | `verifyBatch(vks, inputs, proof)` | [`VerifyingKey::verify_batch`] | errors collapse to `false`, like upstream |
//!
//! `numConstraints` is reachable because snarkVM's `VerifyingKey` implements
//! `Deref<Target = varuna::CircuitVerifyingKey>`, whose `circuit_info` field is
//! public. Its sibling `num_variables()` is a direct native method, already
//! available through this type's own `Deref`.
//!
//! ## Reuse, not reimplementation
//!
//! `checksum` delegates to the crate's shared `SHA-256(key.to_bytes_le())`
//! helper in `keys` — the same formula `crate::proving_key` uses. The upstream
//! wasm test downloads the `transfer_public` verifier and pins its SHA-256 as
//! `1b5109468e…`; the test module reproduces that literal from the
//! **embedded** `snarkvm-parameters` bytes, so CI needs no download.
//!
//! `toString` and `copy` are traits (`Display` / `Clone`) rather than inherent
//! methods, avoiding the clippy lints upstream silences with
//! `#[allow(clippy::inherent_to_string)]`.
//!
//! ## Differences from the JS page
//!
//! * Every fallible method returns `anyhow::Result`, as elsewhere in this
//!   crate. The wasm class unwraps internally for `checksum()` and returns
//!   `Result<_, String>` for the rest; serialization and parsing can fail, so
//!   this API does not hide that.
//! * `verify` takes `&[Field<N>]` rather than an array of strings. JS has to
//!   parse `"1field"` at the boundary; here that is
//!   [`VerifyingKey::parse_field_inputs`], so the typed API stays typed and the
//!   string form remains available for JS-shaped call sites.
//! * `checksum()` hashes the **canonical bytes** (`toBytes`), not the string
//!   form. `SHA-256(toString())` is *not* the upstream checksum.
//!
//! ## Which consensus rules does `verify` use?
//!
//! Upstream calls the native verifier with the function name `"snark_verify"`
//! and the Varuna version of [`ConsensusVersion::latest`], and documents that
//! proofs produced under an older Varuna version therefore fail. This module
//! does the same, because the JS page has no version parameter. That is *not*
//! how a historical on-chain transition is checked: there the Varuna version
//! comes from the block height. For that case use
//! [`crate::execution::ExecutionEngine`] / `AleoClient::verify_execution_at`,
//! or reach the native key through `Deref` and call
//! `verify(function_name, varuna_version, inputs, proof)` directly.
//!
//! ## Example
//!
//! ```
//! use aleo_rust_sdk::verifying_key::VerifyingKey;
//! use snarkvm::parameters::testnet as params;
//! use snarkvm::prelude::TestnetV0;
//!
//! let bytes = params::TransferPublicVerifier::load_bytes().unwrap();
//! let key = VerifyingKey::<TestnetV0>::from_bytes(&bytes).unwrap();
//!
//! // JS: key.toBytes() / key.checksum()
//! assert_eq!(key.to_bytes().unwrap(), bytes);
//! assert_eq!(key.checksum().unwrap().len(), 64);
//!
//! // JS: key.numConstraints()
//! assert_eq!(key.num_constraints(), 12_326);
//!
//! // JS: key.toString() / VerifyingKey.fromString(string)
//! let string = key.to_string();
//! assert!(string.starts_with("verifier1"));
//! let restored = VerifyingKey::<TestnetV0>::from_string(&string).unwrap();
//! assert!(restored == key);
//! ```

use anyhow::{Context, Result};
use snarkvm::prelude::{ConsensusVersion, Environment, Field, FromBytes, Network, Proof, ToBytes};
use snarkvm::synthesizer::snark::VerifyingKey as NativeVerifyingKey;
use std::{fmt, ops::Deref, str::FromStr};

use crate::execution::consensus_version_to_varuna;

/// The locator the upstream wasm passes for single-proof verification. It only
/// labels dev-print output, but keeping it identical makes logs comparable.
const VERIFY_LOCATOR: &str = "snark_verify";

/// The locator the upstream wasm passes for batch verification.
const VERIFY_BATCH_LOCATOR: &str = "snark_verify_batch";

/// A verifying key paired with its public-input instances — one element of the
/// batch a [`VerifyingKey::verify_batch`] call consumes.
///
/// The outer `Vec` matches upstream's `inputs[circuit_idx][instance_idx][field_idx]`
/// layout: a key can carry several instances (one per proven call) and each
/// instance is a list of field elements.
pub type KeyInstances<N> = (VerifyingKey<N>, Vec<Vec<Field<N>>>);

/// A verifying key for a function within an Aleo program — the Rust shape of
/// the JS SDK's wasm `VerifyingKey`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey<N: Network>(NativeVerifyingKey<N>);

impl<N: Network> VerifyingKey<N> {
    /// Returns the checksum of the verifying key — JS `checksum()`.
    ///
    /// This is `hex(SHA-256(to_bytes_le()))`, the upstream wasm formula, shared
    /// with the credits-key validation in `keys`.
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be serialized — practically
    /// unreachable for a parsed key, but not something this layer can promise.
    pub fn checksum(&self) -> Result<String> {
        crate::keys::key_checksum(&self.0)
    }

    /// Returns a copy of the key — JS `copy()`.
    ///
    /// The native key holds its circuit data behind an `Arc`, so this copies a
    /// pointer, not megabytes of parameters.
    pub fn copy(&self) -> Self {
        self.clone()
    }

    /// Parses a verifying key from its little-endian byte form — JS
    /// `fromBytes(bytes)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid serialized key (wrong
    /// version byte, truncated data, or points that fail validation).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key = NativeVerifyingKey::<N>::from_bytes_le(bytes)
            .context("failed to deserialize verifying key")?;
        Ok(Self(key))
    }

    /// Parses a verifying key from its bech32m string form (`verifier1…`) — JS
    /// `fromString(string)`.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong human-readable prefix, an empty data
    /// field, or bytes that fail to deserialize.
    pub fn from_string(string: &str) -> Result<Self> {
        let key = NativeVerifyingKey::<N>::from_str(string)
            .with_context(|| format!("failed to parse verifying key '{string}'"))?;
        Ok(Self(key))
    }

    /// Returns the little-endian byte form — JS `toBytes()`.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.0.to_bytes_le().context("failed to serialize verifying key")
    }

    /// Returns the number of constraints in the circuit — JS `numConstraints()`.
    ///
    /// snarkVM stores this as a `usize`; the JS page (and therefore this
    /// method) reports a `u32`. Circuits are far below that bound.
    pub fn num_constraints(&self) -> u32 {
        self.0.circuit_info.num_constraints as u32
    }

    /// Verifies `proof` against this key and `inputs` — JS `verify(inputs, proof)`.
    ///
    /// Uses the function-name locator `"snark_verify"` and the Varuna version
    /// of [`ConsensusVersion::latest`], mirroring the upstream wasm. A proof
    /// produced under an older Varuna version will not verify here; see the
    /// module docs for the height-aware path.
    ///
    /// Returns `false` (never an error) for a malformed or mismatched proof —
    /// the native verifier folds failures into `false`.
    pub fn verify(&self, inputs: &[Field<N>], proof: &Proof<N>) -> bool {
        let inputs = to_raw_field_elements(inputs);
        self.0.verify(VERIFY_LOCATOR, latest_varuna_version(), &inputs, proof)
    }

    /// Verifies a batch proof against multiple keys and their instances — JS
    /// `verifyBatch(verifying_keys, inputs, proof)`.
    ///
    /// Each element pairs a key with one or more instances (`Vec<Vec<Field>>`),
    /// matching the upstream 3-D `inputs[circuit_idx][instance_idx][field_idx]`
    /// shape. As upstream does (`map_or(Ok(false), |_| Ok(true))`), any error
    /// from the native batch verifier — including duplicate keys — becomes
    /// `false` rather than an `Err`.
    pub fn verify_batch(keys_and_inputs: &[KeyInstances<N>], proof: &Proof<N>) -> bool {
        let inputs = keys_and_inputs
            .iter()
            .map(|(key, instances)| {
                let instances =
                    instances.iter().map(|instance| to_raw_field_elements(instance)).collect();
                (key.0.clone(), instances)
            })
            .collect();
        NativeVerifyingKey::verify_batch(
            VERIFY_BATCH_LOCATOR,
            latest_varuna_version(),
            inputs,
            proof,
        )
        .is_ok()
    }

    /// Parses `"1field"`-style strings into field elements — the boundary
    /// conversion the JS `verify` / `verifyBatch` signatures perform implicitly.
    ///
    /// # Errors
    ///
    /// Returns an error naming the offending literal if any entry is not a
    /// valid field element.
    pub fn parse_field_inputs(inputs: &[&str]) -> Result<Vec<Field<N>>> {
        inputs
            .iter()
            .map(|input| {
                Field::<N>::from_str(input)
                    .with_context(|| format!("failed to parse field element '{input}'"))
            })
            .collect()
    }
}

/// The Varuna version the off-chain verifiers assume — upstream's
/// `latest_varuna_version()`, which is `ConsensusVersion::latest()` mapped
/// through snarkVM's `varuna_version_from_consensus`.
fn latest_varuna_version() -> snarkvm::algorithms::snark::varuna::VarunaVersion {
    consensus_version_to_varuna(ConsensusVersion::latest())
}

/// Unwraps console `Field<N>` values into the raw prime-field elements the
/// native verifier takes (`N::Field`).
///
/// `snarkVM`'s `VerifyingKey::verify` takes `&[N::Field]` — the underlying
/// `PrimeField`, not the console wrapper. `Field<N>` derefs to exactly that
/// type, which is why upstream wasm's `parse_field_inputs` ends with `*field`.
fn to_raw_field_elements<N: Network>(inputs: &[Field<N>]) -> Vec<<N as Environment>::Field> {
    inputs.iter().map(|field| **field).collect()
}

impl<N: Network> Deref for VerifyingKey<N> {
    type Target = NativeVerifyingKey<N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<N: Network> fmt::Display for VerifyingKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<N: Network> FromStr for VerifyingKey<N> {
    type Err = anyhow::Error;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        Self::from_string(string)
    }
}

impl<N: Network> From<NativeVerifyingKey<N>> for VerifyingKey<N> {
    fn from(key: NativeVerifyingKey<N>) -> Self {
        Self(key)
    }
}

impl<N: Network> From<VerifyingKey<N>> for NativeVerifyingKey<N> {
    fn from(key: VerifyingKey<N>) -> Self {
        key.0
    }
}

impl<N: Network> AsRef<NativeVerifyingKey<N>> for VerifyingKey<N> {
    fn as_ref(&self) -> &NativeVerifyingKey<N> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::parameters::testnet as params;
    use snarkvm::prelude::TestnetV0;
    use std::sync::LazyLock;

    /// Upstream wasm literal for the testnet `transfer_public` verifier
    /// (`wasm/src/programs/verifying_key/mod.rs`).
    const UPSTREAM_TRANSFER_PUBLIC_KEY: &str = "verifier1qygqqqqqqqqqqqp3xqqqqqqqqqqzvvqqqqqqqqqq23hqqqqqqqqqqau5qqqqqqqqqq5yzqqqqqqqqqqvqqqqqqqqqqqz2rh4q6m4u0ycv2z5qx95echpdcsktezkr2j9cvff0dngp45jfqggm8q3578nkhjudslm2rdpsgcpks4ulquyqrtd978zvj65pxmhkudyjtj005h66jcnwg3f6mdqqaqjed3avcz599kth8a3nak0tftsrk4hczcdvlmrdnzsa6rfppy72flsrhdhn6npxfxt2rrudk8jrk5fefkawhhrf0psccp6l9akckaps898v5mk7vprkx90gg798d6j5tvvtma0r9phq3jndan5rkwv8wmkngeha3pzrjzslkt8ct9umm4wfq8dhnpdv8m4plq70c3d6wxs4l3cv4gyqhgjtwfuydc5fflulwgjvdtaxxlmpf0l5n800jn2lwnt5kqqtdsx2lvzl3kw3ns5hnsu4jzg9ejptg7n7r7d9dvqsrvldw9paeq86hjxeaac6typemynwzt8w3vq3e27l4swd9aqxaas7zsy5mw7ftnjct9jq6t9rdq0kx8vjag77nt0z894xqkrfp27hehk83nfcg7cpjcc7f8mznga33xp36seafxpn26rq4w5l9uawtx02mzpq9kuyyx7nvhtad0mxk5su659xx5wv3yhqqy3577kwc40spvp9dst59ap2ll5uuq7qaauy9vy5yvrjd77c443evxrwfsee8jg5hvt6f9xaupjzq2cmuuwdvjs0qtxmnwjmdepu5979qy4nhqs63zljatt7kkggddxctt74crayt4djvnh3u6tjzm8wyqpc7nf0r0k9mp34x9musgdqegkmscey50ckyehm67c5tcdlawkh6my2v3xzwaug7c4y9xyw0dfkqup24jdckk5wxkyfd8rsp6h220dj786t54fyj59ehtq0gyut6lcattumgdss4kkchrdp7f5sjgcu7ycpzq0d47m6xe3yh2q5q76fa20lm46pe8fcd9yqcrxduhkdqfe4c9pw3pqqqqqqqqqq0qvtsl";

    /// The checksum the upstream wasm `test_verifier_checksum` pins for that key.
    const UPSTREAM_TRANSFER_PUBLIC_CHECKSUM: &str =
        "1b5109468e7992c39bbbc299dd1f94f18e49928e253e60ed68c7d9f02e73fe8d";

    /// The constraint count the upstream wasm `test_num_constraints` pins.
    const UPSTREAM_NUM_CONSTRAINTS: u32 = 12_326;

    /// `impl_local!`-embedded verifier parameters — no network in CI.
    static VERIFIER_BYTES: LazyLock<Vec<u8>> =
        LazyLock::new(|| params::TransferPublicVerifier::load_bytes().expect("verifier bytes"));

    /// A real `credits.aleo` execution proof, used only as a *foreign* proof:
    /// it does not verify against this key and these inputs, which is exactly
    /// the rejected path. Embedding it avoids generating a proof (and
    /// downloading the universal SRS) in tests.
    static FOREIGN_PROOF: LazyLock<Proof<TestnetV0>> = LazyLock::new(|| {
        let json: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/credits_execute_tx.json"))
                .expect("valid transaction fixture");
        let proof = json["transaction"]["execution"]["proof"]
            .as_str()
            .expect("execution proof in fixture");
        Proof::<TestnetV0>::from_str(proof).expect("valid proof literal")
    });

    fn key() -> VerifyingKey<TestnetV0> {
        VerifyingKey::from_bytes(&VERIFIER_BYTES).expect("valid transfer_public verifying key")
    }

    #[test]
    fn upstream_string_literal_matches_embedded_verifier() {
        assert_eq!(key().to_string(), UPSTREAM_TRANSFER_PUBLIC_KEY);
    }

    #[test]
    fn checksum_matches_upstream_literal_and_official_metadata() {
        let key = key();
        assert_eq!(key.checksum().unwrap(), UPSTREAM_TRANSFER_PUBLIC_CHECKSUM);

        let metadata: serde_json::Value =
            serde_json::from_str(params::TransferPublicVerifier::METADATA)
                .expect("valid verifier metadata");
        assert_eq!(
            metadata["verifier_checksum"].as_str().unwrap(),
            UPSTREAM_TRANSFER_PUBLIC_CHECKSUM
        );
    }

    #[test]
    fn from_bytes_to_bytes_roundtrip() {
        assert_eq!(key().to_bytes().unwrap(), *VERIFIER_BYTES);
    }

    #[test]
    fn num_constraints_matches_upstream_literal() {
        assert_eq!(key().num_constraints(), UPSTREAM_NUM_CONSTRAINTS);
    }

    #[test]
    fn num_variables_is_reachable_through_deref() {
        // Native accessor, not a JS-page method: proves `Deref` keeps the
        // native surface available.
        assert!(key().num_variables() > 0);
    }

    #[test]
    fn string_roundtrip_is_bech32m() {
        let key = key();
        let string = key.to_string();
        assert!(string.starts_with("verifier1"));
        let restored = VerifyingKey::<TestnetV0>::from_string(&string).unwrap();
        assert!(restored == key);
        assert_eq!(restored.checksum().unwrap(), key.checksum().unwrap());

        let via_trait: VerifyingKey<TestnetV0> = string.parse().unwrap();
        assert!(via_trait == key);
    }

    #[test]
    fn copy_returns_an_equal_independent_key() {
        let key = key();
        let copy = key.copy();
        assert!(copy == key);
        assert_eq!(copy.checksum().unwrap(), key.checksum().unwrap());
    }

    #[test]
    fn invalid_bytes_and_string_are_rejected() {
        assert!(VerifyingKey::<TestnetV0>::from_bytes(&[]).is_err());
        assert!(VerifyingKey::<TestnetV0>::from_bytes(&[0u8; 4]).is_err());
        assert!(VerifyingKey::<TestnetV0>::from_string("").is_err());
        assert!(VerifyingKey::<TestnetV0>::from_string("not-a-verifying-key").is_err());
        assert!(VerifyingKey::<TestnetV0>::from_string("prover1qqqqqq").is_err());
    }

    #[test]
    fn deref_from_and_as_ref_keep_native_access() {
        let native = NativeVerifyingKey::<TestnetV0>::from_bytes_le(&VERIFIER_BYTES).unwrap();
        let key: VerifyingKey<TestnetV0> = native.into();
        assert_eq!(key.to_bytes().unwrap(), *VERIFIER_BYTES);
        assert_eq!(key.to_bytes_le().unwrap(), *VERIFIER_BYTES);

        let as_ref: &NativeVerifyingKey<TestnetV0> = key.as_ref();
        assert_eq!(as_ref.to_bytes_le().unwrap(), *VERIFIER_BYTES);

        let back: NativeVerifyingKey<TestnetV0> = key.into();
        assert_eq!(back.to_bytes_le().unwrap(), *VERIFIER_BYTES);
    }

    #[test]
    fn debug_wraps_the_display_form() {
        // Native `Debug` forwards to the bech32m `Display`; the derived impl on
        // the newtype wraps that, exactly like the upstream wasm `#[derive(Debug)]`.
        let key = key();
        let debug = format!("{key:?}");
        assert_eq!(debug, format!("VerifyingKey({key})"));
        assert!(debug.ends_with(')'));
    }

    #[test]
    fn verify_rejects_a_foreign_proof() {
        let key = key();
        // A real proof for a different circuit and different inputs.
        assert!(!key.verify(&[Field::from_u64(1)], &FOREIGN_PROOF));
        // Right circuit shape, wrong instance: still rejected.
        let zeros = vec![Field::from_u64(0); UPSTREAM_NUM_CONSTRAINTS as usize];
        assert!(!key.verify(&zeros, &FOREIGN_PROOF));
        // Fewer inputs than the circuit expects must not panic.
        assert!(!key.verify(&[], &FOREIGN_PROOF));
    }

    #[test]
    fn verify_batch_rejects_a_foreign_proof() {
        let key = key();
        let pairs = vec![(key.clone(), vec![vec![Field::from_u64(1)]])];
        assert!(!VerifyingKey::verify_batch(&pairs, &FOREIGN_PROOF));

        // Duplicate keys make the native verifier bail; upstream maps that to
        // `false`, and so does this wrapper.
        let duplicated = vec![
            (key.clone(), vec![vec![Field::from_u64(1)]]),
            (key.clone(), vec![vec![Field::from_u64(2)]]),
        ];
        assert!(!VerifyingKey::verify_batch(&duplicated, &FOREIGN_PROOF));
    }

    #[test]
    fn parse_field_inputs_handles_js_style_strings() {
        let inputs = VerifyingKey::<TestnetV0>::parse_field_inputs(&["1field", "2field"]).unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0], Field::from_u64(1));
        assert_eq!(inputs[1], Field::from_u64(2));

        let empty = VerifyingKey::<TestnetV0>::parse_field_inputs(&[]).unwrap();
        assert!(empty.is_empty());

        let err = VerifyingKey::<TestnetV0>::parse_field_inputs(&["nope"])
            .expect_err("invalid literal must be rejected");
        assert!(err.to_string().contains("nope"));
    }
}
