//! # Function key providers — cached and online key retrieval.
//!
//! This module holds the Rust counterparts of the JS SDK's two
//! `FunctionKeyProvider` implementations:
//!
//! - [`OfflineKeyProvider`] — a key cache for devices that **cannot contact
//!   the internet** for key material (hardware wallets, air-gapped machines).
//!   The user inserts Aleo function proving and verifying keys from local
//!   storage; transaction building then reads them from here instead of
//!   synthesizing circuits on the fly.
//! - [`AleoKeyProvider`] — the online provider (JS `AleoKeyProvider`): the
//!   same cache plus [`KeyByteTransport`], which downloads key bytes over
//!   HTTP from arbitrary URLs (or serves the embedded `credits.aleo` keys
//!   with no network access at all — see *Differences* below).
//!
//! ```no_run
//! # use aleo_rust_sdk::keys::{CreditsFunction, OfflineKeyProvider};
//! # use snarkvm::prelude::{FromBytes, TestnetV0};
//! # use snarkvm::synthesizer::snark::{ProvingKey, VerifyingKey};
//! # fn main() -> anyhow::Result<()> {
//! // On an offline device, keys arrive from local files.
//! # let fee_prover_bytes: &[u8] = &[];
//! let proving_key = ProvingKey::<TestnetV0>::from_bytes_le(fee_prover_bytes)?;
//!
//! let mut provider = OfflineKeyProvider::new();
//!
//! // JS `insertFeePublicKeys`: verifies the checksum and attaches the
//! // canonical verifying key — no need to load or trust one yourself.
//! provider.insert_credits_key(CreditsFunction::FeePublic, proving_key)?;
//!
//! // Later, when building a transaction:
//! let (pk, vk) = provider.credits_keys(CreditsFunction::FeePublic)?;
//! # Ok(())
//! # }
//! ```
//!
//! Cached keys can also be installed straight into an
//! [`ExecutionEngine`](crate::ExecutionEngine)'s process (see
//! [`OfflineKeyProvider::install`]) so that authorization and proving find
//! them instead of synthesizing circuits.
//!
//! ## Locator convention
//!
//! Entries are keyed by `"program.aleo/function"` — the same strings the JS
//! SDK uses (e.g. `"credits.aleo/fee_public"`). The inclusion prover is the
//! one exception: its locator is the bare string `"inclusion"`, matching
//! `CREDITS_PROGRAM_KEYS.inclusion.locator` in the JS SDK.
//!
//! ## Differences from the JS SDK
//!
//! - JS exposes 15 `insert*Keys()` methods, 15 `OfflineSearchParams.*Params()`
//!   constructors, and a matching `*Keys()` getter per function. Rust models
//!   the insert/search surface as the [`CreditsFunction`] enum:
//!   `insert_credits_key(function, pk)` replaces `insert*Keys(pk)` and
//!   [`OfflineKeyProvider::credits_keys`] replaces the search. The JS getter
//!   names are preserved as convenience methods on both providers
//!   ([`OfflineKeyProvider::fee_public_keys`],
//!   [`AleoKeyProvider::transfer_keys`], …), with the
//!   `transferKeys(visibility)` alias strings handled by
//!   [`CreditsFunction::from_transfer_visibility`].
//! - [`AleoKeyProvider::get_verifying_key`] mirrors JS `getVerifyingKey`: the
//!   official credits verifier identifiers (e.g. `"fee_public.verifier.f72b6ff"`)
//!   resolve to the embedded canonical verifiers; any other URI is fetched
//!   and parsed as a verifying-key string first, then as raw key bytes,
//!   failing with `"Invalid verifying key. Error: …"`. The identifier suffix
//!   is the **prover** checksum prefix — the JS wasm `Metadata` builder
//!   always reads `prover_checksum`, see
//!   [`CreditsFunction::verifier_identifier`].
//! - JS caches raw key bytes; the cache here holds the typed
//!   [`ProvingKey`] / [`VerifyingKey`] pair. The
//!   serialization is identical either way.
//! - JS `AleoKeyProvider` downloads `credits.aleo` proving keys over HTTP
//!   (`fetchCreditsKeys`) because the WASM bundle cannot embed them. The
//!   native `snarkvm-parameters` crate embeds every credits key
//!   (`impl_local!`), so [`AleoKeyProvider::credits_keys`] loads both halves
//!   **offline** and never touches the network — while keeping the JS cache
//!   read/write semantics of `fetchCreditsKeys`.
//! - The JS SDK feeds cached keys into the prover explicitly. Native snarkVM
//!   proves the inclusion (state-path) circuit with the protocol built-in
//!   `TestnetV0::inclusion_proving_key()`, so there is nothing to install:
//!   install skips the `"inclusion"` locator. The
//!   entry can still be cached and checksum-verified for parity.
//!
//! [`OfflineKeyProvider::install`]: OfflineKeyProvider::install

use anyhow::{Context, Result};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use snarkvm::prelude::{FromBytes, Identifier, Process, ProgramID, TestnetV0, ToBytes};
use snarkvm::synthesizer::snark::{ProvingKey, VerifyingKey};
use std::collections::HashMap;
use std::str::FromStr;

/// A proving/verifying key pair for one function (JS `FunctionKeyPair`).
pub type FunctionKeyPair = (ProvingKey<TestnetV0>, VerifyingKey<TestnetV0>);

/// The built-in key slots with pre-configured search parameters in the JS SDK
/// (the `OfflineSearchParams.*Params()` constructors).
///
/// [`CreditsFunction::locator`] returns exactly the JS cache-key strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CreditsFunction {
    BondPublic,
    BondValidator,
    ClaimUnbondPublic,
    FeePrivate,
    FeePublic,
    Inclusion,
    Join,
    SetValidatorState,
    Split,
    TransferPrivate,
    TransferPrivateToPublic,
    TransferPublic,
    TransferPublicAsSigner,
    TransferPublicToPrivate,
    UnbondPublic,
}

impl CreditsFunction {
    /// Every variant, in declaration order.
    pub const ALL: [Self; 15] = [
        Self::BondPublic,
        Self::BondValidator,
        Self::ClaimUnbondPublic,
        Self::FeePrivate,
        Self::FeePublic,
        Self::Inclusion,
        Self::Join,
        Self::SetValidatorState,
        Self::Split,
        Self::TransferPrivate,
        Self::TransferPrivateToPublic,
        Self::TransferPublic,
        Self::TransferPublicAsSigner,
        Self::TransferPublicToPrivate,
        Self::UnbondPublic,
    ];

    /// The cache-key locator, matching the JS SDK strings exactly.
    ///
    /// Program functions are `"credits.aleo/<function>"`; the inclusion prover
    /// is the bare string `"inclusion"`.
    pub fn locator(self) -> &'static str {
        match self {
            Self::BondPublic => "credits.aleo/bond_public",
            Self::BondValidator => "credits.aleo/bond_validator",
            Self::ClaimUnbondPublic => "credits.aleo/claim_unbond_public",
            Self::FeePrivate => "credits.aleo/fee_private",
            Self::FeePublic => "credits.aleo/fee_public",
            Self::Inclusion => "inclusion",
            Self::Join => "credits.aleo/join",
            Self::SetValidatorState => "credits.aleo/set_validator_state",
            Self::Split => "credits.aleo/split",
            Self::TransferPrivate => "credits.aleo/transfer_private",
            Self::TransferPrivateToPublic => "credits.aleo/transfer_private_to_public",
            Self::TransferPublic => "credits.aleo/transfer_public",
            Self::TransferPublicAsSigner => "credits.aleo/transfer_public_as_signer",
            Self::TransferPublicToPrivate => "credits.aleo/transfer_public_to_private",
            Self::UnbondPublic => "credits.aleo/unbond_public",
        }
    }

    /// The bare function name used in JS error messages
    /// ("Attempted to insert invalid proving keys for **bond_public**").
    pub fn name(self) -> &'static str {
        match self {
            Self::BondPublic => "bond_public",
            Self::BondValidator => "bond_validator",
            Self::ClaimUnbondPublic => "claim_unbond_public",
            Self::FeePrivate => "fee_private",
            Self::FeePublic => "fee_public",
            Self::Inclusion => "inclusion",
            Self::Join => "join",
            Self::SetValidatorState => "set_validator_state",
            Self::Split => "split",
            Self::TransferPrivate => "transfer_private",
            Self::TransferPrivateToPublic => "transfer_private_to_public",
            Self::TransferPublic => "transfer_public",
            Self::TransferPublicAsSigner => "transfer_public_as_signer",
            Self::TransferPublicToPrivate => "transfer_public_to_private",
            Self::UnbondPublic => "unbond_public",
        }
    }

    /// Reverse of [`Self::locator`]. Returns `None` for custom program
    /// locators (those can still be cached; they just have no official keys
    /// to verify against).
    pub fn from_locator(locator: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|function| function.locator() == locator)
    }

    /// Map a JS `transferKeys(visibility)` alias to the concrete function.
    ///
    /// Accepts exactly the alias sets the JS SDK accepts, e.g. `"private"`,
    /// `"transferPrivate"`, `"public_as_signer"`, `"publicToPrivate"`.
    pub fn from_transfer_visibility(visibility: &str) -> Result<Self> {
        match visibility {
            "private" | "transfer_private" | "transferPrivate" => Ok(Self::TransferPrivate),
            "private_to_public"
            | "privateToPublic"
            | "transfer_private_to_public"
            | "transferPrivateToPublic" => Ok(Self::TransferPrivateToPublic),
            "public" | "transfer_public" | "transferPublic" => Ok(Self::TransferPublic),
            "public_as_signer" | "transfer_public_as_signer" | "transferPublicAsSigner" => {
                Ok(Self::TransferPublicAsSigner)
            }
            "public_to_private"
            | "publicToPrivate"
            | "transfer_public_to_private"
            | "transferPublicToPrivate" => Ok(Self::TransferPublicToPrivate),
            _ => anyhow::bail!("Invalid visibility type"),
        }
    }

    /// The JS `CREDITS_PROGRAM_KEYS.<fn>.verifier` identifier
    /// (`"{name}.verifier.{checksum[..7]}"`).
    ///
    /// The 7-character suffix is the **prover** checksum prefix, not the
    /// verifier's — exactly how the JS wasm `Metadata` builder forms these
    /// strings (it always reads `prover_checksum` from the shared per-function
    /// metadata JSON). These identifiers are what
    /// [`AleoKeyProvider::get_verifying_key`] switches on.
    pub fn verifier_identifier(self) -> Result<String> {
        let (prover_checksum, _) = self.expected_checksums()?;
        Ok(format!(
            "{}.verifier.{}",
            self.name(),
            &prover_checksum[..7]
        ))
    }

    /// Reverse of [`Self::verifier_identifier`]: the function whose official
    /// verifier identifier equals `identifier` (the JS `getVerifyingKey`
    /// switch). `None` for anything else, including full URLs.
    pub fn from_verifier_identifier(identifier: &str) -> Option<Self> {
        Self::ALL.into_iter().find(
            |function| matches!(function.verifier_identifier(), Ok(known) if known == identifier),
        )
    }

    /// The embedded `snarkvm-parameters` metadata JSON for this function,
    /// carrying the official `prover_checksum` / `verifier_checksum`.
    fn metadata(self) -> &'static str {
        use snarkvm::parameters::testnet as params;
        match self {
            Self::BondPublic => params::BondPublicProver::METADATA,
            Self::BondValidator => params::BondValidatorProver::METADATA,
            Self::ClaimUnbondPublic => params::ClaimUnbondPublicProver::METADATA,
            Self::FeePrivate => params::FeePrivateProver::METADATA,
            Self::FeePublic => params::FeePublicProver::METADATA,
            Self::Inclusion => params::InclusionProver::METADATA,
            Self::Join => params::JoinProver::METADATA,
            Self::SetValidatorState => params::SetValidatorStateProver::METADATA,
            Self::Split => params::SplitProver::METADATA,
            Self::TransferPrivate => params::TransferPrivateProver::METADATA,
            Self::TransferPrivateToPublic => params::TransferPrivateToPublicProver::METADATA,
            Self::TransferPublic => params::TransferPublicProver::METADATA,
            Self::TransferPublicAsSigner => params::TransferPublicAsSignerProver::METADATA,
            Self::TransferPublicToPrivate => params::TransferPublicToPrivateProver::METADATA,
            Self::UnbondPublic => params::UnbondPublicProver::METADATA,
        }
    }

    /// The official `(prover_checksum, verifier_checksum)` pair, exactly as
    /// embedded in `snarkvm-parameters` (SHA-256 of the canonical key bytes).
    fn expected_checksums(self) -> Result<(String, String)> {
        let value: serde_json::Value = serde_json::from_str(self.metadata())
            .with_context(|| format!("Malformed key metadata for {}", self.name()))?;
        let checksum = |key: &str| -> Result<String> {
            value[key]
                .as_str()
                .map(str::to_string)
                .with_context(|| format!("Missing {key} in key metadata for {}", self.name()))
        };
        Ok((checksum("prover_checksum")?, checksum("verifier_checksum")?))
    }
}

/// SHA-256 of a key's canonical bytes, hex-encoded — the same `checksum()`
/// the JS SDK computes on `ProvingKey` / `VerifyingKey`.
///
/// Shared with the `proving_key` / `verifying_key` parity pages so there is
/// exactly one implementation of the upstream checksum formula.
pub(crate) fn key_checksum(key: &impl ToBytes) -> Result<String> {
    Ok(hex::encode(Sha256::digest(key.to_bytes_le()?)))
}

/// Whether `key` hashes to `expected`.
fn checksum_matches(expected: &str, key: &impl ToBytes) -> bool {
    key_checksum(key).map(|actual| actual == expected).unwrap_or(false)
}

/// The canonical verifying key shipped in `snarkvm-parameters` for a credits
/// function — the Rust equivalent of JS `VerifyingKey.bondPublicVerifier()`.
/// The bytes are embedded (`impl_local!`), so this works offline.
fn canonical_verifying_key(function: CreditsFunction) -> Result<VerifyingKey<TestnetV0>> {
    use snarkvm::parameters::testnet as params;
    let bytes = match function {
        CreditsFunction::BondPublic => params::BondPublicVerifier::load_bytes()?,
        CreditsFunction::BondValidator => params::BondValidatorVerifier::load_bytes()?,
        CreditsFunction::ClaimUnbondPublic => params::ClaimUnbondPublicVerifier::load_bytes()?,
        CreditsFunction::FeePrivate => params::FeePrivateVerifier::load_bytes()?,
        CreditsFunction::FeePublic => params::FeePublicVerifier::load_bytes()?,
        CreditsFunction::Inclusion => params::InclusionVerifier::load_bytes()?,
        CreditsFunction::Join => params::JoinVerifier::load_bytes()?,
        CreditsFunction::SetValidatorState => params::SetValidatorStateVerifier::load_bytes()?,
        CreditsFunction::Split => params::SplitVerifier::load_bytes()?,
        CreditsFunction::TransferPrivate => params::TransferPrivateVerifier::load_bytes()?,
        CreditsFunction::TransferPrivateToPublic => {
            params::TransferPrivateToPublicVerifier::load_bytes()?
        }
        CreditsFunction::TransferPublic => params::TransferPublicVerifier::load_bytes()?,
        CreditsFunction::TransferPublicAsSigner => {
            params::TransferPublicAsSignerVerifier::load_bytes()?
        }
        CreditsFunction::TransferPublicToPrivate => {
            params::TransferPublicToPrivateVerifier::load_bytes()?
        }
        CreditsFunction::UnbondPublic => params::UnbondPublicVerifier::load_bytes()?,
    };
    VerifyingKey::from_bytes_le(&bytes).with_context(|| {
        format!(
            "Failed to parse the canonical verifying key for {}",
            function.name()
        )
    })
}

/// The canonical proving key shipped in `snarkvm-parameters` for a credits
/// function. Embedded (`impl_local!`), so this works offline — the native
/// equivalent of downloading `key.prover` in the JS SDK.
fn canonical_proving_key(function: CreditsFunction) -> Result<ProvingKey<TestnetV0>> {
    use snarkvm::parameters::testnet as params;
    let bytes = match function {
        CreditsFunction::BondPublic => params::BondPublicProver::load_bytes()?,
        CreditsFunction::BondValidator => params::BondValidatorProver::load_bytes()?,
        CreditsFunction::ClaimUnbondPublic => params::ClaimUnbondPublicProver::load_bytes()?,
        CreditsFunction::FeePrivate => params::FeePrivateProver::load_bytes()?,
        CreditsFunction::FeePublic => params::FeePublicProver::load_bytes()?,
        CreditsFunction::Inclusion => params::InclusionProver::load_bytes()?,
        CreditsFunction::Join => params::JoinProver::load_bytes()?,
        CreditsFunction::SetValidatorState => params::SetValidatorStateProver::load_bytes()?,
        CreditsFunction::Split => params::SplitProver::load_bytes()?,
        CreditsFunction::TransferPrivate => params::TransferPrivateProver::load_bytes()?,
        CreditsFunction::TransferPrivateToPublic => {
            params::TransferPrivateToPublicProver::load_bytes()?
        }
        CreditsFunction::TransferPublic => params::TransferPublicProver::load_bytes()?,
        CreditsFunction::TransferPublicAsSigner => {
            params::TransferPublicAsSignerProver::load_bytes()?
        }
        CreditsFunction::TransferPublicToPrivate => {
            params::TransferPublicToPrivateProver::load_bytes()?
        }
        CreditsFunction::UnbondPublic => params::UnbondPublicProver::load_bytes()?,
    };
    ProvingKey::from_bytes_le(&bytes).with_context(|| {
        format!(
            "Failed to parse the canonical proving key for {}",
            function.name()
        )
    })
}

/// The canonical `(proving, verifying)` pair for a credits function, both
/// halves loaded from the embedded `snarkvm-parameters` bytes.
fn canonical_key_pair(function: CreditsFunction) -> Result<FunctionKeyPair> {
    Ok((
        canonical_proving_key(function)?,
        canonical_verifying_key(function)?,
    ))
}

/// Offline function-key cache (JS `OfflineKeyProvider`).
///
/// Entries are keyed by locator (see the [module docs](self)); values are
/// [`FunctionKeyPair`]s. The cache itself performs no verification — use
/// [`OfflineKeyProvider::insert_credits_key`] or the `verify_credits_keys`
/// flag on [`OfflineKeyProvider::function_keys`] for that.
#[derive(Default)]
pub struct OfflineKeyProvider {
    cache: HashMap<String, FunctionKeyPair>,
}

impl OfflineKeyProvider {
    /// Create an empty provider (JS `new OfflineKeyProvider()`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Store keys under `locator`, overwriting any previous entry
    /// (JS `cacheKeys`). No verification is performed — keys for custom
    /// programs have no official checksums to check against.
    pub fn cache_keys(&mut self, locator: impl Into<String>, keys: FunctionKeyPair) {
        self.cache.insert(locator.into(), keys);
    }

    /// Whether `locator` has a cached entry (JS `containsKeys`).
    pub fn contains_keys(&self, locator: &str) -> bool {
        self.cache.contains_key(locator)
    }

    /// Drop a cached entry, returning the removed pair if it existed.
    pub fn remove_keys(&mut self, locator: &str) -> Option<FunctionKeyPair> {
        self.cache.remove(locator)
    }

    /// Retrieve cached keys (JS `functionKeys`).
    ///
    /// With `verify_credits_keys = true` the pair is checked against the
    /// official `credits.aleo` checksums first (JS `OfflineSearchParams`
    /// with `verifyCreditsKeys: true`).
    ///
    /// # Errors
    ///
    /// Fails when nothing is cached under `locator`, or verification fails.
    pub fn function_keys(
        &self,
        locator: &str,
        verify_credits_keys: bool,
    ) -> Result<FunctionKeyPair> {
        let (proving_key, verifying_key) = self
            .cache
            .get(locator)
            .with_context(|| format!("Keys not found in cache for {locator}"))?;
        if verify_credits_keys && !Self::verify_credits_keys(locator, proving_key, verifying_key) {
            anyhow::bail!("Cached keys do not match expected keys for {locator}");
        }
        Ok((proving_key.clone(), verifying_key.clone()))
    }

    /// Insert the proving key of a `credits.aleo` function
    /// (JS `insertFeePublicKeys`, `insertJoinKeys`, …).
    ///
    /// The key must match the official checksum for `function`; the canonical
    /// verifying key is attached automatically, so only the proving key needs
    /// to be loaded from local storage.
    ///
    /// # Errors
    ///
    /// Fails when the proving key does not match the official checksum for
    /// `function`, or the canonical verifying key cannot be loaded.
    pub fn insert_credits_key(
        &mut self,
        function: CreditsFunction,
        proving_key: ProvingKey<TestnetV0>,
    ) -> Result<()> {
        let (prover_checksum, _) = function.expected_checksums()?;
        if !checksum_matches(&prover_checksum, &proving_key) {
            anyhow::bail!(
                "Attempted to insert invalid proving keys for {}",
                function.name()
            );
        }
        let verifying_key = canonical_verifying_key(function)?;
        self.cache.insert(function.locator().to_string(), (proving_key, verifying_key));
        Ok(())
    }

    /// Retrieve a `credits.aleo` key pair with checksum verification
    /// (JS `feePublicKeys()`, `joinKeys()`, `transferKeys(visibility)`, …).
    ///
    /// # Errors
    ///
    /// Fails when the keys are not cached or do not match the official
    /// checksums — the keys must be cached first via
    /// [`OfflineKeyProvider::insert_credits_key`] or
    /// [`OfflineKeyProvider::cache_keys`].
    pub fn credits_keys(&self, function: CreditsFunction) -> Result<FunctionKeyPair> {
        self.function_keys(function.locator(), true)
    }

    /// JS `bondPublicKeys()`.
    pub fn bond_public_keys(&self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::BondPublic)
    }

    /// JS `bondValidatorKeys()`.
    pub fn bond_validator_keys(&self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::BondValidator)
    }

    /// JS `claimUnbondPublicKeys()`.
    pub fn claim_unbond_public_keys(&self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::ClaimUnbondPublic)
    }

    /// JS `transferKeys(visibility)` — routes by the visibility alias
    /// strings (see [`CreditsFunction::from_transfer_visibility`]).
    pub fn transfer_keys(&self, visibility: &str) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::from_transfer_visibility(visibility)?)
    }

    /// JS `inclusionKeys()`.
    pub fn inclusion_keys(&self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::Inclusion)
    }

    /// JS `joinKeys()`.
    pub fn join_keys(&self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::Join)
    }

    /// JS `splitKeys()`.
    pub fn split_keys(&self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::Split)
    }

    /// JS `feePrivateKeys()`.
    pub fn fee_private_keys(&self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::FeePrivate)
    }

    /// JS `feePublicKeys()`.
    pub fn fee_public_keys(&self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::FeePublic)
    }

    /// JS `unBondPublicKeys()`.
    pub fn unbond_public_keys(&self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::UnbondPublic)
    }

    /// Whether the pair matches the official checksums for `locator`
    /// (JS `verifyCreditsKeys`). Always `false` for unknown locators.
    pub fn verify_credits_keys(
        locator: &str,
        proving_key: &ProvingKey<TestnetV0>,
        verifying_key: &VerifyingKey<TestnetV0>,
    ) -> bool {
        let Some(function) = CreditsFunction::from_locator(locator) else {
            return false;
        };
        let Ok((prover_checksum, verifier_checksum)) = function.expected_checksums() else {
            return false;
        };
        checksum_matches(&prover_checksum, proving_key)
            && checksum_matches(&verifier_checksum, verifying_key)
    }

    /// Install every cached key into `process`, so authorization and proving
    /// find them instead of synthesizing circuits. This is what makes
    /// transaction building work on an offline device.
    ///
    /// Only `"program.aleo/function"` locators are installed; the bare
    /// `"inclusion"` locator is skipped (snarkVM proves inclusion with the
    /// protocol built-in `TestnetV0::inclusion_proving_key()`). Custom
    /// programs must be added to the process first (see
    /// [`ExecutionEngine::add_program`](crate::ExecutionEngine::add_program)).
    ///
    /// Returns the number of key pairs installed.
    ///
    /// # Errors
    ///
    /// Fails when a locator is malformed or its program is not loaded in
    /// `process`. The install is not transactional: earlier entries remain
    /// installed if a later one fails.
    pub fn install(&self, process: &Process<TestnetV0>) -> Result<usize> {
        let mut installed = 0;
        for (locator, (proving_key, verifying_key)) in &self.cache {
            let Some((program, function)) = locator.split_once('/') else {
                // "inclusion" and other bare locators have no program slot.
                continue;
            };
            let program_id = ProgramID::<TestnetV0>::from_str(program)
                .with_context(|| format!("Invalid program id in locator: {locator}"))?;
            let function_name = Identifier::<TestnetV0>::from_str(function)
                .with_context(|| format!("Invalid function name in locator: {locator}"))?;
            process
                .insert_proving_key(&program_id, &function_name, proving_key.clone())
                .with_context(|| format!("Failed to install proving key for {locator}"))?;
            process
                .insert_verifying_key(&program_id, &function_name, verifying_key.clone())
                .with_context(|| format!("Failed to install verifying key for {locator}"))?;
            installed += 1;
        }
        Ok(installed)
    }
}

/// Source of raw key bytes over the network (JS `TransportFunction`).
///
/// [`AleoKeyProvider`] calls this for every remote fetch, so tests and
/// custom transports can be injected without touching HTTP.
#[async_trait]
pub trait KeyByteTransport: Send + Sync {
    /// Download the bytes served at `url`.
    ///
    /// # Errors
    ///
    /// Fails when the transport cannot retrieve `url` (network error, non-2xx
    /// status, …).
    async fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>>;
}

/// Default [`KeyByteTransport`] backed by `reqwest`.
///
/// Reuses the crate's shared HTTP client, which already honours proxy
/// environment variables and sends the browser-like User-Agent some key
/// hosts require.
pub struct ReqwestKeyTransport {
    client: reqwest::Client,
}

impl ReqwestKeyTransport {
    /// Build the transport with the crate's shared HTTP client.
    ///
    /// # Errors
    ///
    /// Fails when the shared HTTP client cannot be constructed.
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: crate::network::default_http_client()?,
        })
    }
}

#[async_trait]
impl KeyByteTransport for ReqwestKeyTransport {
    async fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("Error fetching data from {url}"))?;
        let response = response
            .error_for_status()
            .with_context(|| format!("Error fetching data from {url}"))?;
        response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .with_context(|| format!("Error fetching data from {url}"))
    }
}

/// Search parameters for [`AleoKeyProvider::function_keys`]
/// (JS `AleoKeyProviderParams`).
///
/// At least one of `name` (credits function), the `prover_uri` +
/// `verifier_uri` pair, or `cache_key` must be set.
#[derive(Clone, Debug, Default)]
pub struct AleoKeyProviderParams {
    /// Route to the embedded `credits.aleo` keys (JS `params.name`).
    pub name: Option<CreditsFunction>,
    /// URL to download the proving key bytes from.
    pub prover_uri: Option<String>,
    /// URL to download the verifying key bytes from.
    pub verifier_uri: Option<String>,
    /// Cache entry to read from / write to (JS `params.cacheKey`).
    pub cache_key: Option<String>,
}

impl AleoKeyProviderParams {
    /// Search by credits function name (JS `params.name`).
    pub fn credits(function: CreditsFunction) -> Self {
        Self {
            name: Some(function),
            ..Self::default()
        }
    }

    /// Search by remote URLs, optionally caching under `cache_key`.
    pub fn remote(prover_uri: impl Into<String>, verifier_uri: impl Into<String>) -> Self {
        Self {
            prover_uri: Some(prover_uri.into()),
            verifier_uri: Some(verifier_uri.into()),
            ..Self::default()
        }
    }

    /// Search the cache only (JS `params.cacheKey`).
    pub fn cached(cache_key: impl Into<String>) -> Self {
        Self {
            cache_key: Some(cache_key.into()),
            ..Self::default()
        }
    }
}

/// Online function-key provider (JS `AleoKeyProvider`).
///
/// Wraps a [`KeyByteTransport`] with an in-memory cache. `credits.aleo` keys
/// come from the embedded `snarkvm-parameters` (no network); custom program
/// keys are downloaded from arbitrary URLs via the transport.
///
/// ```no_run
/// # use aleo_rust_sdk::keys::{AleoKeyProvider, AleoKeyProviderParams, CreditsFunction};
/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
/// let mut provider = AleoKeyProvider::new()?;
/// provider.use_cache(true);
///
/// // The embedded credits.aleo keys — works offline.
/// let (_pk, _vk) = provider.credits_keys(CreditsFunction::FeePublic)?;
///
/// // Custom program keys from your own key host.
/// let params = AleoKeyProviderParams::remote(
///     "https://keys.example.com/myprogram.aleo/myfunction.prover",
///     "https://keys.example.com/myprogram.aleo/myfunction.verifier",
/// );
/// let _keys = provider.function_keys(params).await?;
/// # Ok(())
/// # }
/// ```
pub struct AleoKeyProvider {
    cache: HashMap<String, FunctionKeyPair>,
    use_cache: bool,
    transport: Box<dyn KeyByteTransport>,
}

impl AleoKeyProvider {
    /// Create a provider backed by [`ReqwestKeyTransport`] (JS `new AleoKeyProvider()`).
    ///
    /// Caching is **off** by default, matching the JS SDK.
    ///
    /// # Errors
    ///
    /// Fails when the shared HTTP client cannot be constructed.
    pub fn new() -> Result<Self> {
        Ok(Self::with_transport(Box::new(ReqwestKeyTransport::new()?)))
    }

    /// Create a provider around a custom [`KeyByteTransport`].
    pub fn with_transport(transport: Box<dyn KeyByteTransport>) -> Self {
        Self {
            cache: HashMap::new(),
            use_cache: false,
            transport,
        }
    }

    /// Turn the in-memory cache on or off (JS `useCache`). Downloads are
    /// cached only while this is `true`.
    pub fn use_cache(&mut self, use_cache: bool) {
        self.use_cache = use_cache;
    }

    /// Drop every cached entry (JS `clearCache`).
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Store keys under `key_id`, overwriting any previous entry
    /// (JS `cacheKeys`). No verification is performed.
    pub fn cache_keys(&mut self, key_id: impl Into<String>, keys: FunctionKeyPair) {
        self.cache.insert(key_id.into(), keys);
    }

    /// Whether `key_id` has a cached entry (JS `containsKeys`).
    pub fn contains_keys(&self, key_id: &str) -> bool {
        self.cache.contains_key(key_id)
    }

    /// Drop a cached entry (JS `deleteKeys`), returning whether it existed.
    pub fn delete_keys(&mut self, key_id: &str) -> bool {
        self.cache.remove(key_id).is_some()
    }

    /// Retrieve cached keys (JS `getKeys`).
    ///
    /// # Errors
    ///
    /// Fails when nothing is cached under `key_id`.
    pub fn get_keys(&self, key_id: &str) -> Result<FunctionKeyPair> {
        self.cache
            .get(key_id)
            .cloned()
            .with_context(|| "Key not found in cache.".to_string())
    }

    /// Get keys according to `params` (JS `functionKeys`).
    ///
    /// Routing, in order (exactly the JS behaviour):
    /// 1. `params.name` → [`AleoKeyProvider::credits_keys`] (JS
    ///    `fetchCreditsKeys`: embedded keys, with cache read/write)
    /// 2. `params.prover_uri` + `params.verifier_uri` →
    ///    [`AleoKeyProvider::fetch_remote_keys`]
    /// 3. `params.cache_key` → [`AleoKeyProvider::get_keys`]
    ///
    /// # Errors
    ///
    /// Fails when no usable parameter combination is present, or the chosen
    /// route fails.
    pub async fn function_keys(
        &mut self,
        params: AleoKeyProviderParams,
    ) -> Result<FunctionKeyPair> {
        if let Some(function) = params.name {
            return self.credits_keys(function);
        }
        if let (Some(prover_uri), Some(verifier_uri)) = (params.prover_uri, params.verifier_uri) {
            return self.fetch_remote_keys(&prover_uri, &verifier_uri, params.cache_key).await;
        }
        if let Some(cache_key) = params.cache_key {
            return self.get_keys(&cache_key);
        }
        anyhow::bail!(
            "Invalid parameters provided, must provide either a cacheKey and/or a proverUrl and a verifierUrl"
        )
    }

    /// Download a proving/verifying key pair (JS `fetchRemoteKeys`).
    ///
    /// While caching is enabled the pair is stored under `cache_key` (or the
    /// prover URL when `cache_key` is `None`) and cache hits skip the
    /// download entirely.
    ///
    /// # Errors
    ///
    /// Fails when either download fails or the bytes do not parse as keys.
    pub async fn fetch_remote_keys(
        &mut self,
        prover_uri: &str,
        verifier_uri: &str,
        cache_key: Option<String>,
    ) -> Result<FunctionKeyPair> {
        let cache_key = cache_key.unwrap_or_else(|| prover_uri.to_string());
        if self.use_cache
            && let Some(keys) = self.cache.get(&cache_key)
        {
            return Ok(keys.clone());
        }
        let proving_key = match self.fetch_proving_key_bytes(prover_uri).await {
            Ok(key) => key,
            Err(error) => anyhow::bail!(
                "Error: {error} fetching fee proving and verifying keys from {prover_uri} and {verifier_uri}."
            ),
        };
        let verifying_key = match self.get_verifying_key(verifier_uri).await {
            Ok(key) => key,
            Err(error) => anyhow::bail!(
                "Error: {error} fetching fee proving and verifying keys from {prover_uri} and {verifier_uri}."
            ),
        };
        let keys = (proving_key, verifying_key);
        if self.use_cache {
            self.cache.insert(cache_key, keys.clone());
        }
        Ok(keys)
    }

    /// Download a proving key (JS `fetchProvingKey`).
    ///
    /// With caching enabled, a cached pair under `cache_key` (or the URL)
    /// short-circuits the download; misses are **not** cached — matching the
    /// JS SDK, which only writes cache entries in `fetchRemoteKeys`.
    ///
    /// # Errors
    ///
    /// Fails when the download fails or the bytes do not parse as a proving key.
    pub async fn fetch_proving_key(
        &self,
        prover_uri: &str,
        cache_key: Option<String>,
    ) -> Result<ProvingKey<TestnetV0>> {
        let cache_key = cache_key.unwrap_or_else(|| prover_uri.to_string());
        if self.use_cache
            && let Some((proving_key, _)) = self.cache.get(&cache_key)
        {
            return Ok(proving_key.clone());
        }
        match self.fetch_proving_key_bytes(prover_uri).await {
            Ok(proving_key) => Ok(proving_key),
            Err(error) => {
                anyhow::bail!("Error: {error} fetching fee proving keys from {prover_uri}")
            }
        }
    }

    /// Download and parse a verifying key from raw key bytes — the byte-level
    /// fallback inside JS `getVerifyingKey`.
    ///
    /// Prefer [`AleoKeyProvider::get_verifying_key`], which additionally
    /// serves the embedded credits verifiers and the text form of a key.
    ///
    /// # Errors
    ///
    /// Fails when the download fails or the bytes do not parse as a verifying key.
    pub async fn fetch_verifying_key(&self, verifier_uri: &str) -> Result<VerifyingKey<TestnetV0>> {
        let bytes = self.transport.fetch_bytes(verifier_uri).await.map_err(|error| {
            anyhow::anyhow!(
                "Error fetching data.{error} fetching verifying key from {verifier_uri}"
            )
        })?;
        VerifyingKey::from_bytes_le(&bytes)
            .with_context(|| format!("Failed to parse verifying key from {verifier_uri}"))
    }

    /// Resolve a verifying key from a URI (JS `getVerifyingKey`).
    ///
    /// Double route, exactly like the JS SDK:
    /// 1. Official `credits.aleo` verifier identifiers (see
    ///    [`CreditsFunction::verifier_identifier`]) return the embedded
    ///    canonical verifying key — no download at all.
    /// 2. Anything else is fetched from `verifier_uri` and parsed as a
    ///    verifying-key string first ([`VerifyingKey::from_str`]), falling
    ///    back to raw key bytes ([`VerifyingKey::from_bytes_le`]) with a
    ///    second fetch, matching the JS retry. When both fail the error is
    ///    `"Invalid verifying key. Error: …"`.
    ///
    /// # Errors
    ///
    /// Fails when neither route yields a verifying key.
    pub async fn get_verifying_key(&self, verifier_uri: &str) -> Result<VerifyingKey<TestnetV0>> {
        if let Some(function) = CreditsFunction::from_verifier_identifier(verifier_uri) {
            return canonical_verifying_key(function);
        }
        // Attempt 1: the text form (JS `VerifyingKey.fromString`).
        if let Ok(bytes) = self.transport.fetch_bytes(verifier_uri).await
            && let Ok(text) = String::from_utf8(bytes)
            && let Ok(verifying_key) = VerifyingKey::from_str(&text)
        {
            return Ok(verifying_key);
        }
        // Attempt 2: raw key bytes (JS `VerifyingKey.fromBytes`).
        self.fetch_verifying_key(verifier_uri)
            .await
            .map_err(|error| anyhow::anyhow!("Invalid verifying key. Error: {error}"))
    }

    /// The embedded `credits.aleo` key pair (JS `fetchCreditsKeys`).
    ///
    /// Keeps the JS cache semantics: with caching enabled, a cached pair
    /// under the function locator short-circuits the load, and fresh pairs
    /// are written back to the cache. (JS downloads the proving key over
    /// HTTP; the native parameters crate embeds it, so this never touches
    /// the network.)
    ///
    /// # Errors
    ///
    /// Fails when the embedded key bytes cannot be loaded or parsed.
    pub fn credits_keys(&mut self, function: CreditsFunction) -> Result<FunctionKeyPair> {
        if self.use_cache
            && let Some(keys) = self.cache.get(function.locator())
        {
            return Ok(keys.clone());
        }
        let keys = canonical_key_pair(function)
            .map_err(|error| anyhow::anyhow!("Error: fetching credits.aleo keys: {error}"))?;
        if self.use_cache {
            self.cache.insert(function.locator().to_string(), keys.clone());
        }
        Ok(keys)
    }

    /// JS `bondPublicKeys()`.
    pub fn bond_public_keys(&mut self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::BondPublic)
    }

    /// JS `bondValidatorKeys()`.
    pub fn bond_validator_keys(&mut self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::BondValidator)
    }

    /// JS `claimUnbondPublicKeys()`.
    pub fn claim_unbond_public_keys(&mut self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::ClaimUnbondPublic)
    }

    /// JS `transferKeys(visibility)` — routes by the visibility alias
    /// strings (see [`CreditsFunction::from_transfer_visibility`]).
    pub fn transfer_keys(&mut self, visibility: &str) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::from_transfer_visibility(visibility)?)
    }

    /// JS `transferPublicKeys()`.
    pub fn transfer_public_keys(&mut self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::TransferPublic)
    }

    /// JS `inclusionKeys()`.
    pub fn inclusion_keys(&mut self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::Inclusion)
    }

    /// JS `joinKeys()`.
    pub fn join_keys(&mut self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::Join)
    }

    /// JS `splitKeys()`.
    pub fn split_keys(&mut self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::Split)
    }

    /// JS `feePrivateKeys()`.
    pub fn fee_private_keys(&mut self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::FeePrivate)
    }

    /// JS `feePublicKeys()`.
    pub fn fee_public_keys(&mut self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::FeePublic)
    }

    /// JS `unBondPublicKeys()`.
    pub fn unbond_public_keys(&mut self) -> Result<FunctionKeyPair> {
        self.credits_keys(CreditsFunction::UnbondPublic)
    }

    /// Install every cached key into `process` — the same semantics as
    /// [`OfflineKeyProvider::install`].
    ///
    /// # Errors
    ///
    /// Fails when a locator is malformed or its program is not loaded in
    /// `process`.
    pub fn install(&self, process: &Process<TestnetV0>) -> Result<usize> {
        let mut installed = 0;
        for (locator, (proving_key, verifying_key)) in &self.cache {
            let Some((program, function)) = locator.split_once('/') else {
                continue;
            };
            let program_id = ProgramID::<TestnetV0>::from_str(program)
                .with_context(|| format!("Invalid program id in locator: {locator}"))?;
            let function_name = Identifier::<TestnetV0>::from_str(function)
                .with_context(|| format!("Invalid function name in locator: {locator}"))?;
            process
                .insert_proving_key(&program_id, &function_name, proving_key.clone())
                .with_context(|| format!("Failed to install proving key for {locator}"))?;
            process
                .insert_verifying_key(&program_id, &function_name, verifying_key.clone())
                .with_context(|| format!("Failed to install verifying key for {locator}"))?;
            installed += 1;
        }
        Ok(installed)
    }

    async fn fetch_proving_key_bytes(&self, prover_uri: &str) -> Result<ProvingKey<TestnetV0>> {
        let bytes = self
            .transport
            .fetch_bytes(prover_uri)
            .await
            .map_err(|error| anyhow::anyhow!("Error fetching data.{error}"))?;
        ProvingKey::from_bytes_le(&bytes)
            .with_context(|| format!("Failed to parse proving key from {prover_uri}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::parameters::testnet::{FeePublicProver, FeePublicVerifier};

    /// The real `credits.aleo/fee_public` pair, loaded from the embedded
    /// parameter cache (the same loader `new_with_fee_keys` uses).
    fn fee_public_pair() -> FunctionKeyPair {
        let proving_key =
            ProvingKey::<TestnetV0>::from_bytes_le(&FeePublicProver::load_bytes().unwrap())
                .unwrap();
        let verifying_key =
            VerifyingKey::<TestnetV0>::from_bytes_le(&FeePublicVerifier::load_bytes().unwrap())
                .unwrap();
        (proving_key, verifying_key)
    }

    /// Locator strings must match the JS SDK's `CREDITS_PROGRAM_KEYS` exactly.
    #[test]
    fn test_locators_match_js_sdk_strings() {
        let expected = [
            "credits.aleo/bond_public",
            "credits.aleo/bond_validator",
            "credits.aleo/claim_unbond_public",
            "credits.aleo/fee_private",
            "credits.aleo/fee_public",
            "inclusion",
            "credits.aleo/join",
            "credits.aleo/set_validator_state",
            "credits.aleo/split",
            "credits.aleo/transfer_private",
            "credits.aleo/transfer_private_to_public",
            "credits.aleo/transfer_public",
            "credits.aleo/transfer_public_as_signer",
            "credits.aleo/transfer_public_to_private",
            "credits.aleo/unbond_public",
        ];
        for (function, locator) in CreditsFunction::ALL.into_iter().zip(expected) {
            assert_eq!(function.locator(), locator);
            assert_eq!(CreditsFunction::from_locator(locator), Some(function));
        }
        assert_eq!(
            CreditsFunction::from_locator("myprogram.aleo/myfunction"),
            None
        );
    }

    /// Every official function carries a parseable checksum pair.
    #[test]
    fn test_expected_checksums_parse_for_all() {
        for function in CreditsFunction::ALL {
            let (prover, verifier) = function.expected_checksums().unwrap();
            for checksum in [prover, verifier] {
                assert_eq!(checksum.len(), 64, "{}", function.locator());
                assert!(
                    checksum.chars().all(|c| c.is_ascii_hexdigit()),
                    "{}",
                    function.locator()
                );
            }
        }
    }

    /// The canonical verifying keys shipped in `snarkvm-parameters` must hash
    /// to the recorded `verifier_checksum` — this pins the checksum logic,
    /// the key byte format, and the metadata together, all offline.
    #[test]
    fn test_canonical_verifiers_match_metadata_checksums() {
        for function in CreditsFunction::ALL {
            let verifying_key = canonical_verifying_key(function).unwrap();
            let (_, verifier_checksum) = function.expected_checksums().unwrap();
            assert!(
                checksum_matches(&verifier_checksum, &verifying_key),
                "verifier checksum mismatch for {}",
                function.locator()
            );
        }
    }

    /// Full positive path on the real fee_public keys, plus rejection cases.
    #[test]
    fn test_verify_credits_keys_accepts_and_rejects() {
        let (proving_key, verifying_key) = fee_public_pair();
        assert!(OfflineKeyProvider::verify_credits_keys(
            "credits.aleo/fee_public",
            &proving_key,
            &verifying_key
        ));

        // Real keys under the wrong function's locator must fail.
        assert!(!OfflineKeyProvider::verify_credits_keys(
            "credits.aleo/join",
            &proving_key,
            &verifying_key
        ));
        // Unknown locators have no official checksums.
        assert!(!OfflineKeyProvider::verify_credits_keys(
            "myprogram.aleo/myfunction",
            &proving_key,
            &verifying_key
        ));
    }

    /// JS `insert*Keys` parity: verifying key is attached automatically and
    /// the pair round-trips through `credits_keys` with verification on.
    #[test]
    fn test_insert_credits_key_attaches_canonical_verifier() {
        let (proving_key, verifying_key) = fee_public_pair();
        let mut provider = OfflineKeyProvider::new();
        provider
            .insert_credits_key(CreditsFunction::FeePublic, proving_key.clone())
            .unwrap();

        let (cached_pk, cached_vk) = provider.credits_keys(CreditsFunction::FeePublic).unwrap();
        assert_eq!(
            cached_pk.to_bytes_le().unwrap(),
            proving_key.to_bytes_le().unwrap()
        );
        assert_eq!(
            cached_vk.to_bytes_le().unwrap(),
            verifying_key.to_bytes_le().unwrap()
        );
        assert!(provider.contains_keys("credits.aleo/fee_public"));
    }

    /// A real key inserted for the *wrong* function must be rejected
    /// (JS: "Attempted to insert invalid proving keys for …").
    #[test]
    fn test_insert_credits_key_rejects_wrong_function() {
        let (proving_key, _) = fee_public_pair();
        let mut provider = OfflineKeyProvider::new();
        let err = provider.insert_credits_key(CreditsFunction::Join, proving_key).unwrap_err();
        assert!(
            err.to_string().contains("invalid proving keys for join"),
            "{err}"
        );
        assert!(!provider.contains_keys("credits.aleo/join"));
    }

    /// Custom-program keys have no official checksums: cache_keys stores them
    /// unverified, and the verify flag on `function_keys` rejects them.
    #[test]
    fn test_cache_roundtrip_and_function_keys_verify() {
        let keys = fee_public_pair();
        let mut provider = OfflineKeyProvider::new();
        provider.cache_keys("myprogram.aleo/myfunction", keys.clone());
        assert!(provider.contains_keys("myprogram.aleo/myfunction"));

        let (pk, vk) = provider.function_keys("myprogram.aleo/myfunction", false).unwrap();
        assert_eq!(pk.to_bytes_le().unwrap(), keys.0.to_bytes_le().unwrap());
        assert_eq!(vk.to_bytes_le().unwrap(), keys.1.to_bytes_le().unwrap());

        // Verification against official checksums must reject custom locators.
        let err = provider.function_keys("myprogram.aleo/myfunction", true).unwrap_err();
        assert!(
            err.to_string().contains("do not match expected keys"),
            "{err}"
        );

        // Missing entries fail with the JS error string.
        let err = provider.function_keys("credits.aleo/split", false).unwrap_err();
        assert!(
            err.to_string().contains("Keys not found in cache for credits.aleo/split"),
            "{err}"
        );

        assert!(provider.remove_keys("myprogram.aleo/myfunction").is_some());
        assert!(!provider.contains_keys("myprogram.aleo/myfunction"));
    }

    /// `install` loads cached keys into a process so proving skips synthesis;
    /// the bare "inclusion" locator is skipped (protocol built-in key).
    #[test]
    fn test_install_loads_keys_into_process() {
        let (proving_key, verifying_key) = fee_public_pair();
        let mut provider = OfflineKeyProvider::new();
        // Park the fee pair under an unrelated slot — install does not
        // verify, it only loads what the cache holds.
        provider.cache_keys(
            "credits.aleo/join",
            (proving_key.clone(), verifying_key.clone()),
        );
        provider.cache_keys("inclusion", (proving_key.clone(), verifying_key.clone()));

        let process = Process::<TestnetV0>::load().unwrap();
        assert_eq!(provider.install(&process).unwrap(), 1);

        // The installed key must be returned instead of synthesizing join.
        let installed = process.get_proving_key("credits.aleo", "join").unwrap();
        assert_eq!(
            installed.to_bytes_le().unwrap(),
            proving_key.to_bytes_le().unwrap()
        );
    }

    /// Malformed and unknown-program locators surface as install errors.
    #[test]
    fn test_install_error_paths() {
        let keys = fee_public_pair();
        let mut provider = OfflineKeyProvider::new();
        provider.cache_keys("myprogram.aleo/myfunction", keys.clone());
        let process = Process::<TestnetV0>::load().unwrap();
        let err = provider.install(&process).unwrap_err();
        assert!(
            err.to_string().contains("Failed to install proving key for myprogram.aleo"),
            "{err}"
        );

        let mut provider = OfflineKeyProvider::new();
        provider.cache_keys("not a program/function", keys);
        let err = provider.install(&process).unwrap_err();
        assert!(
            err.to_string().contains("Invalid program id in locator"),
            "{err}"
        );
    }

    /// JS `transferKeys(visibility)` alias strings map to the right function.
    #[test]
    fn test_transfer_visibility_aliases() {
        let cases = [
            ("private", CreditsFunction::TransferPrivate),
            ("transfer_private", CreditsFunction::TransferPrivate),
            ("transferPrivate", CreditsFunction::TransferPrivate),
            (
                "private_to_public",
                CreditsFunction::TransferPrivateToPublic,
            ),
            ("privateToPublic", CreditsFunction::TransferPrivateToPublic),
            (
                "transfer_private_to_public",
                CreditsFunction::TransferPrivateToPublic,
            ),
            (
                "transferPrivateToPublic",
                CreditsFunction::TransferPrivateToPublic,
            ),
            ("public", CreditsFunction::TransferPublic),
            ("transfer_public", CreditsFunction::TransferPublic),
            ("transferPublic", CreditsFunction::TransferPublic),
            ("public_as_signer", CreditsFunction::TransferPublicAsSigner),
            (
                "transfer_public_as_signer",
                CreditsFunction::TransferPublicAsSigner,
            ),
            (
                "transferPublicAsSigner",
                CreditsFunction::TransferPublicAsSigner,
            ),
            (
                "public_to_private",
                CreditsFunction::TransferPublicToPrivate,
            ),
            ("publicToPrivate", CreditsFunction::TransferPublicToPrivate),
            (
                "transfer_public_to_private",
                CreditsFunction::TransferPublicToPrivate,
            ),
            (
                "transferPublicToPrivate",
                CreditsFunction::TransferPublicToPrivate,
            ),
        ];
        for (visibility, expected) in cases {
            assert_eq!(
                CreditsFunction::from_transfer_visibility(visibility).unwrap(),
                expected,
                "{visibility}"
            );
        }
        let err = CreditsFunction::from_transfer_visibility("bogus").unwrap_err();
        assert!(err.to_string().contains("Invalid visibility type"), "{err}");
    }

    /// The JS `verifier` identifier is `"{name}.verifier.{prover_checksum[..7]}"` —
    /// the suffix is the **prover** checksum prefix, because the wasm
    /// `Metadata` builder always reads `prover_checksum`. The fee_public
    /// literal pins the format; the roundtrip covers every function.
    #[test]
    fn test_verifier_identifier_matches_js_metadata_format() {
        assert_eq!(
            CreditsFunction::FeePublic.verifier_identifier().unwrap(),
            "fee_public.verifier.f72b6ff"
        );
        for function in CreditsFunction::ALL {
            let identifier = function.verifier_identifier().unwrap();
            assert_eq!(
                CreditsFunction::from_verifier_identifier(&identifier),
                Some(function),
                "{identifier}"
            );
        }
        assert_eq!(
            CreditsFunction::from_verifier_identifier("fee_public.verifier.deadbee"),
            None
        );
        assert_eq!(
            CreditsFunction::from_verifier_identifier("https://keys.example.com/hello.verifier"),
            None
        );
    }

    /// Every JS `*Keys()` convenience getter routes to its own cache slot:
    /// on an empty cache the error names the exact locator.
    #[test]
    fn test_offline_convenience_methods_route_to_locators() {
        type Getter = fn(&OfflineKeyProvider) -> Result<FunctionKeyPair>;
        let provider = OfflineKeyProvider::new();
        let cases: [(Getter, &str); 9] = [
            (
                OfflineKeyProvider::bond_public_keys,
                "credits.aleo/bond_public",
            ),
            (
                OfflineKeyProvider::bond_validator_keys,
                "credits.aleo/bond_validator",
            ),
            (
                OfflineKeyProvider::claim_unbond_public_keys,
                "credits.aleo/claim_unbond_public",
            ),
            (
                OfflineKeyProvider::fee_private_keys,
                "credits.aleo/fee_private",
            ),
            (
                OfflineKeyProvider::fee_public_keys,
                "credits.aleo/fee_public",
            ),
            (OfflineKeyProvider::inclusion_keys, "inclusion"),
            (OfflineKeyProvider::join_keys, "credits.aleo/join"),
            (OfflineKeyProvider::split_keys, "credits.aleo/split"),
            (
                OfflineKeyProvider::unbond_public_keys,
                "credits.aleo/unbond_public",
            ),
        ];
        for (method, locator) in cases {
            let error = method(&provider).unwrap_err().to_string();
            assert!(
                error.contains(&format!("Keys not found in cache for {locator}")),
                "{locator}: {error}"
            );
        }
        // transferKeys(visibility) routes by alias to the transfer slots.
        for (visibility, locator) in [
            ("private", "credits.aleo/transfer_private"),
            (
                "private_to_public",
                "credits.aleo/transfer_private_to_public",
            ),
            ("public", "credits.aleo/transfer_public"),
            ("public_as_signer", "credits.aleo/transfer_public_as_signer"),
            (
                "public_to_private",
                "credits.aleo/transfer_public_to_private",
            ),
        ] {
            let error = provider.transfer_keys(visibility).unwrap_err().to_string();
            assert!(
                error.contains(&format!("Keys not found in cache for {locator}")),
                "{visibility}: {error}"
            );
        }
        assert!(
            provider
                .transfer_keys("bogus")
                .unwrap_err()
                .to_string()
                .contains("Invalid visibility type")
        );
    }

    /// A cached real pair satisfies the convenience getters end to end
    /// (JS `feePublicKeys()` on `OfflineKeyProvider`).
    #[test]
    fn test_offline_convenience_positive_path() {
        let (proving_key, _) = fee_public_pair();
        let mut provider = OfflineKeyProvider::new();
        provider.insert_credits_key(CreditsFunction::FeePublic, proving_key).unwrap();
        let keys = provider.fee_public_keys().unwrap();
        assert!(checksum_matches(
            &CreditsFunction::FeePublic.expected_checksums().unwrap().0,
            &keys.0
        ));
    }

    // ------------------------------------------------------------------
    // AleoKeyProvider (online provider) — all offline via MockTransport.
    // ------------------------------------------------------------------

    use std::sync::{Arc, Mutex};

    /// Scripted [`KeyByteTransport`] that records every requested URL.
    struct MockTransport {
        responses: HashMap<String, std::result::Result<Vec<u8>, String>>,
        hits: Arc<Mutex<Vec<String>>>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                responses: HashMap::new(),
                hits: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn serving(mut self, url: &str, bytes: std::result::Result<Vec<u8>, String>) -> Self {
            self.responses.insert(url.to_string(), bytes);
            self
        }

        /// Shareable handle to the request log, for assertions after the
        /// transport has been boxed into a provider.
        fn hits_handle(&self) -> Arc<Mutex<Vec<String>>> {
            Arc::clone(&self.hits)
        }
    }

    fn hit_count(hits: &Arc<Mutex<Vec<String>>>, url: &str) -> usize {
        hits.lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|hit| *hit == url)
            .count()
    }

    #[async_trait]
    impl KeyByteTransport for MockTransport {
        async fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>> {
            self.hits.lock().unwrap_or_else(|e| e.into_inner()).push(url.to_string());
            match self.responses.get(url) {
                Some(Ok(bytes)) => Ok(bytes.clone()),
                Some(Err(message)) => anyhow::bail!(message.clone()),
                None => anyhow::bail!("unexpected url {url}"),
            }
        }
    }

    const PROVER_URL: &str = "https://keys.example.com/myprogram.aleo/hello.prover";
    const VERIFIER_URL: &str = "https://keys.example.com/myprogram.aleo/hello.verifier";

    /// The real `fee_public` parameter bytes, used as stand-in "downloads".
    fn fee_public_prover_bytes() -> Vec<u8> {
        FeePublicProver::load_bytes().unwrap()
    }

    fn fee_public_verifier_bytes() -> Vec<u8> {
        FeePublicVerifier::load_bytes().unwrap()
    }

    fn mock_with_fee_public_keys() -> MockTransport {
        MockTransport::new()
            .serving(PROVER_URL, Ok(fee_public_prover_bytes()))
            .serving(VERIFIER_URL, Ok(fee_public_verifier_bytes()))
    }

    /// The freshly extracted loader must agree with the metadata checksums.
    #[test]
    fn test_canonical_key_pair_matches_metadata_checksums() {
        let (proving_key, verifying_key) = canonical_key_pair(CreditsFunction::FeePublic).unwrap();
        let (prover_checksum, verifier_checksum) =
            CreditsFunction::FeePublic.expected_checksums().unwrap();
        assert!(checksum_matches(&prover_checksum, &proving_key));
        assert!(checksum_matches(&verifier_checksum, &verifying_key));
    }

    /// `params.name` routes to the embedded credits keys (JS fetchCreditsKeys).
    #[tokio::test]
    async fn test_function_keys_routes_name_to_embedded_keys() {
        let mut provider = AleoKeyProvider::with_transport(Box::new(MockTransport::new()));
        let keys = provider
            .function_keys(AleoKeyProviderParams::credits(CreditsFunction::FeePublic))
            .await
            .unwrap();
        let expected = canonical_key_pair(CreditsFunction::FeePublic).unwrap();
        assert_eq!(
            key_checksum(&keys.0).unwrap(),
            key_checksum(&expected.0).unwrap()
        );
        assert_eq!(
            key_checksum(&keys.1).unwrap(),
            key_checksum(&expected.1).unwrap()
        );
    }

    /// `prover_uri` + `verifier_uri` route to the transport.
    #[tokio::test]
    async fn test_function_keys_routes_uris_to_transport() {
        let transport = mock_with_fee_public_keys();
        let mut provider = AleoKeyProvider::with_transport(Box::new(transport));
        let keys = provider
            .function_keys(AleoKeyProviderParams::remote(PROVER_URL, VERIFIER_URL))
            .await
            .unwrap();
        assert!(checksum_matches(
            &CreditsFunction::FeePublic.expected_checksums().unwrap().0,
            &keys.0
        ));
    }

    /// `cache_key` alone reads from the cache.
    #[tokio::test]
    async fn test_function_keys_routes_cache_key() {
        let mut provider = AleoKeyProvider::with_transport(Box::new(MockTransport::new()));
        let pair = fee_public_pair();
        provider.cache_keys("myprogram.aleo/hello", pair.clone());
        let keys = provider
            .function_keys(AleoKeyProviderParams::cached("myprogram.aleo/hello"))
            .await
            .unwrap();
        assert_eq!(
            key_checksum(&keys.0).unwrap(),
            key_checksum(&pair.0).unwrap()
        );
    }

    /// Empty params reproduce the JS error message.
    #[tokio::test]
    async fn test_function_keys_invalid_params() {
        let mut provider = AleoKeyProvider::with_transport(Box::new(MockTransport::new()));
        let err = provider
            .function_keys(AleoKeyProviderParams::default())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("Invalid parameters provided"), "{err}");
    }

    /// With caching on, a second fetch is served from the cache.
    #[tokio::test]
    async fn test_fetch_remote_keys_caches_and_dedupes() {
        let transport = mock_with_fee_public_keys();
        let hits = transport.hits_handle();
        let mut provider = AleoKeyProvider::with_transport(Box::new(transport));
        provider.use_cache(true);

        let first = provider
            .fetch_remote_keys(PROVER_URL, VERIFIER_URL, Some("my-key".to_string()))
            .await
            .unwrap();
        let second = provider
            .fetch_remote_keys(PROVER_URL, VERIFIER_URL, Some("my-key".to_string()))
            .await
            .unwrap();
        assert_eq!(
            key_checksum(&first.0).unwrap(),
            key_checksum(&second.0).unwrap()
        );
        assert_eq!(hit_count(&hits, PROVER_URL), 1);
        // The verifier half goes through `get_verifying_key`, which — like
        // the JS SDK — tries the text form first and re-fetches for the raw
        // byte fallback: two requests on the first call, none on the second.
        assert_eq!(hit_count(&hits, VERIFIER_URL), 2);
    }

    /// Without an explicit cache key the prover URL becomes the key (JS).
    #[tokio::test]
    async fn test_fetch_remote_keys_default_cache_key() {
        let transport = mock_with_fee_public_keys();
        let mut provider = AleoKeyProvider::with_transport(Box::new(transport));
        provider.use_cache(true);
        provider.fetch_remote_keys(PROVER_URL, VERIFIER_URL, None).await.unwrap();
        assert!(provider.contains_keys(PROVER_URL));
    }

    /// With caching off nothing is stored and every call downloads.
    #[tokio::test]
    async fn test_fetch_remote_keys_no_cache() {
        let transport = mock_with_fee_public_keys();
        let hits = transport.hits_handle();
        let mut provider = AleoKeyProvider::with_transport(Box::new(transport));
        provider.fetch_remote_keys(PROVER_URL, VERIFIER_URL, None).await.unwrap();
        provider.fetch_remote_keys(PROVER_URL, VERIFIER_URL, None).await.unwrap();
        assert_eq!(hit_count(&hits, PROVER_URL), 2);
        assert!(!provider.contains_keys(PROVER_URL));
    }

    /// `fetch_proving_key` reads cached hits but never writes (JS semantics).
    #[tokio::test]
    async fn test_fetch_proving_key_reads_cache_without_writing() {
        let transport = mock_with_fee_public_keys();
        let hits = transport.hits_handle();
        let mut provider = AleoKeyProvider::with_transport(Box::new(transport));
        provider.use_cache(true);

        // Cache miss: downloads, but does not store.
        let key = provider.fetch_proving_key(PROVER_URL, None).await.unwrap();
        assert_eq!(hit_count(&hits, PROVER_URL), 1);
        assert!(!provider.contains_keys(PROVER_URL));

        // Seed the cache; the next call must not download.
        provider.cache_keys(PROVER_URL, (key.clone(), fee_public_pair().1));
        let again = provider.fetch_proving_key(PROVER_URL, None).await.unwrap();
        assert_eq!(key_checksum(&key).unwrap(), key_checksum(&again).unwrap());
        assert_eq!(hit_count(&hits, PROVER_URL), 1);
    }

    /// Verifying keys parse from bytes; garbage is rejected with context.
    #[tokio::test]
    async fn test_fetch_verifying_key_and_bad_bytes() {
        let transport = MockTransport::new()
            .serving(VERIFIER_URL, Ok(fee_public_verifier_bytes()))
            .serving("https://bad.example/vk", Ok(vec![0u8, 1, 2]))
            .serving("https://err.example/vk", Err("boom".to_string()));
        let provider = AleoKeyProvider::with_transport(Box::new(transport));

        let key = provider.fetch_verifying_key(VERIFIER_URL).await.unwrap();
        assert!(checksum_matches(
            &CreditsFunction::FeePublic.expected_checksums().unwrap().1,
            &key
        ));

        let err = provider
            .fetch_verifying_key("https://bad.example/vk")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("Failed to parse verifying key"), "{err}");

        let err = provider
            .fetch_verifying_key("https://err.example/vk")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("Error fetching data.boom"), "{err}");
    }

    /// JS `fetchCreditsKeys` cache semantics on `credits_keys`: hits return
    /// the cached pair, misses load the embedded pair and write back only
    /// while caching is on.
    #[test]
    fn test_credits_keys_cache_semantics() {
        let mut provider = AleoKeyProvider::with_transport(Box::new(MockTransport::new()));
        provider.use_cache(true);

        // Miss: loads the embedded pair and writes it back.
        let keys = provider.credits_keys(CreditsFunction::FeePublic).unwrap();
        assert!(provider.contains_keys("credits.aleo/fee_public"));
        assert!(checksum_matches(
            &CreditsFunction::FeePublic.expected_checksums().unwrap().0,
            &keys.0
        ));

        // Hit: the cached pair comes back unchanged.
        let again = provider.credits_keys(CreditsFunction::FeePublic).unwrap();
        assert_eq!(
            key_checksum(&keys.0).unwrap(),
            key_checksum(&again.0).unwrap()
        );
        assert_eq!(
            key_checksum(&keys.1).unwrap(),
            key_checksum(&again.1).unwrap()
        );

        // Caching off: nothing is written back.
        provider.use_cache(false);
        provider.clear_cache();
        let _ = provider.credits_keys(CreditsFunction::FeePublic).unwrap();
        assert!(!provider.contains_keys("credits.aleo/fee_public"));
    }

    /// The 11 JS `*Keys()` convenience getters each read their own cache
    /// slot: every locator is pre-seeded with a distinct verifying key, and
    /// the returned one identifies which slot was read.
    #[test]
    fn test_aleo_convenience_methods_route_to_locators() {
        let mut provider = AleoKeyProvider::with_transport(Box::new(MockTransport::new()));
        provider.use_cache(true);
        let proving_key = fee_public_pair().0;
        for function in CreditsFunction::ALL {
            let verifying_key = canonical_verifying_key(function).unwrap();
            provider.cache_keys(function.locator(), (proving_key.clone(), verifying_key));
        }

        fn assert_routed(keys: Result<FunctionKeyPair>, function: CreditsFunction) {
            let keys = keys.unwrap();
            let expected = canonical_verifying_key(function).unwrap();
            assert_eq!(
                key_checksum(&keys.1).unwrap(),
                key_checksum(&expected).unwrap(),
                "{}",
                function.locator()
            );
        }

        assert_routed(provider.bond_public_keys(), CreditsFunction::BondPublic);
        assert_routed(
            provider.bond_validator_keys(),
            CreditsFunction::BondValidator,
        );
        assert_routed(
            provider.claim_unbond_public_keys(),
            CreditsFunction::ClaimUnbondPublic,
        );
        assert_routed(
            provider.transfer_keys("private"),
            CreditsFunction::TransferPrivate,
        );
        assert_routed(
            provider.transfer_keys("private_to_public"),
            CreditsFunction::TransferPrivateToPublic,
        );
        assert_routed(
            provider.transfer_keys("public"),
            CreditsFunction::TransferPublic,
        );
        assert_routed(
            provider.transfer_keys("public_as_signer"),
            CreditsFunction::TransferPublicAsSigner,
        );
        assert_routed(
            provider.transfer_keys("public_to_private"),
            CreditsFunction::TransferPublicToPrivate,
        );
        assert_routed(
            provider.transfer_public_keys(),
            CreditsFunction::TransferPublic,
        );
        assert_routed(provider.inclusion_keys(), CreditsFunction::Inclusion);
        assert_routed(provider.join_keys(), CreditsFunction::Join);
        assert_routed(provider.split_keys(), CreditsFunction::Split);
        assert_routed(provider.fee_private_keys(), CreditsFunction::FeePrivate);
        assert_routed(provider.fee_public_keys(), CreditsFunction::FeePublic);
        assert_routed(provider.unbond_public_keys(), CreditsFunction::UnbondPublic);
    }

    /// `get_verifying_key` serves the embedded canonical verifier for every
    /// official credits identifier without touching the transport
    /// (the JS `getVerifyingKey` switch).
    #[tokio::test]
    async fn test_get_verifying_key_routes_credits_identifiers() {
        let transport = MockTransport::new();
        let hits = transport.hits_handle();
        let provider = AleoKeyProvider::with_transport(Box::new(transport));
        for function in CreditsFunction::ALL {
            let identifier = function.verifier_identifier().unwrap();
            let key = provider.get_verifying_key(&identifier).await.unwrap();
            let (_, verifier_checksum) = function.expected_checksums().unwrap();
            assert!(checksum_matches(&verifier_checksum, &key), "{identifier}");
        }
        assert!(hits.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
    }

    /// Custom verifier URIs parse as a verifying-key string first, then fall
    /// back to raw key bytes with a second fetch (JS `getVerifyingKey`); both
    /// failing forms surface as `"Invalid verifying key. Error: …"`.
    #[tokio::test]
    async fn test_get_verifying_key_text_then_bytes_fallback() {
        let (_, verifier_checksum) = CreditsFunction::FeePublic.expected_checksums().unwrap();
        let verifying_key = fee_public_pair().1;
        let text_url = "https://keys.example.com/hello.verifier.text";
        let bytes_url = "https://keys.example.com/hello.verifier.bytes";
        let bad_url = "https://keys.example.com/hello.verifier.bad";
        let err_url = "https://keys.example.com/hello.verifier.err";
        let raw_bytes = fee_public_verifier_bytes();
        // Precondition: the raw bytes cannot take the text route.
        assert!(String::from_utf8(raw_bytes.clone()).is_err());
        let transport = MockTransport::new()
            .serving(text_url, Ok(verifying_key.to_string().into_bytes()))
            .serving(bytes_url, Ok(raw_bytes))
            .serving(bad_url, Ok(vec![0xFF, 0xFF, 0xFF]))
            .serving(err_url, Err("boom".to_string()));
        let hits = transport.hits_handle();
        let provider = AleoKeyProvider::with_transport(Box::new(transport));

        // The bech32m text form parses on the first attempt.
        let key = provider.get_verifying_key(text_url).await.unwrap();
        assert!(checksum_matches(&verifier_checksum, &key));
        assert_eq!(hit_count(&hits, text_url), 1);

        // Raw bytes: the text attempt fails, the byte fallback re-fetches.
        let key = provider.get_verifying_key(bytes_url).await.unwrap();
        assert!(checksum_matches(&verifier_checksum, &key));
        assert_eq!(hit_count(&hits, bytes_url), 2);

        // Neither form parses.
        let error = provider.get_verifying_key(bad_url).await.unwrap_err().to_string();
        assert!(error.contains("Invalid verifying key. Error:"), "{error}");
        assert_eq!(hit_count(&hits, bad_url), 2);

        // The transport itself failing is wrapped the same way.
        let error = provider.get_verifying_key(err_url).await.unwrap_err().to_string();
        assert!(error.contains("Invalid verifying key. Error:"), "{error}");
        assert!(error.contains("boom"), "{error}");
    }

    /// `fetch_remote_keys` resolves the verifier half through
    /// `get_verifying_key`, so a credits verifier identifier needs no
    /// download (JS `fetchRemoteKeys`).
    #[tokio::test]
    async fn test_fetch_remote_keys_verifier_half_uses_get_verifying_key() {
        let identifier = CreditsFunction::FeePublic.verifier_identifier().unwrap();
        let transport = MockTransport::new().serving(PROVER_URL, Ok(fee_public_prover_bytes()));
        let hits = transport.hits_handle();
        let mut provider = AleoKeyProvider::with_transport(Box::new(transport));

        let keys = provider.fetch_remote_keys(PROVER_URL, &identifier, None).await.unwrap();
        assert!(checksum_matches(
            &CreditsFunction::FeePublic.expected_checksums().unwrap().1,
            &keys.1
        ));
        assert_eq!(hit_count(&hits, PROVER_URL), 1);
        // MockTransport errors on unserved URLs, so zero hits on the
        // identifier proves the embedded route was taken.
        assert_eq!(hit_count(&hits, &identifier), 0);
    }

    /// Transport failures are wrapped with the JS error shape and the URL.
    #[tokio::test]
    async fn test_fetch_error_wraps_url() {
        let transport = MockTransport::new().serving(PROVER_URL, Err("offline".to_string()));
        let mut provider = AleoKeyProvider::with_transport(Box::new(transport));
        let err = provider
            .fetch_remote_keys(PROVER_URL, VERIFIER_URL, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("fetching fee proving and verifying keys"),
            "{err}"
        );
        assert!(err.contains(PROVER_URL), "{err}");

        let err = provider.fetch_proving_key(PROVER_URL, None).await.unwrap_err().to_string();
        assert!(err.contains("fetching fee proving keys"), "{err}");
    }

    /// Cache management mirrors the JS `deleteKeys` / `clearCache` surface.
    #[test]
    fn test_delete_keys_and_clear_cache() {
        let mut provider = AleoKeyProvider::with_transport(Box::new(MockTransport::new()));
        provider.cache_keys("a", fee_public_pair());
        assert!(provider.contains_keys("a"));
        assert!(provider.delete_keys("a"));
        assert!(!provider.delete_keys("a"));
        provider.cache_keys("b", fee_public_pair());
        provider.clear_cache();
        assert!(!provider.contains_keys("b"));
        assert!(
            provider
                .get_keys("b")
                .unwrap_err()
                .to_string()
                .contains("Key not found in cache.")
        );
    }

    /// Cached entries install into a Process exactly like the offline provider.
    #[test]
    fn test_online_provider_install() {
        let mut provider = AleoKeyProvider::with_transport(Box::new(MockTransport::new()));
        let pair = fee_public_pair();
        provider.cache_keys("credits.aleo/fee_public", pair.clone());

        let process = Process::<TestnetV0>::load().unwrap();
        let installed = provider.install(&process).unwrap();
        assert_eq!(installed, 1);

        // The installed key is returned directly — no synthesis involved.
        let stored = process.get_proving_key("credits.aleo", "fee_public").unwrap();
        assert_eq!(stored.to_bytes_le().unwrap(), pair.0.to_bytes_le().unwrap());
    }

    /// The default HTTP transport constructs without panicking.
    #[test]
    fn test_reqwest_transport_constructs() {
        assert!(ReqwestKeyTransport::new().is_ok());
        assert!(AleoKeyProvider::new().is_ok());
    }
}
