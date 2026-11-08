//! # Offline key provider — function keys loaded from local storage.
//!
//! This is the Rust counterpart of the JS SDK's `OfflineKeyProvider`: a key
//! cache for devices that **cannot contact the internet** for key material
//! (hardware wallets, air-gapped machines). The user inserts Aleo function
//! proving and verifying keys from local storage; transaction building then
//! reads them from here instead of synthesizing circuits on the fly.
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
//! - JS exposes 15 `insert*Keys()` / `*Keys()` methods and 15
//!   `OfflineSearchParams.*Params()` constructors. Rust models the same set
//!   as the [`CreditsFunction`] enum: `insert_credits_key(function, pk)`
//!   replaces `insert*Keys(pk)`, `credits_keys(function)` replaces the
//!   getters, and `CreditsFunction::from_transfer_visibility` covers
//!   `transferKeys(visibility)`'s alias strings.
//! - JS caches raw key bytes; this cache holds the typed
//!   [`ProvingKey`] / [`VerifyingKey`] pair. The
//!   serialization is identical either way.
//! - The JS SDK feeds cached keys into the prover explicitly. Native snarkVM
//!   proves the inclusion (state-path) circuit with the protocol built-in
//!   `TestnetV0::inclusion_proving_key()`, so there is nothing to install:
//!   [`OfflineKeyProvider::install`] skips the `"inclusion"` locator. The
//!   entry can still be cached and checksum-verified for parity.

use anyhow::{Context, Result};
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
fn key_checksum(key: &impl ToBytes) -> Result<String> {
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
}
