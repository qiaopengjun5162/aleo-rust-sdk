//! JS SDK `Metadata` parity.
//!
//! The JS `Metadata` class is a static catalogue of per-function parameter
//! download URLs for the credits program. Each entry pairs a function name with
//! the URLs of its prover and verifier parameter files (hosted on Provable's
//! parameter CDN), the program locator, and the rust identifier name of the
//! verifier type.
//!
//! The backing checksums live in [`snarkvm_parameters::testnet`] — the same
//! crate the JS wasm build pulls them from — so the URLs are byte-identical to
//! upstream for snarkVM 4.12.0 / testnet.
//!
//! ## The `verifier` URL is missing its base
//!
//! `Metadata::new` builds the two URLs like this:
//!
//! ```text
//! prover   = BASE_URL            + "<func>.prover.<checksum7>"
//! verifier = /* nothing here */  + "<func>.verifier.<checksum7>"
//! ```
//!
//! The prover URL gets `BASE_URL` prepended; the verifier URL does not. This is
//! not a transcription error in this file — it is copied verbatim from the wasm
//! source (`wasm/src/programs/verifying_key/metadata.rs`), where `verifier` is
//! `url(name, "verifier", verifier)` with no `BASE_URL` in front of it. So the
//! `verifier` field is a relative path, not an absolute URL, while `prover` is
//! absolute. Both are reproduced as-is; do not "fix" the asymmetry unless you
//! also want to diverge from what the JS SDK emits.
//!
//! ## The checksum comes from the `prover_checksum` field only
//!
//! `url()` parses the metadata JSON and reads exactly one field:
//! `prover_checksum`. It does this for *both* URLs — even the verifier URL is
//! built from the `prover_checksum` of the verifier type's metadata. And because
//! the verifier type's `METADATA` is the very same `.metadata` JSON as the
//! prover type's `METADATA` (the `impl_local!` / `impl_remote!` macros both
//! point at `<func>.metadata`), the two URLs of a function share the same 7-char
//! checksum prefix; only the `prover` / `verifier` label differs.

use serde_json::Value;
use snarkvm_parameters::testnet::{
    BondPublicProver, BondPublicVerifier, BondValidatorProver, BondValidatorVerifier,
    ClaimUnbondPublicProver, ClaimUnbondPublicVerifier, FeePrivateProver, FeePrivateVerifier,
    FeePublicProver, FeePublicVerifier, InclusionProver, InclusionVerifier, JoinProver,
    JoinVerifier, SetValidatorStateProver, SetValidatorStateVerifier, SplitProver, SplitVerifier,
    TransferPrivateProver, TransferPrivateToPublicProver, TransferPrivateToPublicVerifier,
    TransferPrivateVerifier, TransferPublicAsSignerProver, TransferPublicAsSignerVerifier,
    TransferPublicProver, TransferPublicToPrivateProver, TransferPublicToPrivateVerifier,
    TransferPublicVerifier, UnbondPublicProver, UnbondPublicVerifier,
};

/// The per-network parameter CDN base. The JS SDK selects it by feature flag
/// (`testnet` → `https://parameters.provable.com/testnet/`, `mainnet` → the
/// `mainnet` equivalent). This crate targets `TestnetV0`, so the testnet base is
/// the only one that applies.
pub const BASE_URL: &str = "https://parameters.provable.com/testnet/";

/// A single entry in the parameter catalogue: the URLs of a credits function's
/// prover and verifier parameter files, its program locator, and the rust
/// identifier name of the verifier type.
///
/// Mirrors the JS `Metadata` struct field-for-field. Every field is a plain
/// string — there is no richer type hiding behind it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    /// The function name, e.g. `"transfer_public"`.
    pub name: String,
    /// The program locator, e.g. `"credits.aleo/transfer_public"`.
    /// The exception is `inclusion`, whose locator is just `"inclusion"`.
    pub locator: String,
    /// The absolute prover parameter URL: `BASE_URL + "<func>.prover.<checksum7>"`.
    pub prover: String,
    /// The *relative* verifier parameter path: `"<func>.verifier.<checksum7>"`
    /// — note the missing `BASE_URL` (see the module docs).
    pub verifier: String,
    /// The rust identifier name of the verifier type, e.g. `"transferPublicVerifier"`.
    /// Not a URL, not a checksum — just the symbol name.
    pub verifying_key: String,
}

impl Metadata {
    /// Read the 7-character checksum prefix out of a `Xxx::METADATA` JSON string,
    /// exactly as the JS `Metadata::new` does. Only the `prover_checksum` field
    /// is ever read, for both URLs.
    fn checksum_prefix(metadata: &'static str) -> String {
        let metadata: Value =
            serde_json::from_str(metadata).expect("parameter metadata was not well-formatted");
        metadata["prover_checksum"]
            .as_str()
            .expect("failed to parse prover_checksum")
            .get(0..7)
            .expect("prover_checksum is shorter than 7 chars")
            .to_string()
    }

    /// Build one catalogue entry. This is the Rust twin of the wasm
    /// `Metadata::new`; the `verifier` argument is intentionally *not* prefixed
    /// with [`BASE_URL`], reproducing the upstream asymmetry.
    fn new(
        name: &str,
        verifying_key: &str,
        locator: &str,
        prover_metadata: &'static str,
        verifier_metadata: &'static str,
    ) -> Self {
        fn url(function_name: &str, kind: &str, metadata: &'static str) -> String {
            let prefix = Metadata::checksum_prefix(metadata);
            format!("{function_name}.{kind}.{prefix}")
        }
        Self {
            name: name.to_string(),
            locator: locator.to_string(),
            prover: format!("{BASE_URL}{}", url(name, "prover", prover_metadata)),
            verifier: url(name, "verifier", verifier_metadata),
            verifying_key: verifying_key.to_string(),
        }
    }

    /// The per-network parameter CDN base URL (e.g.
    /// `https://parameters.provable.com/testnet/`).
    ///
    /// JS: `Metadata.baseUrl()`.
    pub fn base_url() -> &'static str {
        BASE_URL
    }

    /// Parameter metadata for `credits.aleo/bond_public`.
    pub fn bond_public() -> Metadata {
        Metadata::new(
            "bond_public",
            "bondPublicVerifier",
            "credits.aleo/bond_public",
            BondPublicProver::METADATA,
            BondPublicVerifier::METADATA,
        )
    }

    /// Parameter metadata for `credits.aleo/bond_validator`.
    pub fn bond_validator() -> Metadata {
        Metadata::new(
            "bond_validator",
            "bondValidatorVerifier",
            "credits.aleo/bond_validator",
            BondValidatorProver::METADATA,
            BondValidatorVerifier::METADATA,
        )
    }

    /// Parameter metadata for `credits.aleo/claim_unbond_public`.
    pub fn claim_unbond_public() -> Metadata {
        Metadata::new(
            "claim_unbond_public",
            "claimUnbondPublicVerifier",
            "credits.aleo/claim_unbond_public",
            ClaimUnbondPublicProver::METADATA,
            ClaimUnbondPublicVerifier::METADATA,
        )
    }

    /// Parameter metadata for `credits.aleo/fee_private`.
    pub fn fee_private() -> Metadata {
        Metadata::new(
            "fee_private",
            "feePrivateVerifier",
            "credits.aleo/fee_private",
            FeePrivateProver::METADATA,
            FeePrivateVerifier::METADATA,
        )
    }

    /// Parameter metadata for `credits.aleo/fee_public`.
    pub fn fee_public() -> Metadata {
        Metadata::new(
            "fee_public",
            "feePublicVerifier",
            "credits.aleo/fee_public",
            FeePublicProver::METADATA,
            FeePublicVerifier::METADATA,
        )
    }

    /// Parameter metadata for the `inclusion` function. Its locator is the bare
    /// program name `"inclusion"`, not `"credits.aleo/inclusion"`.
    pub fn inclusion() -> Metadata {
        Metadata::new(
            "inclusion",
            "inclusionVerifier",
            "inclusion",
            InclusionProver::METADATA,
            InclusionVerifier::METADATA,
        )
    }

    /// Parameter metadata for `credits.aleo/join`.
    pub fn join() -> Metadata {
        Metadata::new(
            "join",
            "joinVerifier",
            "credits.aleo/join",
            JoinProver::METADATA,
            JoinVerifier::METADATA,
        )
    }

    /// Parameter metadata for `credits.aleo/set_validator_state`.
    pub fn set_validator_state() -> Metadata {
        Metadata::new(
            "set_validator_state",
            "setValidatorStateVerifier",
            "credits.aleo/set_validator_state",
            SetValidatorStateProver::METADATA,
            SetValidatorStateVerifier::METADATA,
        )
    }

    /// Parameter metadata for `credits.aleo/split`.
    pub fn split() -> Metadata {
        Metadata::new(
            "split",
            "splitVerifier",
            "credits.aleo/split",
            SplitProver::METADATA,
            SplitVerifier::METADATA,
        )
    }

    /// Parameter metadata for `credits.aleo/transfer_private`.
    pub fn transfer_private() -> Metadata {
        Metadata::new(
            "transfer_private",
            "transferPrivateVerifier",
            "credits.aleo/transfer_private",
            TransferPrivateProver::METADATA,
            TransferPrivateVerifier::METADATA,
        )
    }

    /// Parameter metadata for `credits.aleo/transfer_private_to_public`.
    pub fn transfer_private_to_public() -> Metadata {
        Metadata::new(
            "transfer_private_to_public",
            "transferPrivateToPublicVerifier",
            "credits.aleo/transfer_private_to_public",
            TransferPrivateToPublicProver::METADATA,
            TransferPrivateToPublicVerifier::METADATA,
        )
    }

    /// Parameter metadata for `credits.aleo/transfer_public`.
    pub fn transfer_public() -> Metadata {
        Metadata::new(
            "transfer_public",
            "transferPublicVerifier",
            "credits.aleo/transfer_public",
            TransferPublicProver::METADATA,
            TransferPublicVerifier::METADATA,
        )
    }

    /// Parameter metadata for `credits.aleo/transfer_public_as_signer`.
    pub fn transfer_public_as_signer() -> Metadata {
        Metadata::new(
            "transfer_public_as_signer",
            "transferPublicAsSignerVerifier",
            "credits.aleo/transfer_public_as_signer",
            TransferPublicAsSignerProver::METADATA,
            TransferPublicAsSignerVerifier::METADATA,
        )
    }

    /// Parameter metadata for `credits.aleo/transfer_public_to_private`.
    pub fn transfer_public_to_private() -> Metadata {
        Metadata::new(
            "transfer_public_to_private",
            "transferPublicToPrivateVerifier",
            "credits.aleo/transfer_public_to_private",
            TransferPublicToPrivateProver::METADATA,
            TransferPublicToPrivateVerifier::METADATA,
        )
    }

    /// Parameter metadata for `credits.aleo/unbond_public`.
    pub fn unbond_public() -> Metadata {
        Metadata::new(
            "unbond_public",
            "unbondPublicVerifier",
            "credits.aleo/unbond_public",
            UnbondPublicProver::METADATA,
            UnbondPublicVerifier::METADATA,
        )
    }

    /// Render the entry as the JS-shaped JSON object. The keys are the JS
    /// getter names (`verifyingKey`, not `verifying_key`), and this is the form
    /// the JS SDK would serialize to.
    pub fn to_json_value(&self) -> Value {
        serde_json::json!({
            "name": self.name,
            "locator": self.locator,
            "prover": self.prover,
            "verifier": self.verifier,
            "verifyingKey": self.verifying_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every function, so the catalogue is exhaustive and the checksum logic is
    /// exercised once per entry.
    fn all() -> Vec<Metadata> {
        vec![
            Metadata::bond_public(),
            Metadata::bond_validator(),
            Metadata::claim_unbond_public(),
            Metadata::fee_private(),
            Metadata::fee_public(),
            Metadata::inclusion(),
            Metadata::join(),
            Metadata::set_validator_state(),
            Metadata::split(),
            Metadata::transfer_private(),
            Metadata::transfer_private_to_public(),
            Metadata::transfer_public(),
            Metadata::transfer_public_as_signer(),
            Metadata::transfer_public_to_private(),
            Metadata::unbond_public(),
        ]
    }

    #[test]
    fn the_catalogue_has_all_fifteen_functions() {
        assert_eq!(all().len(), 15);
    }

    #[test]
    fn the_prover_url_is_absolute_and_the_verifier_url_is_relative() {
        for m in all() {
            assert!(
                m.prover.starts_with(BASE_URL),
                "prover URL for {} must be absolute: {}",
                m.name,
                m.prover
            );
            assert!(
                !m.verifier.starts_with("https://"),
                "verifier URL for {} must NOT be absolute (upstream asymmetry): {}",
                m.name,
                m.verifier
            );
            // Both URLs have the shape `<name>.<kind>.<checksum7>`; the only
            // differences are the BASE_URL prefix and the `prover` / `verifier`
            // label — the 7-char checksum prefix is shared.
            let prover_rest = m.prover.strip_prefix(BASE_URL).unwrap();
            let prover_checksum = &prover_rest[prover_rest.len() - 7..];
            let verifier_checksum = &m.verifier[m.verifier.len() - 7..];
            assert_eq!(
                prover_checksum, verifier_checksum,
                "prover and verifier share the checksum prefix for {}",
                m.name
            );
            assert_eq!(prover_checksum.len(), 7, "checksum prefix is 7 chars");
            assert!(prover_rest.ends_with(&format!(".prover.{prover_checksum}")));
            assert!(m.verifier.ends_with(&format!(".verifier.{verifier_checksum}")));
            assert!(prover_rest.starts_with(&format!("{}.", m.name)));
            assert!(m.verifier.starts_with(&format!("{}.", m.name)));
        }
    }

    #[test]
    fn the_checksum_prefix_matches_the_metadata() {
        // The prefix the URL carries must equal the first 7 chars of the
        // `prover_checksum` field of the prover type's METADATA — the only field
        // `url()` ever reads.
        let m = Metadata::fee_public();
        let metadata: Value = serde_json::from_str(FeePublicProver::METADATA).unwrap();
        let expected = metadata["prover_checksum"].as_str().unwrap().get(0..7).unwrap();
        assert_eq!(m.prover, format!("{BASE_URL}fee_public.prover.{expected}"));
        // And the verifier URL uses the *same* prefix, even though its label says
        // "verifier".
        assert_eq!(m.verifier, format!("fee_public.verifier.{expected}"));
    }

    #[test]
    fn inclusion_locator_is_bare() {
        let m = Metadata::inclusion();
        assert_eq!(m.locator, "inclusion");
        assert_eq!(m.name, "inclusion");
        // Every other function carries the `credits.aleo/` prefix.
        for m in all() {
            if m.name != "inclusion" {
                assert!(
                    m.locator.starts_with("credits.aleo/"),
                    "{} should be credits.aleo/*, got {}",
                    m.name,
                    m.locator
                );
            }
        }
    }

    #[test]
    fn verifying_key_is_the_rust_symbol_name_not_a_url() {
        let m = Metadata::transfer_public();
        assert_eq!(m.verifying_key, "transferPublicVerifier");
        assert!(!m.verifying_key.contains('.'));
        assert!(!m.verifying_key.starts_with("https://"));
    }

    #[test]
    fn base_url_is_the_testnet_cdn_root() {
        assert_eq!(
            Metadata::base_url(),
            "https://parameters.provable.com/testnet/"
        );
    }

    #[test]
    fn json_shape_uses_js_key_names() {
        let m = Metadata::fee_public();
        let json = m.to_json_value();
        assert!(json.get("verifyingKey").is_some());
        assert!(json.get("verifying_key").is_none());
        assert_eq!(json["name"], "fee_public");
        assert_eq!(json["verifier"], m.verifier);
    }
}
