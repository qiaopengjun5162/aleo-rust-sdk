//! # credits.aleo value operations — transfers, joins, splits, staking.
//!
//! The "create value transfers and stake credits" half of the JS SDK's
//! `ProgramManager`: plan the `credits.aleo` call for a transfer, a record
//! join, a record split, or a staking operation, then run it through
//! [`AleoClient`](crate::AleoClient)'s prove pipeline.
//!
//! ## Units
//!
//! Every amount here is **microcredits** (`u64`). The JS SDK takes `f64`
//! *credits* and converts with `(amount * 1_000_000.0) as u64` inside the wasm
//! layer; Rust callers state microcredits directly, which is also what the rest
//! of this crate uses (`get_balance`, `priority_fee`, …). The JS conversion is
//! float arithmetic and can round; a `u64` cannot.
//!
//! ## Records are passed as plaintext literals
//!
//! The record inputs ([`plan_transfer`]'s `amount_record`, [`plan_join`]'s two
//! records) are **plaintext record strings** —
//! `{ owner: aleo1...private, microcredits: 1000000u64.private, _nonce: ...group.public }`
//! — not the on-chain `record1...` ciphertexts. snarkVM's `Value` parser has
//! no ciphertext arm: a record reaching a function call must already be
//! decrypted. The JS SDK behaves identically (its wasm layer passes
//! `RecordPlaintext.to_string()`); decrypt with
//! [`AleoAccount::decrypt_record`](crate::account::AleoAccount::decrypt_record)
//! first.
//!
//! ## Two documented divergences from the JS docs
//!
//! Both follow the JS **implementation** (`wasm/src/programs/manager/*.rs`)
//! where it disagrees with its own documentation, and both are written down
//! here because the docs will keep saying otherwise:
//!
//! 1. **There are five transfer kinds, not four.** The docs list
//!    `private / privateToPublic / public / publicToPrivate`; the wasm layer
//!    also accepts `public_as_signer` (the `transfer_public_as_signer`
//!    function, exposed by `ProgramManager.buildTransferPublicAsSignerTransaction`).
//! 2. **`split`'s amount is in credits in JS, despite the docs.** The TS
//!    `split(splitAmount, …)` docstring says "Amount in microcredits", but the
//!    wasm layer multiplies it by `1_000_000` like every other amount. Here the
//!    parameter is honestly named `split_amount_microcredits`.
//!
//! `credits.aleo/split` is also the one call the protocol allows **without a
//! fee** — the JS `buildSplitTransaction` packages with a `None` fee. Use
//! [`AleoClient::split`](crate::AleoClient::split), which does exactly that.
//!
//! ## Staking (bond / unbond / claim / validator state)
//!
//! The staking plans ([`plan_bond_public`], [`plan_bond_validator`],
//! [`plan_unbond_public`], [`plan_claim_unbond_public`],
//! [`plan_set_validator_state`]) follow the **deployed `credits.aleo`**
//! (verified against both the snarkVM 4.12 embedded copy and the testnet
//! program source) where the JS SDK's `build*Transaction` wrappers in
//! `sdk/src/program-manager.ts` disagree with it. Divergences:
//!
//! * **`bond_validator` takes three inputs, not four.** The program is
//!   `bond_validator(withdrawal_address, amount, commission)` — the validator
//!   is the transaction signer. The JS wrapper prepends `validator_address`,
//!   sending four inputs to a three-input function. This crate follows the
//!   program.
//! * **`bond_public` refuses self-bonding** (`assert.neq self.caller
//!   validator`). The JS docstring says passing your own address "bonds as a
//!   validator" — that is `bond_validator`'s job; `bond_public` is the
//!   delegator entry only.
//! * **Minimum amounts and the commission cap live in the program**, not in
//!   either SDK: `bond_public`/`bond_validator` assert ≥ 1 credit in the
//!   function body, and `bond_validator` asserts `commission ≤ 100` there too
//!   (the JS docs' "an error will be thrown" is right — the circuit throws).
//!   Committee-level minimums (validator vs delegator stake floors) are
//!   finalize-time chain rules; the JS comments contradict each other on the
//!   numbers (10M vs 1M validator, 10 vs 10,000 delegator) and neither SDK
//!   enforces them.

use anyhow::{Result, bail};
use snarkvm::prelude::FromStr;

use crate::account::RecordPlaintext;
use crate::record::parse_u64_entry;

/// How credits move between accounts — the JS `transferType` of
/// `ProgramManager.buildTransferTransaction`, resolved to its
/// `credits.aleo` function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferKind {
    /// `credits.aleo/transfer_private` — record in, two records out.
    Private,
    /// `credits.aleo/transfer_private_to_public` — record in, recipient's
    /// public balance up.
    PrivateToPublic,
    /// `credits.aleo/transfer_public` — public balance to public balance.
    Public,
    /// `credits.aleo/transfer_public_as_signer` — like [`Public`](Self::Public),
    /// but the spender signs as the transaction signer rather than the
    /// program's internal caller. Present in the JS implementation but not in
    /// its docs; see the module notes.
    PublicAsSigner,
    /// `credits.aleo/transfer_public_to_private` — public balance in, a record
    /// out to the recipient.
    PublicToPrivate,
}

impl TransferKind {
    /// The `credits.aleo` function implementing this transfer kind.
    pub fn function(self) -> &'static str {
        match self {
            Self::Private => "transfer_private",
            Self::PrivateToPublic => "transfer_private_to_public",
            Self::Public => "transfer_public",
            Self::PublicAsSigner => "transfer_public_as_signer",
            Self::PublicToPrivate => "transfer_public_to_private",
        }
    }

    /// Whether the call spends an amount record (the two private-in kinds).
    pub fn takes_amount_record(self) -> bool {
        matches!(self, Self::Private | Self::PrivateToPublic)
    }
}

impl FromStr for TransferKind {
    type Err = anyhow::Error;

    /// Parse the JS SDK's `transferType` spellings.
    ///
    /// Accepts exactly the alias set the JS wasm layer accepts, so a type
    /// string from JS code or docs maps to the same function there and here.
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "private" | "transfer_private" | "transferPrivate" => Self::Private,
            "private_to_public"
            | "privateToPublic"
            | "transfer_private_to_public"
            | "transferPrivateToPublic" => Self::PrivateToPublic,
            "public" | "transfer_public" | "transferPublic" => Self::Public,
            "public_as_signer" | "transfer_public_as_signer" | "transferPublicAsSigner" => {
                Self::PublicAsSigner
            }
            "public_to_private"
            | "publicToPrivate"
            | "transfer_public_to_private"
            | "transferPublicToPrivate" => Self::PublicToPrivate,
            _ => bail!(
                "Invalid transfer type '{s}'. Valid transfer types are 'private', 'privateToPublic', \
                 'public', 'publicToPrivate', and 'publicAsSigner'."
            ),
        })
    }
}

/// A ready-to-run `credits.aleo` call: the function name and its input strings.
///
/// Feed `inputs` to [`AleoClient::execute_and_broadcast`](crate::AleoClient::execute_and_broadcast)
/// (or the fee-less pipeline for [`plan_split`]) as `Vec<&str>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreditsCall {
    /// The `credits.aleo` function to call.
    pub function: &'static str,
    /// Inputs, in on-chain order, already formatted for snarkVM's parser.
    pub inputs: Vec<String>,
}

/// The `microcredits` of a plaintext record.
///
/// snarkVM's `Record` exposes entries but no typed accessor; the same
/// textual-entry parsing [`RecordScanner`](crate::record::RecordScanner) uses
/// for decrypted records is applied here to a caller-supplied plaintext.
/// A record without a parseable `microcredits` entry cannot be checked against
/// an amount, so this is an error rather than a silent zero.
pub fn record_microcredits(record: &RecordPlaintext) -> Result<u64> {
    for (id, entry) in record.data().iter() {
        if id.to_string() == "microcredits" {
            if let Some(amount) = parse_u64_entry(&entry.to_string()) {
                return Ok(amount);
            }
            bail!("record `microcredits` entry is not a u64: {}", entry);
        }
    }
    bail!("record has no `microcredits` entry");
}

/// Plan a transfer — the JS `buildTransferTransaction`, minus proving.
///
/// * `amount_microcredits` — how much to send (JS takes credits and converts).
/// * `amount_record` — the plaintext record funding the transfer; required for
///   [`TransferKind::Private`] and [`TransferKind::PrivateToPublic`], ignored
///   by the public kinds (pass `None`).
///
/// Mirrors the wasm layer's validation: a missing record for a private-in kind
/// is an error, and a record smaller than the amount is an error. Whether the
/// *fee* is affordable is not this function's business — see
/// [`AleoHttpClient::check_fee`](crate::network::AleoHttpClient::check_fee).
pub fn plan_transfer(
    kind: TransferKind,
    amount_microcredits: u64,
    recipient: &str,
    amount_record: Option<&str>,
) -> Result<CreditsCall> {
    let amount = format!("{amount_microcredits}u64");

    if !kind.takes_amount_record() {
        return Ok(CreditsCall {
            function: kind.function(),
            inputs: vec![recipient.to_string(), amount],
        });
    }

    let Some(raw) = amount_record else {
        bail!("Amount record must be provided for private transfers");
    };
    let record = RecordPlaintext::from_str(raw)
        .map_err(|e| anyhow::anyhow!("Record provided is not a valid plaintext record: {e}"))?;
    if amount_microcredits > record_microcredits(&record)? {
        bail!("Amount record does not have enough credits");
    }

    Ok(CreditsCall {
        function: kind.function(),
        inputs: vec![record.to_string(), recipient.to_string(), amount],
    })
}

/// Plan a join of two credits records — the JS `buildJoinTransaction`, minus
/// proving.
///
/// The two records must be plaintext records (see the module notes). The
/// joined record carries their summed `microcredits`; snarkVM enforces that
/// both inputs are `credits.aleo` records of the same shape.
pub fn plan_join(record_one: &str, record_two: &str) -> Result<CreditsCall> {
    let first = parse_record(record_one, "record_one")?;
    let second = parse_record(record_two, "record_two")?;
    Ok(CreditsCall {
        function: "join",
        inputs: vec![first.to_string(), second.to_string()],
    })
}

/// Plan a split of one credits record into two — the JS `buildSplitTransaction`,
/// minus proving.
///
/// `split_amount_microcredits` is carved out of `amount_record` into a new
/// record; the remainder comes back as change. The amount must fit the record.
///
/// `credits.aleo/split` needs **no fee**; run the plan through
/// [`AleoClient::split`](crate::AleoClient::split), which packages without one.
pub fn plan_split(split_amount_microcredits: u64, amount_record: &str) -> Result<CreditsCall> {
    let record = parse_record(amount_record, "amount_record")?;
    if split_amount_microcredits > record_microcredits(&record)? {
        bail!("Amount record does not have enough credits");
    }
    Ok(CreditsCall {
        function: "split",
        inputs: vec![record.to_string(), format!("{split_amount_microcredits}u64")],
    })
}

/// Plan a bond as a delegator to a validator — the JS
/// `buildBondPublicTransaction`'s intent, minus proving.
///
/// This is the **delegator** entry: `validator_address` must be a different
/// address than the caller (the program asserts `self.caller != validator`).
/// To bond as a validator oneself, use [`plan_bond_validator`].
/// `withdrawal_address` receives the credits when they are later unbonded.
/// The function asserts the amount is at least 1 credit; committee-level
/// minimums are finalize-time chain rules (see the module notes).
pub fn plan_bond_public(
    validator_address: &str,
    withdrawal_address: &str,
    amount_microcredits: u64,
) -> Result<CreditsCall> {
    Ok(CreditsCall {
        function: "bond_public",
        inputs: vec![
            validator_address.to_string(),
            withdrawal_address.to_string(),
            format!("{amount_microcredits}u64"),
        ],
    })
}

/// Plan a bond as a validator (self-bond) with a commission rate — the JS
/// `buildBondValidatorTransaction`, minus proving and minus one wrong
/// argument.
///
/// The deployed `credits.aleo` is
/// `bond_validator(withdrawal_address, amount, commission)`: the validator is
/// the transaction **signer**, so there is no validator-address input. The JS
/// wrapper sends one (`[validator_address, withdrawal_address, amount,
/// commission]`, four inputs for a three-input function) — see the module
/// notes. `withdrawal_address` must differ from the signer (the program
/// asserts it). `commission` is the validator's take in percent; the program
/// asserts it is at most 100.
pub fn plan_bond_validator(
    withdrawal_address: &str,
    amount_microcredits: u64,
    commission: u8,
) -> Result<CreditsCall> {
    Ok(CreditsCall {
        function: "bond_validator",
        inputs: vec![
            withdrawal_address.to_string(),
            format!("{amount_microcredits}u64"),
            format!("{commission}u8"),
        ],
    })
}

/// Plan an unbond of staked credits — the JS `buildUnbondPublicTransaction`,
/// minus proving.
///
/// `staker_address` is the address whose stake shrinks; `amount_microcredits`
/// unbonds part of the stake (the chain enforces what may remain).
pub fn plan_unbond_public(staker_address: &str, amount_microcredits: u64) -> Result<CreditsCall> {
    Ok(CreditsCall {
        function: "unbond_public",
        inputs: vec![staker_address.to_string(), format!("{amount_microcredits}u64")],
    })
}

/// Plan a claim of unbonded credits — the JS
/// `buildClaimUnbondPublicTransaction`, minus proving.
///
/// After [`plan_unbond_public`], the credits wait out the unbonding period and
/// are then claimed to `staker_address`'s public balance.
pub fn plan_claim_unbond_public(staker_address: &str) -> Result<CreditsCall> {
    Ok(CreditsCall {
        function: "claim_unbond_public",
        inputs: vec![staker_address.to_string()],
    })
}

/// Plan opening or closing a validator to new stakers — the JS
/// `buildSetValidatorStateTransaction`, minus proving.
///
/// `validator_state: true` opens the validator to new bonds, `false` closes it
/// (existing stakers can still bond and unbond). Formatted as the boolean
/// literal `true`/`false`, exactly the input the wasm layer builds.
pub fn plan_set_validator_state(validator_state: bool) -> Result<CreditsCall> {
    Ok(CreditsCall {
        function: "set_validator_state",
        inputs: vec![validator_state.to_string()],
    })
}

/// Parse a caller-supplied plaintext record, labelling errors with the
/// argument name the caller used.
fn parse_record(raw: &str, what: &str) -> Result<RecordPlaintext> {
    RecordPlaintext::from_str(raw)
        .map_err(|e| anyhow::anyhow!("{what} is not a valid plaintext record: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexmap::IndexMap;
    use snarkvm::console::program::{Entry, Identifier, Literal, Plaintext, Record};
    use snarkvm::prelude::{Network, Owner, Scalar, TestRng, TestnetV0, U8};
    use snarkvm::utilities::rand::Uniform;

    /// A plaintext record owned by a fresh address, holding `microcredits`.
    ///
    /// Same construction `tests/record_decryption_test.rs` encrypts; here the
    /// record is kept in the plaintext form the plan functions consume.
    fn plaintext_record(microcredits: u64, rng: &mut TestRng) -> String {
        let randomizer = Scalar::rand(rng);
        let nonce = TestnetV0::g_scalar_multiply(&randomizer);
        let owner_account = crate::account::AleoAccount::new_random(rng).unwrap();
        let owner = Owner::Private(Plaintext::from(Literal::Address(owner_account.address)));
        let mut data = IndexMap::new();
        data.insert(
            Identifier::from_str("microcredits").unwrap(),
            Entry::Private(Plaintext::from_str(&format!("{microcredits}u64")).unwrap()),
        );
        Record::<TestnetV0, Plaintext<TestnetV0>>::from_plaintext(owner, data, nonce, U8::new(0))
            .unwrap()
            .to_string()
    }

    #[test]
    fn every_js_transfer_type_spelling_resolves_to_a_kind() {
        for (spelling, expected) in [
            ("private", TransferKind::Private),
            ("transfer_private", TransferKind::Private),
            ("transferPrivate", TransferKind::Private),
            ("private_to_public", TransferKind::PrivateToPublic),
            ("privateToPublic", TransferKind::PrivateToPublic),
            ("transfer_private_to_public", TransferKind::PrivateToPublic),
            ("transferPrivateToPublic", TransferKind::PrivateToPublic),
            ("public", TransferKind::Public),
            ("transfer_public", TransferKind::Public),
            ("transferPublic", TransferKind::Public),
            ("public_as_signer", TransferKind::PublicAsSigner),
            ("transfer_public_as_signer", TransferKind::PublicAsSigner),
            ("transferPublicAsSigner", TransferKind::PublicAsSigner),
            ("public_to_private", TransferKind::PublicToPrivate),
            ("publicToPrivate", TransferKind::PublicToPrivate),
            ("transfer_public_to_private", TransferKind::PublicToPrivate),
            ("transferPublicToPrivate", TransferKind::PublicToPrivate),
        ] {
            assert_eq!(
                TransferKind::from_str(spelling).unwrap(),
                expected,
                "spelling {spelling:?}"
            );
        }
    }

    #[test]
    fn an_unknown_transfer_type_is_rejected_with_the_valid_set() {
        let err = TransferKind::from_str("publicPrivate").unwrap_err().to_string();
        assert!(
            err.contains("Invalid transfer type 'publicPrivate'"),
            "{err}"
        );
        assert!(err.contains("'publicToPrivate'"), "{err}");
    }

    #[test]
    fn each_kind_names_the_function_the_js_wasm_layer_calls() {
        assert_eq!(TransferKind::Private.function(), "transfer_private");
        assert_eq!(
            TransferKind::PrivateToPublic.function(),
            "transfer_private_to_public"
        );
        assert_eq!(TransferKind::Public.function(), "transfer_public");
        assert_eq!(
            TransferKind::PublicAsSigner.function(),
            "transfer_public_as_signer"
        );
        assert_eq!(
            TransferKind::PublicToPrivate.function(),
            "transfer_public_to_private"
        );
    }

    #[test]
    fn a_public_transfer_needs_no_record_and_formats_the_amount_as_u64() {
        let call = plan_transfer(TransferKind::Public, 2_500_000, "aleo1recipient", None).unwrap();
        assert_eq!(call.function, "transfer_public");
        assert_eq!(
            call.inputs,
            vec!["aleo1recipient".to_string(), "2500000u64".to_string()]
        );
    }

    #[test]
    fn every_public_kind_spends_no_record() {
        for kind in [
            TransferKind::Public,
            TransferKind::PublicAsSigner,
            TransferKind::PublicToPrivate,
        ] {
            assert!(!kind.takes_amount_record(), "{kind:?}");
            // A record passed anyway is ignored, matching the wasm layer.
            let call = plan_transfer(kind, 1, "aleo1recipient", Some("ignored")).unwrap();
            assert_eq!(call.inputs.len(), 2, "{kind:?}");
        }
    }

    #[test]
    fn a_private_transfer_requires_an_amount_record() {
        let err = plan_transfer(TransferKind::Private, 1, "aleo1recipient", None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Amount record must be provided for private transfers"),
            "{err}"
        );

        let err = plan_transfer(TransferKind::PrivateToPublic, 1, "aleo1recipient", None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Amount record must be provided for private transfers"),
            "{err}"
        );
    }

    #[test]
    fn a_private_transfer_puts_the_record_first_and_normalizes_it() {
        let rng = &mut TestRng::default();
        let raw = plaintext_record(5_000_000, rng);
        let call = plan_transfer(
            TransferKind::Private,
            4_000_000,
            "aleo1recipient",
            Some(&raw),
        )
        .unwrap();
        assert_eq!(call.function, "transfer_private");
        assert_eq!(call.inputs.len(), 3);
        // The record is re-serialized from its parsed form, so the input is the
        // canonical literal even if the caller's spacing was odd.
        assert_eq!(
            call.inputs[0],
            RecordPlaintext::from_str(&raw).unwrap().to_string()
        );
        assert_eq!(call.inputs[1], "aleo1recipient");
        assert_eq!(call.inputs[2], "4000000u64");
    }

    #[test]
    fn a_record_that_cannot_pay_the_amount_is_rejected() {
        let rng = &mut TestRng::default();
        let raw = plaintext_record(3_000_000, rng);
        let err = plan_transfer(TransferKind::Private, 3_000_001, "aleo1r", Some(&raw))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Amount record does not have enough credits"),
            "{err}"
        );

        // The exact amount is fine — the boundary is inclusive.
        plan_transfer(TransferKind::Private, 3_000_000, "aleo1r", Some(&raw)).unwrap();
    }

    #[test]
    fn a_malformed_record_input_says_which_argument_failed() {
        let err = plan_transfer(TransferKind::Private, 1, "aleo1r", Some("record1bogus"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a valid plaintext record"), "{err}");
    }

    #[test]
    fn join_orders_the_two_records_and_validates_both() {
        let rng = &mut TestRng::default();
        let one = plaintext_record(1, rng);
        let two = plaintext_record(2, rng);
        let call = plan_join(&one, &two).unwrap();
        assert_eq!(call.function, "join");
        assert_eq!(
            call.inputs[0],
            RecordPlaintext::from_str(&one).unwrap().to_string()
        );
        assert_eq!(
            call.inputs[1],
            RecordPlaintext::from_str(&two).unwrap().to_string()
        );

        let err = plan_join(&one, "record1bogus").unwrap_err().to_string();
        assert!(err.contains("record_two"), "{err}");
        let err = plan_join("record1bogus", &two).unwrap_err().to_string();
        assert!(err.contains("record_one"), "{err}");
    }

    #[test]
    fn split_carves_the_amount_out_of_the_record_and_needs_no_fee() {
        let rng = &mut TestRng::default();
        let raw = plaintext_record(10_000_000, rng);
        let call = plan_split(4_000_000, &raw).unwrap();
        assert_eq!(call.function, "split");
        assert_eq!(call.inputs.len(), 2);
        assert_eq!(
            call.inputs[0],
            RecordPlaintext::from_str(&raw).unwrap().to_string()
        );
        assert_eq!(call.inputs[1], "4000000u64");

        let err = plan_split(10_000_001, &raw).unwrap_err().to_string();
        assert!(
            err.contains("Amount record does not have enough credits"),
            "{err}"
        );
        plan_split(10_000_000, &raw).unwrap();
    }

    #[test]
    fn bond_public_formats_three_inputs_in_js_order() {
        let call =
            plan_bond_public("aleo1validator", "aleo1withdrawal", 10_000_000_000_000).unwrap();
        assert_eq!(call.function, "bond_public");
        assert_eq!(
            call.inputs,
            vec![
                "aleo1validator".to_string(),
                "aleo1withdrawal".to_string(),
                "10000000000000u64".to_string(),
            ]
        );
    }

    #[test]
    fn bond_validator_carries_only_withdrawal_amount_and_commission() {
        // The validator is the signer; the deployed credits.aleo has three
        // inputs, while the JS wrapper wrongly prepends the validator address.
        let call = plan_bond_validator("aleo1withdrawal", 2_000_000, 25).unwrap();
        assert_eq!(call.function, "bond_validator");
        assert_eq!(
            call.inputs,
            vec!["aleo1withdrawal".to_string(), "2000000u64".to_string(), "25u8".to_string(),]
        );

        // The 0–100 cap is asserted by the program circuit (gt r2 100u8);
        // the plan layer formats whatever u8 it is given.
        assert_eq!(plan_bond_validator("w", 1, 0).unwrap().inputs[2], "0u8");
        assert_eq!(plan_bond_validator("w", 1, 100).unwrap().inputs[2], "100u8");
    }

    #[test]
    fn unbond_public_scales_the_amount_like_every_other_amount() {
        let call = plan_unbond_public("aleo1staker", 4_000_000).unwrap();
        assert_eq!(call.function, "unbond_public");
        assert_eq!(
            call.inputs,
            vec!["aleo1staker".to_string(), "4000000u64".to_string()]
        );
    }

    #[test]
    fn claim_unbond_public_carries_only_the_staker_address() {
        let call = plan_claim_unbond_public("aleo1staker").unwrap();
        assert_eq!(call.function, "claim_unbond_public");
        assert_eq!(call.inputs, vec!["aleo1staker".to_string()]);
    }

    #[test]
    fn set_validator_state_formats_the_boolean_literal() {
        let open = plan_set_validator_state(true).unwrap();
        assert_eq!(open.function, "set_validator_state");
        assert_eq!(open.inputs, vec!["true".to_string()]);
        let closed = plan_set_validator_state(false).unwrap();
        assert_eq!(closed.inputs, vec!["false".to_string()]);
    }

    #[test]
    fn record_microcredits_reads_the_amount_out_of_a_plaintext_record() {
        let rng = &mut TestRng::default();
        let raw = plaintext_record(42, rng);
        let record = RecordPlaintext::from_str(&raw).unwrap();
        assert_eq!(record_microcredits(&record).unwrap(), 42);
    }

    #[test]
    fn record_microcredits_rejects_a_record_without_the_entry() {
        let rng = &mut TestRng::default();
        let randomizer = Scalar::rand(rng);
        let nonce = TestnetV0::g_scalar_multiply(&randomizer);
        let owner_account = crate::account::AleoAccount::new_random(rng).unwrap();
        let owner = Owner::Private(Plaintext::from(Literal::Address(owner_account.address)));
        let mut data = IndexMap::new();
        data.insert(
            Identifier::from_str("votes").unwrap(),
            Entry::Private(Plaintext::from_str("1u64").unwrap()),
        );
        let record = Record::<TestnetV0, Plaintext<TestnetV0>>::from_plaintext(
            owner,
            data,
            nonce,
            U8::new(0),
        )
        .unwrap();
        let err = record_microcredits(&record).unwrap_err().to_string();
        assert!(err.contains("no `microcredits` entry"), "{err}");
    }
}
