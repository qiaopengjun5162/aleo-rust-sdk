//! Aleo `Transaction` — parity with the JS SDK's wasm `Transaction` class.
//!
//! `Transaction` wraps snarkVM's native [`snarkvm::prelude::Transaction`], so it
//! is a thin shell: most JS methods forward to the native transaction, and a few
//! (`summary`) assemble a structured view of it.
//!
//! ## JS `Transaction` → Rust mapping
//!
//! | # | JS `Transaction` | Rust equivalent | Where |
//! |---|---|---|---|
//! | 1 | `Transaction.fromString(s)` | [`Transaction::from_string`] / [`FromStr`] | this module |
//! | 2 | `Transaction.fromBytesLe(b)` | [`Transaction::from_bytes_le`] | this module |
//! | 3 | `tx.toString()` | [`ToString::to_string`] (or [`std::fmt::Display`]) | this module |
//! | 4 | `tx.toBytesLe()` | [`Transaction::to_bytes_le`] | this module |
//! | 5 | `tx.constainsSerialNumber(f)` | [`Transaction::contains_serial_number`] | **this module** (see note) |
//! | 6 | `tx.constainsCommitment(f)` | [`Transaction::contains_commitment`] | **this module** (see note) |
//! | 7 | `tx.findRecord(f)` | [`Transaction::find_record`] | this module |
//! | 8 | `tx.baseFeeAmount()` | [`Transaction::base_fee_amount`] | this module |
//! | 9 | `tx.feeAmount()` | [`Transaction::fee_amount`] | this module |
//! | 10 | `tx.priorityFeeAmount()` | [`Transaction::priority_fee_amount`] | this module |
//! | 11 | `tx.isDeploy()` | [`Transaction::is_deploy`] | this module |
//! | 12 | `tx.isExecute()` | [`Transaction::is_execute`] | this module |
//! | 13 | `tx.isFee()` | [`Transaction::is_fee`] | this module |
//! | 14 | `tx.deployedProgram()` | [`Transaction::deployed_program`] | this module |
//! | 15 | `tx.execution()` | [`Transaction::execution`] | this module |
//! | 16 | `tx.ownedRecords(vk)` | [`Transaction::owned_records`] | this module |
//! | 17 | `tx.records()` | [`Transaction::records`] | this module |
//! | 18 | `tx.summary(convertToJs)` | [`Transaction::summary`] | this module |
//! | 19 | `tx.id()` | [`Transaction::id`] | this module |
//! | 20 | `tx.transactionType()` | [`Transaction::transaction_type`] | this module |
//! | 21 | `tx.transitions()` | [`Transaction::transitions`] | this module |
//! | 22 | `tx.verifyingKeys()` | [`Transaction::verifying_keys`] | this module |
//!
//! ## Traps
//!
//! - **Upstream typos.** The JS class exposes `constainsSerialNumber` and
//!   `constainsCommitment` (missing an `n`). Rust uses the correct spellings
//!   [`Transaction::contains_serial_number`] / [`Transaction::contains_commitment`]
//!   and documents the divergence, following the same policy as the `negate`
//!   rename for `Field::inverse` and the `KeyPair` error-text fix.
//! - **Fee amounts fold to `0`.** `baseFeeAmount` / `feeAmount` /
//!   `priorityFeeAmount` return `u64`. The native transaction returns `None`
//!   for non-fee transactions; the JS contract folds that to `0`, so the Rust
//!   helpers do the same. (snarkVM's `U64` is unwrapped to a plain `u64`.)
//! - **`summary` returns structured JSON, not a JS object.** The JS method
//!   builds a dynamic `Object`; the Rust equivalent is a
//!   [`serde_json::Value`]. The `convertToJs` flag in JS toggles between
//!   string and native representations of `tpk`/`tcm`/`scm`; this
//!   implementation always serializes them as strings (the `convertToJs = true`
//!   path), which is what the JS test asserts against. Input/output `value`
//!   fields are always emitted as their string form (the JS SDK emits numeric
//!   values as JS bigints, but the structured meaning is identical).
//! - **`deployedProgram` / `execution` return snarkVM native types**
//!   (`Program<N>` / `Execution<N>`), mirroring the JS `Program` / `Execution`
//!   classes. This crate's higher-level `AleoProgram` / `ExecutionEngine`
//!   abstractions sit one layer above and are intentionally *not* used here.

use anyhow::{Result, anyhow};
use serde::Serialize;
use serde_json::Value as JsonValue;
use snarkvm::prelude::{
    Argument, Ciphertext, Execution, Fee, Field, FromBytes, Future, Input, Literal, Network,
    Output, Plaintext, Program, Record, ToBytes, Transaction as TransactionNative, Transition,
    ViewKey,
};
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

/// A transaction: a deployment, execution, or fee.
///
/// Wraps snarkVM's [`TransactionNative`]; see the [module docs](crate::transaction)
/// for the full JS-method mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction<N: Network>(pub(crate) TransactionNative<N>);

impl<N: Network> Deref for Transaction<N> {
    type Target = TransactionNative<N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<N: Network> From<TransactionNative<N>> for Transaction<N> {
    fn from(transaction: TransactionNative<N>) -> Self {
        Self(transaction)
    }
}

impl<N: Network> From<Transaction<N>> for TransactionNative<N> {
    fn from(transaction: Transaction<N>) -> Self {
        transaction.0
    }
}

impl<N: Network> From<&TransactionNative<N>> for Transaction<N> {
    fn from(transaction: &TransactionNative<N>) -> Self {
        Self(transaction.clone())
    }
}

impl<N: Network> From<&Transaction<N>> for TransactionNative<N> {
    fn from(transaction: &Transaction<N>) -> Self {
        transaction.0.clone()
    }
}

impl<N: Network> FromStr for Transaction<N> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(Self(
            TransactionNative::<N>::from_str(s).map_err(|e| anyhow!("invalid transaction: {e}"))?,
        ))
    }
}

impl<N: Network> fmt::Display for Transaction<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One entry of a deployment's verifying-key list, as surfaced by
/// [`Transaction::verifying_keys`]. Mirrors the JS `verifyingKeys()` array shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerifyingKeyEntry<N: Network> {
    /// The program id the deployment belongs to.
    pub program: String,
    /// The function name.
    pub function: String,
    /// The verifying key, as a string.
    pub verifying_key: String,
    /// The certificate, as a string.
    pub certificate: String,
    #[serde(skip)]
    _network: std::marker::PhantomData<N>,
}

impl<N: Network> Transaction<N> {
    /// Build a transaction from its string form — the JS `Transaction.fromString(s)`.
    ///
    /// Accepts the same canonical JSON the JS SDK emits and consumes.
    pub fn from_string(transaction: &str) -> Result<Self> {
        Self::from_str(transaction)
    }

    /// Build a transaction from left-endian bytes — the JS `Transaction.fromBytesLe(b)`.
    pub fn from_bytes_le(bytes: &[u8]) -> Result<Self> {
        let transaction = TransactionNative::<N>::from_bytes_le(bytes)
            .map_err(|e| anyhow!("invalid transaction bytes: {e}"))?;
        Ok(Self(transaction))
    }

    /// Serialize the transaction to left-endian bytes — the JS `Transaction.toBytesLe()`.
    pub fn to_bytes_le(&self) -> Result<Vec<u8>> {
        self.0
            .to_bytes_le()
            .map_err(|e| anyhow!("failed to serialize transaction: {e}"))
    }

    /// Returns true if the transaction contains the given serial number.
    ///
    /// Corrects the upstream JS typo `constainsSerialNumber` (missing an `n`).
    pub fn contains_serial_number(&self, serial_number: &Field<N>) -> bool {
        self.0.contains_serial_number(serial_number)
    }

    /// Returns true if the transaction contains the given commitment.
    ///
    /// Corrects the upstream JS typo `constainsCommitment` (missing an `n`).
    pub fn contains_commitment(&self, commitment: &Field<N>) -> bool {
        self.0.contains_commitment(commitment)
    }

    /// Find a record ciphertext in the transaction by its commitment.
    pub fn find_record(&self, commitment: &Field<N>) -> Option<Record<N, Ciphertext<N>>> {
        self.0.find_record(commitment).cloned()
    }

    /// The transaction's base fee, folded to `0` for non-fee transactions.
    pub fn base_fee_amount(&self) -> u64 {
        self.0.base_fee_amount().map(|fee| *fee).unwrap_or(0)
    }

    /// The transaction's total fee, folded to `0` for non-fee transactions.
    pub fn fee_amount(&self) -> u64 {
        self.0.fee_amount().map(|fee| *fee).unwrap_or(0)
    }

    /// The transaction's priority fee, folded to `0` for non-fee transactions.
    pub fn priority_fee_amount(&self) -> u64 {
        self.0.priority_fee_amount().map(|fee| *fee).unwrap_or(0)
    }

    /// True if this is a deployment transaction.
    pub fn is_deploy(&self) -> bool {
        self.0.is_deploy()
    }

    /// True if this is an execution transaction.
    pub fn is_execute(&self) -> bool {
        self.0.is_execute()
    }

    /// True if this is a fee transaction.
    pub fn is_fee(&self) -> bool {
        self.0.is_fee()
    }

    /// The program deployed by this transaction, if it is a deployment.
    pub fn deployed_program(&self) -> Option<Program<N>> {
        self.0.deployment().map(|deployment| deployment.program().clone())
    }

    /// The execution contained in this transaction, if present.
    pub fn execution(&self) -> Option<Execution<N>> {
        self.0.execution().cloned()
    }

    /// The record plaintexts in this transaction owned by `view_key`.
    ///
    /// Each record ciphertext is decrypted with the view key; records that fail
    /// to decrypt are skipped (they belong to a different owner).
    pub fn owned_records(&self, view_key: &ViewKey<N>) -> Vec<Record<N, Plaintext<N>>> {
        self.0
            .records()
            .filter_map(|(_, record_ciphertext)| record_ciphertext.decrypt(view_key).ok())
            .collect()
    }

    /// The `(commitment, record ciphertext)` pairs in this transaction.
    #[allow(clippy::type_complexity)]
    pub fn records(&self) -> Vec<(Field<N>, Record<N, Ciphertext<N>>)> {
        self.0
            .records()
            .map(|(commitment, record_ciphertext)| (*commitment, record_ciphertext.clone()))
            .collect()
    }

    /// The transaction id (the merkle root of its inclusion proof).
    pub fn id(&self) -> String {
        self.0.id().to_string()
    }

    /// The transaction type: `"deploy"`, `"execute"`, or `"fee"`.
    pub fn transaction_type(&self) -> String {
        match &self.0 {
            TransactionNative::Deploy(..) => "deploy",
            TransactionNative::Execute(..) => "execute",
            TransactionNative::Fee(..) => "fee",
        }
        .to_string()
    }

    /// The transitions in this transaction.
    pub fn transitions(&self) -> Vec<Transition<N>> {
        self.0.transitions().cloned().collect()
    }

    /// The verifying keys of a deployment, as a structured list.
    pub fn verifying_keys(&self) -> Vec<VerifyingKeyEntry<N>> {
        match self.0.deployment() {
            Some(deployment) => deployment
                .verifying_keys()
                .iter()
                .map(
                    |(function_name, (verifying_key, certificate))| VerifyingKeyEntry {
                        program: deployment.program_id().to_string(),
                        function: function_name.to_string(),
                        verifying_key: verifying_key.to_string(),
                        certificate: certificate.to_string(),
                        _network: std::marker::PhantomData,
                    },
                )
                .collect(),
            None => Vec::new(),
        }
    }

    /// A structured summary of the transaction — the JS `Transaction.summary(convertToJs)`.
    ///
    /// `convert_to_js` is accepted for API parity but is ignored: the summary
    /// always serializes `tpk`/`tcm`/`scm` as strings (the JS `convertToJs = true`
    /// path). See the [module docs](crate::transaction#traps) for the one
    /// cosmetic divergence from the JS object (numeric input/output values are
    /// emitted as strings rather than JS bigints).
    pub fn summary(&self, _convert_to_js: bool) -> JsonValue {
        let execution_json = if self.0.is_execute() {
            if let Some(execution) = self.0.execution() {
                let transitions: Vec<JsonValue> =
                    self.0.transitions().map(transition_to_json::<N>).collect();
                serde_json::json!({
                    "global_state_root": execution.global_state_root().to_string(),
                    "proof": execution.proof().map(|proof| proof.to_string()).unwrap_or_default(),
                    "transitions": transitions,
                })
            } else {
                JsonValue::Null
            }
        } else {
            JsonValue::Null
        };

        let deployment_json = if let Some(deployment) = self.0.deployment() {
            let functions: Vec<JsonValue> = deployment
                .verifying_keys()
                .iter()
                .map(|(function_name, (verifying_key, certificate))| {
                    serde_json::json!({
                        "name": function_name.to_string(),
                        "constraints": verifying_key.circuit_info.num_constraints,
                        "variables": verifying_key.num_variables(),
                        "verifyingKey": verifying_key.to_string(),
                        "certificate": certificate.to_string(),
                    })
                })
                .collect();
            serde_json::json!({
                "edition": deployment.edition(),
                "program": deployment.program_id().to_string(),
                "functions": functions,
            })
        } else {
            JsonValue::Null
        };

        let owner_json = if let Some(owner) = self.0.owner() {
            serde_json::json!({
                "address": owner.address().to_string(),
                "signature": owner.signature().to_string(),
            })
        } else {
            JsonValue::Null
        };

        let fee_json = match &self.0 {
            TransactionNative::Deploy(_, _, _, _, fee) => fee_json::<N>(fee),
            TransactionNative::Execute(_, _, _, fee) => {
                fee.as_ref().map(fee_json::<N>).unwrap_or(JsonValue::Null)
            }
            TransactionNative::Fee(_, fee) => fee_json::<N>(fee),
        };

        serde_json::json!({
            "id": self.id(),
            "type": self.transaction_type(),
            "execution": execution_json,
            "deployment": deployment_json,
            "fee": fee_json,
            "owner": owner_json,
            "feeAmount": self.fee_amount(),
            "baseFee": self.base_fee_amount(),
            "priorityFee": self.priority_fee_amount(),
        })
    }
}

/// Serialize a transition into the `summary` shape used by the JS SDK.
fn transition_to_json<N: Network>(transition: &Transition<N>) -> JsonValue {
    let inputs: Vec<JsonValue> = transition.inputs().iter().map(request_to_json::<N>).collect();
    let outputs: Vec<JsonValue> = transition.outputs().iter().map(response_to_json::<N>).collect();
    serde_json::json!({
        "program": transition.program_id().to_string(),
        "function": transition.function_name().to_string(),
        "id": transition.id().to_string(),
        "inputs": inputs,
        "outputs": outputs,
        "tpk": transition.tpk().to_string(),
        "tcm": transition.tcm().to_string(),
        "scm": transition.scm().to_string(),
    })
}

/// Serialize a fee transition (a `Fee`) into the `summary.fee` shape.
fn fee_json<N: Network>(fee: &Fee<N>) -> JsonValue {
    let inputs: Vec<JsonValue> = fee.inputs().iter().map(request_to_json::<N>).collect();
    let outputs: Vec<JsonValue> = fee.outputs().iter().map(response_to_json::<N>).collect();
    let fee_transition = serde_json::json!({
        "program": fee.program_id().to_string(),
        "function": fee.function_name().to_string(),
        "id": fee.id().to_string(),
        "inputs": inputs,
        "outputs": outputs,
        "tpk": fee.tpk().to_string(),
        "tcm": fee.tcm().to_string(),
        "scm": fee.scm().to_string(),
    });
    serde_json::json!({
        "global_state_root": fee.global_state_root().to_string(),
        "proof": fee.proof().map(|proof| proof.to_string()).unwrap_or_default(),
        "transition": fee_transition,
    })
}

/// Serialize a transition input (`Input`) into the `summary` shape.
///
/// Mirrors the upstream `input_to_js_value` with `convertToJs = true`: the
/// `value` is the (string/number) representation of the plaintext/ciphertext,
/// records carry a `tag` instead of a `value`, and the dynamic variants expose
/// their `dynamic_id`.
fn request_to_json<N: Network>(request: &Input<N>) -> JsonValue {
    match request {
        Input::Constant(id, plaintext) => serde_json::json!({
            "type": "constant",
            "id": id.to_string(),
            "value": plaintext.as_ref().map(plaintext_to_json::<N>).unwrap_or(JsonValue::Null),
        }),
        Input::Public(id, plaintext) => serde_json::json!({
            "type": "public",
            "id": id.to_string(),
            "value": plaintext.as_ref().map(plaintext_to_json::<N>).unwrap_or(JsonValue::Null),
        }),
        Input::Private(id, ciphertext) => serde_json::json!({
            "type": "private",
            "id": id.to_string(),
            "value": ciphertext.as_ref().map(|c| JsonValue::String(c.to_string())).unwrap_or(JsonValue::Null),
        }),
        Input::Record(serial_number, tag) => serde_json::json!({
            "type": "record",
            "id": serial_number.to_string(),
            "tag": tag.to_string(),
        }),
        Input::ExternalRecord(input_commitment) => serde_json::json!({
            "type": "externalRecord",
            "id": input_commitment.to_string(),
        }),
        Input::DynamicRecord(input_commitment) => serde_json::json!({
            "type": "record_dynamic",
            "id": input_commitment.to_string(),
        }),
        Input::RecordWithDynamicID(serial_number, tag, dynamic_id) => serde_json::json!({
            "type": "record_with_dynamic_id",
            "id": serial_number.to_string(),
            "tag": tag.to_string(),
            "dynamic_id": dynamic_id.to_string(),
        }),
        Input::ExternalRecordWithDynamicID(external_record_hash, dynamic_id) => serde_json::json!({
            "type": "external_record_with_dynamic_id",
            "id": external_record_hash.to_string(),
            "dynamic_id": dynamic_id.to_string(),
        }),
    }
}

/// Serialize a transition output (`Output`) into the `summary` shape.
///
/// Mirrors the upstream `output_to_js_value` with `convertToJs = true`.
fn response_to_json<N: Network>(response: &Output<N>) -> JsonValue {
    match response {
        Output::Constant(id, plaintext) => serde_json::json!({
            "type": "constant",
            "id": id.to_string(),
            "value": plaintext.as_ref().map(plaintext_to_json::<N>).unwrap_or(JsonValue::Null),
        }),
        Output::Public(id, plaintext) => serde_json::json!({
            "type": "public",
            "id": id.to_string(),
            "value": plaintext.as_ref().map(plaintext_to_json::<N>).unwrap_or(JsonValue::Null),
        }),
        Output::Private(id, ciphertext) => serde_json::json!({
            "type": "private",
            "id": id.to_string(),
            "value": ciphertext.as_ref().map(|c| JsonValue::String(c.to_string())).unwrap_or(JsonValue::Null),
        }),
        Output::Record(commitment, checksum, record, sender) => serde_json::json!({
            "type": "record",
            "id": commitment.to_string(),
            "checksum": checksum.to_string(),
            "value": record.as_ref().map(|r| JsonValue::String(r.to_string())).unwrap_or(JsonValue::Null),
            "sender_ciphertext": sender.as_ref().map(|s| JsonValue::String(s.to_string())).unwrap_or(JsonValue::Null),
        }),
        Output::ExternalRecord(output_commitment) => serde_json::json!({
            "type": "external_record",
            "id": output_commitment.to_string(),
        }),
        Output::Future(id, future) => serde_json::json!({
            "type": "future",
            "id": id.to_string(),
            "value": future.as_ref().map(|f| future_to_json::<N>(f, id)).unwrap_or(JsonValue::Null),
        }),
        Output::DynamicRecord(output_commitment) => serde_json::json!({
            "type": "record_dynamic",
            "id": output_commitment.to_string(),
        }),
        Output::RecordWithDynamicID(output_commitment, checksum, record, sender, dynamic_id) => {
            serde_json::json!({
                "type": "record_with_dynamic_id",
                "id": output_commitment.to_string(),
                "checksum": checksum.to_string(),
                "value": record.as_ref().map(|r| JsonValue::String(r.to_string())).unwrap_or(JsonValue::Null),
                "sender_ciphertext": sender.as_ref().map(|s| JsonValue::String(s.to_string())).unwrap_or(JsonValue::Null),
                "dynamic_id": dynamic_id.to_string(),
            })
        }
        Output::ExternalRecordWithDynamicID(external_record_hash, dynamic_id) => {
            serde_json::json!({
                "type": "external_record_with_dynamic_id",
                "id": external_record_hash.to_string(),
                "dynamic_id": dynamic_id.to_string(),
            })
        }
    }
}

/// Serialize a [`Plaintext`] into its `summary` value form (mirrors
/// `plaintext_to_js_value`): literals become strings or numbers, structs and
/// arrays recurse.
fn plaintext_to_json<N: Network>(plaintext: &Plaintext<N>) -> JsonValue {
    match plaintext {
        Plaintext::Literal(literal, _) => literal_to_json::<N>(literal),
        Plaintext::Struct(members, _) => {
            let obj: serde_json::Map<String, JsonValue> = members
                .iter()
                .map(|(key, value)| (key.to_string(), plaintext_to_json::<N>(value)))
                .collect();
            JsonValue::Object(obj)
        }
        Plaintext::Array(array, _) => {
            JsonValue::Array(array.iter().map(|value| plaintext_to_json::<N>(value)).collect())
        }
    }
}

/// Serialize a [`Literal`] into its `summary` value form (mirrors
/// `literal_to_js_value`): address/field/group/scalar/signature/identifier
/// become strings; integers and booleans become JSON numbers / booleans.
fn literal_to_json<N: Network>(literal: &Literal<N>) -> JsonValue {
    match literal {
        Literal::Address(literal) => JsonValue::String(literal.to_string()),
        Literal::Boolean(literal) => JsonValue::Bool(**literal),
        Literal::Field(literal) => JsonValue::String(literal.to_string()),
        Literal::Group(literal) => JsonValue::String(literal.to_string()),
        Literal::I8(literal) => JsonValue::from(**literal),
        Literal::I16(literal) => JsonValue::from(**literal),
        Literal::I32(literal) => JsonValue::from(**literal),
        Literal::I64(literal) => JsonValue::from(**literal),
        Literal::I128(literal) => JsonValue::String((**literal).to_string()),
        Literal::U8(literal) => JsonValue::from(**literal),
        Literal::U16(literal) => JsonValue::from(**literal),
        Literal::U32(literal) => JsonValue::from(**literal),
        Literal::U64(literal) => JsonValue::from(**literal),
        Literal::U128(literal) => JsonValue::String((**literal).to_string()),
        Literal::Scalar(literal) => JsonValue::String(literal.to_string()),
        Literal::Signature(literal) => JsonValue::String(literal.to_string()),
        Literal::String(literal) => JsonValue::String(literal.to_string()),
        Literal::Identifier(literal) => JsonValue::String(literal.to_string()),
    }
}

/// Serialize a [`Future`] into its `summary` value form (mirrors
/// `future_to_js_value`). The `id` mirrors the enclosing output's id, matching
/// the upstream helper's signature (which threads the same id into nested
/// futures).
fn future_to_json<N: Network>(future: &Future<N>, id: &Field<N>) -> JsonValue {
    serde_json::json!({
        "type": "future",
        "id": id.to_string(),
        "program": future.program_id().to_string(),
        "function": future.function_name().to_string(),
        "arguments": future.arguments().iter().map(|argument| argument_to_json::<N>(argument, id)).collect::<Vec<_>>(),
    })
}

/// Serialize a future [`Argument`] into its `summary` value form.
fn argument_to_json<N: Network>(argument: &Argument<N>, id: &Field<N>) -> JsonValue {
    match argument {
        Argument::Plaintext(plaintext) => plaintext_to_json::<N>(plaintext),
        Argument::Future(future) => future_to_json::<N>(future, id),
        Argument::DynamicFuture(dynamic_future) => match dynamic_future.to_future() {
            Ok(future) => future_to_json::<N>(&future, id),
            Err(_) => serde_json::json!({
                "type": "dynamic_future",
                "checksum": dynamic_future.checksum().to_string(),
            }),
        },
    }
}

#[cfg(test)]
#[path = "transaction_fixtures.rs"]
mod transaction_fixtures;

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::{
        Argument, DynamicFuture, Field, Future, Group, Identifier, Input, Literal, One, Output,
        Plaintext, PrivateKey, ProgramID, TestRng, TestnetV0, ViewKey,
    };
    use std::str::FromStr;

    type N = TestnetV0;
    /// `fromString` parses the JS SDK's execution transaction and the id matches.
    #[test]
    fn from_string_recovers_known_id() {
        let transaction =
            Transaction::<N>::from_string(transaction_fixtures::TRANSACTION_STRING).unwrap();
        assert_eq!(transaction.id(), transaction_fixtures::TRANSACTION_ID);
        assert_eq!(transaction.transaction_type(), "execute");
        assert!(transaction.is_execute());
        assert!(!transaction.is_deploy());
        assert!(!transaction.is_fee());
    }

    /// `toString` round-trips to a byte-identical string (the canonical JSON).
    #[test]
    fn to_string_round_trips() {
        let transaction =
            Transaction::<N>::from_string(transaction_fixtures::TRANSACTION_STRING).unwrap();
        let recovered = transaction.to_string();
        assert_eq!(recovered, transaction_fixtures::TRANSACTION_STRING);
        // And re-parsing the reprint yields the same transaction.
        let reparsed = Transaction::<N>::from_string(&recovered).unwrap();
        assert_eq!(reparsed, transaction);
    }

    /// `fromBytesLe` / `toBytesLe` are inverse.
    #[test]
    fn byte_serialization_roundtrip() {
        let transaction =
            Transaction::<N>::from_string(transaction_fixtures::TRANSACTION_STRING).unwrap();
        let bytes = transaction.to_bytes_le().unwrap();
        let recovered = Transaction::<N>::from_bytes_le(&bytes).unwrap();
        assert_eq!(recovered, transaction);
    }

    /// The informational methods classify deployment vs execution correctly.
    #[test]
    fn informational_method_correctness() {
        let deployment =
            Transaction::<N>::from_string(transaction_fixtures::DEPLOYMENT_TRANSACTION_STRING)
                .unwrap();
        let execution =
            Transaction::<N>::from_string(transaction_fixtures::TRANSACTION_STRING).unwrap();

        assert_eq!(deployment.transaction_type(), "deploy");
        assert!(deployment.is_deploy());
        assert!(!(deployment.is_execute() || deployment.is_fee()));

        assert_eq!(execution.transaction_type(), "execute");
        assert!(execution.is_execute());
        assert!(!(execution.is_deploy() || execution.is_fee()));
    }

    /// `deployedProgram` returns the program id of a deployment transaction.
    #[test]
    fn deployed_program_method() {
        let transaction =
            Transaction::<N>::from_string(transaction_fixtures::DEPLOYMENT_TRANSACTION_STRING)
                .unwrap();
        let program = transaction.deployed_program().unwrap();
        assert_eq!(program.id().to_string(), "paleo_token.aleo");
    }

    /// `execution` recovers the execution of an execution transaction.
    #[test]
    fn execution_method() {
        let transaction =
            Transaction::<N>::from_string(transaction_fixtures::TRANSACTION_STRING).unwrap();
        let execution = transaction.execution().unwrap();
        assert_eq!(
            execution.global_state_root().to_string(),
            "sr1cxx6uf72kla7hzu65m394fljpup39h3efe97xsn2wm2gl9apjgyqdr94ud"
        );
        assert_eq!(transaction.transitions().len(), 2);
    }

    /// Fee amounts fold to `0` for a non-fee-bearing transaction type here, and
    /// are plain `u64` otherwise. The execution transaction has a fee transition,
    /// so they are non-zero and consistent.
    #[test]
    fn fee_amounts_are_u64() {
        let execution =
            Transaction::<N>::from_string(transaction_fixtures::TRANSACTION_STRING).unwrap();
        let _: u64 = execution.fee_amount();
        let _: u64 = execution.base_fee_amount();
        let _: u64 = execution.priority_fee_amount();
        assert!(execution.fee_amount() > 0);
    }

    /// `findRecord` / contains_* locate a known commitment and serial number,
    /// and miss a random one — reusing the upstream literal vectors.
    #[test]
    fn record_lookup_methods() {
        let transaction =
            Transaction::<N>::from_string(transaction_fixtures::PRIVATE_TRANSACTION_STRING)
                .unwrap();

        let random = Field::<N>::from_str("1field").unwrap();
        assert!(transaction.find_record(&random).is_none());
        assert!(!transaction.contains_commitment(&random));
        assert!(!transaction.contains_serial_number(&random));

        let commitment = Field::<N>::from_str(
            "3771264214823666953346974490700157125043441681812666085949968314967709800215field",
        )
        .unwrap();
        let serial_number = Field::<N>::from_str(
            "780585721101033968543684654771473636769436273965503504834193318384750303851field",
        )
        .unwrap();
        assert!(transaction.find_record(&commitment).is_some());
        assert!(transaction.contains_commitment(&commitment));
        assert!(transaction.contains_serial_number(&serial_number));
    }

    /// `records` lists every record ciphertext; `ownedRecords` with an unrelated
    /// view key finds none (reuses the upstream `PRIVATE_TRANSACTION_STRING`).
    #[test]
    fn record_and_owned_record_methods() {
        let transaction =
            Transaction::<N>::from_string(transaction_fixtures::PRIVATE_TRANSACTION_STRING)
                .unwrap();
        assert_eq!(transaction.records().len(), 8);

        let private_key = PrivateKey::<N>::new(&mut TestRng::default()).unwrap();
        let view_key = ViewKey::<N>::try_from(private_key).unwrap();
        assert!(transaction.owned_records(&view_key).is_empty());
    }

    /// `transitions` returns the deployment/execution transitions.
    #[test]
    fn transitions_method() {
        let execution =
            Transaction::<N>::from_string(transaction_fixtures::TRANSACTION_STRING).unwrap();
        assert_eq!(execution.transitions().len(), 2);
        let deployment =
            Transaction::<N>::from_string(transaction_fixtures::DEPLOYMENT_TRANSACTION_STRING)
                .unwrap();
        assert_eq!(deployment.transitions().len(), 1);
    }

    /// `verifyingKeys` lists the deployment's functions with their keys.
    #[test]
    fn verifying_keys_method() {
        let deployment =
            Transaction::<N>::from_string(transaction_fixtures::DEPLOYMENT_TRANSACTION_STRING)
                .unwrap();
        let keys = deployment.verifying_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].program, "paleo_token.aleo");
        assert_eq!(keys[0].function, "register_token");
        assert!(keys[0].verifying_key.starts_with("verifier1"));
        assert!(!keys[0].certificate.is_empty());
    }

    /// `summary` reproduces the JS object: id/type/fees, the execution with its
    /// transitions, and the fee transition — pinned against upstream literals.
    #[test]
    fn summary_provides_expected_values() {
        let transaction =
            Transaction::<N>::from_string(transaction_fixtures::TRANSACTION_STRING).unwrap();
        let summary = transaction.summary(true);

        assert_eq!(summary["id"], transaction_fixtures::TRANSACTION_ID);
        assert_eq!(summary["type"], "execute");
        assert!(summary["feeAmount"].is_u64());
        assert!(summary["baseFee"].is_u64());
        assert!(summary["priorityFee"].is_u64());

        let execution = summary["execution"].as_object().unwrap();
        assert_eq!(
            execution["global_state_root"],
            "sr1cxx6uf72kla7hzu65m394fljpup39h3efe97xsn2wm2gl9apjgyqdr94ud"
        );
        assert_eq!(
            execution["proof"],
            "proof1qyqsqqqqqqqqqqqpqqqqqqqqqqqvs2nmr0pnyufteq8wtf080x3vwfh5yk08d6pjmedl8j7gx6a42das2ul7rm9x6wn5tvars43nudvqq9gshva80utleuytjesa4vmkq4cv6kfcm6axn2pwf7klzk402gf9qn5t0ssz3mut0ycjcjwss4e76qrh46q8r8calfmrwmpmwj2j063rsgtvq4v85v8gzlyyy233f90pztncnx9pr65l28vuqwx86n0p2xqws3lw0a2qs4smanr5eq78rgn2t2vtvnfu07589676v86kjxdfc6nqdvmghjvc25zzh7qwj2jxmk5qtu5ecxd8mpx00mjs4q2sen68w57zk6c3e7xnm7jeelrqhuexaae9n8v9ddagrl27wwn8zg8vwv9srrar48d0aqslsmzt6lqnxq2mwn0y89zxtrsfs8uzphrc3geu9y5pn2m90k45s5cqt4ypw8rqea53qprslzcs0xpuhc6gc59lfxk0fz49wj70pxe4wczpnxcendf6f7ep49svrsamw2nn39y02dt3l85ztqr09hcxd6h9382cq2s3j890g6ezu2lktszy278dxhuxj47qmmjs2m2p78ud9s3m7pkrusrqwj65f6qv4h0spx0jsrs0vcyapz868egt4g6jf9zwmdkfn5d4966234td44gzcvzwghl2tcxxpl0vt70366upqd7se7pf8vmlvujalgwglgzu2tnrp474nmuvewflrd6eg8j6usg5c6l5vydrkjav4lqx8n4d83nre9qex57ut3nunlyccedx3npxuqzu4fk6293yxxd0sd05jrtxkjpckqrvaaxnng22j9dxnlrvxm24ql5880tdnd8mwsmhz9hf4tnwlrl65xu2x9tuqz5c4nsha95hqlksj3mapzmc5672md4hckakxfpt28znt0st8p3xwt05a3usl3remvc9e5ng8quakjgax4aquczfqvdxzwstm8et5tgdptkt84wnklwn5c8cy93ezx7rh4jve5dn2t8zcn32vph0d8sx583j6uqz6sg8mjs6upgdsf47d6ageygydpve89p3tsshx5vt98jzet9hnkfacky5hpxgqlgnm0dvchgylg3prq05gq7kzdu8narls66gg7nxml0hzqsrh0lqez38m40dzt9zzg985frap8m43ehfk5z9lpsazc7jx0fyp2qcrncdqvqqqqqqqqqqqkfq8j9ez9zl7gycv3wzsjez8amk3lkrptn62v0xp805dmckhl38k3hn0vc5v54wre6m0n8mcvz3qyq2fchjxd29juplmjywlrfz83zkq2ev6mxryx5dz43tcwneamnpa5m6ezycmqed4dsfrm342e3693qqq8gj3sheypdtugcnxfuvw5pqn5glpxc8hy8efn8z366lm6l46luqpfn0c6cv8jnfkqg8x0djhm97ex4w43ljp2q3p48puy5qg7plrl3082j669dptpvp62h8wrmvl4ggsyqqxqxmd4"
        );

        let transitions = execution["transitions"].as_array().unwrap();
        assert_eq!(transitions.len(), 2);

        let transfer = transitions[0].as_object().unwrap();
        assert_eq!(transfer["program"], "credits.aleo");
        assert_eq!(transfer["function"], "transfer_public");
        assert_eq!(
            transfer["tpk"],
            "8419054782389922523785643599671399767271074354181851447409278470077027626643group"
        );
        assert_eq!(
            transfer["tcm"],
            "6974764911181620995275580693649999038426099390529716278259719011415424425408field"
        );
        assert_eq!(
            transfer["scm"],
            "5706857385070162410502976527403449803156980745820557401650769519800215382444field"
        );

        let inputs = transfer["inputs"].as_array().unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0]["type"], "public");
        assert_eq!(
            inputs[0]["id"],
            "4751135245718319934677221244600857477393936843410399077399851644790898074286field"
        );
        assert_eq!(
            inputs[0]["value"],
            "aleo1nde82xqshcyjq2r3qjel7pphk3zfs928w5dqhuc6g2ywquef7srsmrpjgr"
        );
        assert_eq!(inputs[1]["type"], "public");
        assert_eq!(
            inputs[1]["id"],
            "1879683531456735826402444579986765299787803396630464445477045553705002014280field"
        );
        // A `u64` literal serializes to a JSON *number* (mirrors the JS `literal_to_js_value`).
        assert_eq!(inputs[1]["value"], serde_json::json!(925201u64));

        let outputs = transfer["outputs"].as_array().unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0]["type"], "future");
        // The future's `program`/`function` live inside the nested `value`.
        assert_eq!(outputs[0]["value"]["program"], "credits.aleo");
        assert_eq!(outputs[0]["value"]["function"], "transfer_public");

        // The fee execution transition is mirrored under `fee`.
        let fee = summary["fee"].as_object().unwrap();
        let fee_transition = fee["transition"].as_object().unwrap();
        assert_eq!(fee_transition["program"], "credits.aleo");
        assert_eq!(fee_transition["function"], "fee_public");
        assert_eq!(
            fee_transition["tpk"],
            "5133974047416696841315369281389544483681028470433387841583387079449986330429group"
        );
    }

    /// The serialization helpers mirror the upstream `input_to_js_value` /
    /// `output_to_js_value` / `plaintext_to_js_value` / `literal_to_js_value` /
    /// `future_to_js_value` shapes. These unit tests pin every match arm so the
    /// structured `summary` cannot silently drift from the JS SDK.
    #[test]
    fn serialization_helpers_match_js_shapes() {
        const ADDR: &str = "aleo1nde82xqshcyjq2r3qjel7pphk3zfs928w5dqhuc6g2ywquef7srsmrpjgr";

        // --- `literal_to_json`: every variant serializes like `literal_to_js_value` ---
        let literal_cases: Vec<(&str, JsonValue)> = vec![
            ("true", JsonValue::Bool(true)),
            ("5field", JsonValue::String("5field".to_string())),
            ("5i8", JsonValue::from(5i8)),
            ("5i16", JsonValue::from(5i16)),
            ("5i32", JsonValue::from(5i32)),
            ("5i64", JsonValue::from(5i64)),
            ("5i128", JsonValue::String("5".to_string())),
            ("5u8", JsonValue::from(5u8)),
            ("5u16", JsonValue::from(5u16)),
            ("5u32", JsonValue::from(5u32)),
            ("5u64", JsonValue::from(5u64)),
            ("5u128", JsonValue::String("5".to_string())),
            ("5scalar", JsonValue::String("5scalar".to_string())),
            (ADDR, JsonValue::String(ADDR.to_string())),
            ("'my_id'", JsonValue::String("'my_id'".to_string())),
        ];
        for (src, expected) in literal_cases {
            let plaintext =
                Plaintext::<N>::from_str(src).unwrap_or_else(|e| panic!("parse {src}: {e}"));
            let Plaintext::Literal(literal, _) = &plaintext else {
                panic!("expected a literal plaintext for {src}");
            };
            assert_eq!(literal_to_json::<N>(literal), expected, "literal {src}");
        }
        // `Group` has no simple `from_str` literal form; cover it via the constructor.
        let g = Group::<N>::generator();
        assert_eq!(
            literal_to_json::<N>(&Literal::Group(g)),
            JsonValue::String(g.to_string())
        );

        // --- `plaintext_to_json`: literal / struct / array recurse correctly ---
        let literal_pt = Plaintext::<N>::from_str("5u64").unwrap();
        assert_eq!(plaintext_to_json::<N>(&literal_pt), JsonValue::from(5u64));
        let struct_pt = Plaintext::<N>::from_str("{ a: 5u64 }").unwrap();
        let struct_json = plaintext_to_json::<N>(&struct_pt);
        assert_eq!(struct_json["a"], JsonValue::from(5u64));
        let array_pt = Plaintext::<N>::from_str("[5u64, 6u64]").unwrap();
        let array_json = plaintext_to_json::<N>(&array_pt);
        assert_eq!(array_json.as_array().unwrap().len(), 2);

        // --- `request_to_json`: every `Input` variant ---
        let pt = Plaintext::<N>::from_str("5u64").unwrap();
        let r_constant =
            request_to_json::<N>(&Input::Constant(Field::<N>::one(), Some(pt.clone())));
        assert_eq!(r_constant["type"], "constant");
        assert_eq!(r_constant["id"], Field::<N>::one().to_string());
        assert_eq!(r_constant["value"], JsonValue::from(5u64));

        let r_public = request_to_json::<N>(&Input::Public(Field::<N>::one(), Some(pt)));
        assert_eq!(r_public["type"], "public");
        assert_eq!(r_public["value"], JsonValue::from(5u64));

        // A `Private` input without a ciphertext serializes `value` to `null`.
        let r_private = request_to_json::<N>(&Input::Private(Field::<N>::one(), None));
        assert_eq!(r_private["type"], "private");
        assert_eq!(r_private["value"], JsonValue::Null);

        let r_record = request_to_json::<N>(&Input::Record(Field::<N>::one(), Field::<N>::one()));
        assert_eq!(r_record["type"], "record");
        assert_eq!(r_record["tag"], Field::<N>::one().to_string());
        assert!(!r_record.as_object().unwrap().contains_key("value"));

        assert_eq!(
            request_to_json::<N>(&Input::ExternalRecord(Field::<N>::one()))["type"],
            "externalRecord"
        );
        assert_eq!(
            request_to_json::<N>(&Input::DynamicRecord(Field::<N>::one()))["type"],
            "record_dynamic"
        );
        let r_rwd = request_to_json::<N>(&Input::RecordWithDynamicID(
            Field::<N>::one(),
            Field::<N>::one(),
            Field::<N>::one(),
        ));
        assert_eq!(r_rwd["type"], "record_with_dynamic_id");
        assert_eq!(r_rwd["dynamic_id"], Field::<N>::one().to_string());
        let r_erwd = request_to_json::<N>(&Input::ExternalRecordWithDynamicID(
            Field::<N>::one(),
            Field::<N>::one(),
        ));
        assert_eq!(r_erwd["type"], "external_record_with_dynamic_id");
        assert_eq!(r_erwd["dynamic_id"], Field::<N>::one().to_string());

        // --- `response_to_json`: every `Output` variant ---
        let o_constant = response_to_json::<N>(&Output::Constant(
            Field::<N>::one(),
            Some(Plaintext::<N>::from_str("5u64").unwrap()),
        ));
        assert_eq!(o_constant["type"], "constant");
        assert_eq!(o_constant["value"], JsonValue::from(5u64));

        let o_private = response_to_json::<N>(&Output::Private(Field::<N>::one(), None));
        assert_eq!(o_private["type"], "private");
        assert_eq!(o_private["value"], JsonValue::Null);

        // Reuse a real record ciphertext from the private-transaction fixture.
        let private_tx =
            Transaction::<N>::from_string(transaction_fixtures::PRIVATE_TRANSACTION_STRING)
                .unwrap();
        let (commitment, record) = private_tx.records()[0].clone();
        let o_record = response_to_json::<N>(&Output::Record(
            commitment,
            Field::<N>::one(),
            Some(record.clone()),
            Some(Field::<N>::one()),
        ));
        assert_eq!(o_record["type"], "record");
        assert!(o_record["value"].is_string());
        assert!(o_record["sender_ciphertext"].is_string());
        assert!(!o_record.as_object().unwrap().contains_key("tag"));

        assert_eq!(
            response_to_json::<N>(&Output::ExternalRecord(Field::<N>::one()))["type"],
            "external_record"
        );
        assert_eq!(
            response_to_json::<N>(&Output::DynamicRecord(Field::<N>::one()))["type"],
            "record_dynamic"
        );
        let o_rwd = response_to_json::<N>(&Output::RecordWithDynamicID(
            Field::<N>::one(),
            Field::<N>::one(),
            Some(record.clone()),
            Some(Field::<N>::one()),
            Field::<N>::one(),
        ));
        assert_eq!(o_rwd["type"], "record_with_dynamic_id");
        assert_eq!(o_rwd["dynamic_id"], Field::<N>::one().to_string());
        let o_erwd = response_to_json::<N>(&Output::ExternalRecordWithDynamicID(
            Field::<N>::one(),
            Field::<N>::one(),
        ));
        assert_eq!(o_erwd["type"], "external_record_with_dynamic_id");
        assert_eq!(o_erwd["dynamic_id"], Field::<N>::one().to_string());

        // A `Future` output nests its `program`/`function` inside `value`.
        let program_id = ProgramID::<N>::from_str("credits.aleo").unwrap();
        let function_name = Identifier::<N>::from_str("transfer").unwrap();
        let future = Future::<N>::new(program_id, function_name, vec![]);
        let o_future =
            response_to_json::<N>(&Output::Future(Field::<N>::one(), Some(future.clone())));
        assert_eq!(o_future["type"], "future");
        assert_eq!(o_future["value"]["program"], "credits.aleo");
        assert_eq!(o_future["value"]["function"], "transfer");

        // --- `future_to_json` / `argument_to_json` ---
        let arg_plaintext = Plaintext::<N>::from_str("5u64").unwrap();
        let inner_future = Future::<N>::new(program_id, function_name, vec![]);
        let nested_future = Future::<N>::new(
            program_id,
            function_name,
            vec![Argument::Plaintext(arg_plaintext), Argument::Future(inner_future)],
        );
        let future_json = future_to_json::<N>(&nested_future, &Field::<N>::one());
        assert_eq!(future_json["type"], "future");
        assert_eq!(future_json["program"], "credits.aleo");
        assert_eq!(future_json["arguments"].as_array().unwrap().len(), 2);

        // `Argument::DynamicFuture` with arguments resolves to a static future.
        let with_args = DynamicFuture::<N>::from_future(&nested_future).unwrap();
        let resolved =
            argument_to_json::<N>(&Argument::DynamicFuture(with_args), &Field::<N>::one());
        assert_eq!(resolved["type"], "future");

        // `Argument::DynamicFuture` without arguments falls back to the
        // `dynamic_future` shape carrying only a checksum.
        let no_args = DynamicFuture::<N>::new_unchecked(
            Field::<N>::one(),
            Field::<N>::one(),
            Field::<N>::one(),
            Field::<N>::one(),
            None,
        );
        let fallback = argument_to_json::<N>(&Argument::DynamicFuture(no_args), &Field::<N>::one());
        assert_eq!(fallback["type"], "dynamic_future");
        assert!(fallback["checksum"].is_string());
    }
}
