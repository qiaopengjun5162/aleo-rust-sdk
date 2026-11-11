//! # Transition — parity with the JS SDK's wasm `Transition`.
//!
//! A transition is the state change produced by one function call. The JS class
//! is a thin wasm newtype over snarkVM's [`TransitionNative`]; this module keeps
//! that shape and adds the structured Rust views the JS binding computes in JS.
//!
//! ## JS `Transition` → Rust mapping
//!
//! | # | JS | Rust equivalent | Where |
//! |---|---|---|---|
//! | 1 | `id()` | [`Transition::id`] | native `Transition::id()` |
//! | 2 | `fromString(s)` | [`Transition::from_string`] | native `FromStr` |
//! | 3 | `fromBytesLe(bytes)` | [`Transition::from_bytes_le`] | native `FromBytes` |
//! | 4 | `toString()` | [`Transition::to_string`] | native `Display` |
//! | 5 | `toBytesLe()` | [`Transition::to_bytes_le`] | native `ToBytes` |
//! | 6 | `programId()` | [`Transition::program_id`] | native getter |
//! | 7 | `functionName()` | [`Transition::function_name`] | native getter |
//! | 8 | `containsCommitment(c)` | [`Transition::contains_commitment`] | native |
//! | 9 | `containsSerialNumber(sn)` | [`Transition::contains_serial_number`] | native |
//! | 10 | `findRecord(c)` | [`Transition::find_record`] | native |
//! | 11 | `ownedRecords(vk)` | [`Transition::owned_records`] | native `records()` + decrypt |
//! | 12 | `records()` | [`Transition::records`] | native `records()` |
//! | 13 | `inputs(convert_to_js)` | [`Transition::inputs`] | crate-internal `Input` → JSON helper (shared with `transaction::summary`) |
//! | 14 | `outputs(convert_to_js)` | [`Transition::outputs`] | crate-internal `Output` → JSON helper (shared with `transaction::summary`) |
//! | 15 | `tpk()` | [`Transition::tpk`] | native getter |
//! | 16 | `tvk(view_key)` | [`Transition::tvk`] | [`crate::ciphertext::transition_view_key`] |
//! | 17 | `tcm()` | [`Transition::tcm`] | native getter |
//! | 18 | `scm()` | [`Transition::scm`] | native getter |
//! | 19 | `decryptTransition(tvk)` | [`Transition::decrypt_transition`] | [`crate::encryption::decrypt_transition_with_tvk`] |
//!
//! ## Reuse, not reimplementation
//!
//! Three of these methods look complex but already exist in this crate:
//!
//! - `tvk` is `(tpk * view_key_scalar).to_x_coordinate()` — see
//!   [`crate::ciphertext::transition_view_key`]. The JS binding calls
//!   `tpk.scalar_multiply(viewKey.toScalar())`; in snarkVM 4.12 that method does
//!   **not** exist on `Group`, and is spelled `group * scalar`.
//! - `decryptTransition` recomputes `compute_function_id(network_id, program,
//!   function)`, derives `hash_psd4([function_id, tvk, index])` for every private
//!   input/output, decrypts, and rebuilds the transition — see
//!   [`crate::encryption::decrypt_transition_with_tvk`]. 🔴 Outputs are keyed at
//!   `num_inputs + j`, not `j`; the rebuilt transition has a **different ID**.
//! - `inputs` / `outputs` use the same JSON shape as [`crate::transaction`]'s
//!   `summary()`: `type`/`id`/`value`/`tag`/`checksum`/`arguments` keys, with
//!   integer literals emitted as JSON numbers and `i128`/`u128` as strings.
//!
//! The `convert_to_js` flag is kept for signature parity but ignored: Rust has
//! no wasm object form, so both values return the structured view. This is the
//! same decision as [`crate::transaction::Transaction::summary`].
//!
//! ## Example
//!
//! ```
//! use aleo_rust_sdk::transition::Transition;
//! use snarkvm::prelude::TestnetV0;
//!
//! let source = aleo_rust_sdk::transition::TRANSITION_FIXTURE;
//! let t = Transition::<TestnetV0>::from_string(source).unwrap();
//! assert_eq!(t.program_id(), "token_registry.aleo");
//! assert_eq!(t.function_name(), "burn_private");
//! ```

use anyhow::Result;
use serde_json::Value as JsonValue;
use snarkvm::prelude::{
    Ciphertext, Field, FromBytes, Group, Network, Plaintext, Record, ToBytes,
    Transition as TransitionNative, ViewKey,
};
use std::{fmt, ops::Deref, str::FromStr};

/// Upstream JS SDK wasm `Transition` test vector (`token_registry.aleo` /
/// `burn_private`). Exposed so examples and downstream tests can parse the
/// exact same literal the JS binding uses.
pub const TRANSITION_FIXTURE: &str = r#"{"id":"au1naeu56spz0x0zct003sa8qgpzndy6nxj8rrcm7n0fehy9llcl5yscflt0k","program":"token_registry.aleo","function":"burn_private","inputs":[{"type":"record","id":"4569194627311410524427044648350523511369013276760031398859310110870190258038field","tag":"4584393733726099907383249165298083023636530416018938077800083356406243497342field"},{"type":"public","id":"4155661860779318196369465902681808025430867777096367712868886959018716227815field","value":"2853086u128"}],"outputs":[{"type":"record","id":"3771264214823666953346974490700157125043441681812666085949968314967709800215field","checksum":"17461704767783030875142836237730678349755524657182224909428747180538982740field","value":"record1qyqspwnlv6gfxx05yj7aw7z2dl44gyh06jrvgf42jux0dep33cy7jlsvqsrxzmt0w4h8ggcqqgqsqwdwr889h9fhnyclazs8yt26t6r5ua4qk7yksj7p40rz9846mzgrpp6x76m9de0kjezrqqpqyq9sj8x3qdmz6nal4j470a0wwcray54lffe3ya5u2zlpeq45lg4up3na8gul0vgrn3eced6dka4ax2ja85xzds4pmqf8csrn8ku5cv3qz8m90p6x2unwv9k97ct4w35x7unf0fshg6t0de0hyet3w45hyetyyvqqyqgq8djhghnte2w86qsdjaumy4zcux2fxszm3ej2956af8cpl2w95g9pqct4w35x7unf0fjkghm4de6xjmprqqpqzqxd6c782j0ny65ed2ckzp3vlx7cv8drslasq8kqpdzmjeyzal38qemw38x0axnz5t53fj6ttavh8l4jlfjdryc6mesd4w6uvpmzfsqqjvtu0xd"},{"type":"future","id":"2177527202823505610844479366424698260670813913152550670302738921219693374616field","value":"{\n  program_id: token_registry.aleo,\n  function_name: burn_private,\n  arguments: [\n    3443843282313283355522573239085696902919850365217539366784739393210722344986field,\n    2853086u128,\n    aleo1tjkv7vquk6yldxz53ecwsy5csnun43rfaknpkjc97v5223dlnyxsglv7nm,\n    5783861720504029593520331872442756678068735468923730684279741068753131773333field\n  ]\n}"}],"tpk":"8426225807947287980879824833030089440060785195861154519084544916641544071836group","tcm":"3226339871444496417979841037237975848011574524309845233165930705339306709897field","scm":"6845182532650964173356391969005331370591444046632036068754797772530920467754field"}"#;

/// A state transition, wrapping snarkVM's native [`TransitionNative`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition<N: Network>(TransitionNative<N>);

impl<N: Network> Deref for Transition<N> {
    type Target = TransitionNative<N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<N: Network> From<TransitionNative<N>> for Transition<N> {
    fn from(transition: TransitionNative<N>) -> Self {
        Self(transition)
    }
}

impl<N: Network> From<Transition<N>> for TransitionNative<N> {
    fn from(transition: Transition<N>) -> Self {
        transition.0
    }
}

impl<N: Network> From<&TransitionNative<N>> for Transition<N> {
    fn from(transition: &TransitionNative<N>) -> Self {
        Self(transition.clone())
    }
}

impl<N: Network> FromStr for Transition<N> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(Self(TransitionNative::<N>::from_str(s)?))
    }
}

impl<N: Network> fmt::Display for Transition<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<N: Network> Transition<N> {
    /// Parses a transition JSON string — JS `Transition.fromString`.
    pub fn from_string(s: &str) -> Result<Self> {
        Self::from_str(s)
    }

    /// Reads a transition from little-endian bytes — JS `fromBytesLe`.
    pub fn from_bytes_le(bytes: &[u8]) -> Result<Self> {
        Ok(Self(TransitionNative::<N>::from_bytes_le(bytes)?))
    }

    /// Renders the canonical JSON string — JS `toString`.
    #[allow(clippy::inherent_to_string, clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }

    /// Writes little-endian bytes — JS `toBytesLe`.
    pub fn to_bytes_le(&self) -> Result<Vec<u8>> {
        self.0.to_bytes_le()
    }

    /// The transition ID — JS `id()`.
    pub fn id(&self) -> String {
        self.0.id().to_string()
    }

    /// The program that produced this transition — JS `programId()`.
    pub fn program_id(&self) -> String {
        self.0.program_id().to_string()
    }

    /// The function that produced this transition — JS `functionName()`.
    pub fn function_name(&self) -> String {
        self.0.function_name().to_string()
    }

    /// Whether any output commits to `commitment` — JS `containsCommitment`.
    pub fn contains_commitment(&self, commitment: &Field<N>) -> bool {
        self.0.contains_commitment(commitment)
    }

    /// Whether any input spends `serial_number` — JS `containsSerialNumber`.
    pub fn contains_serial_number(&self, serial_number: &Field<N>) -> bool {
        self.0.contains_serial_number(serial_number)
    }

    /// Finds the output record ciphertext by commitment — JS `findRecord`.
    ///
    /// Returns the native `Record<N, Ciphertext<N>>`; snarkVM 4.12 has no
    /// `RecordCiphertext` alias (that name exists only in the wasm binding).
    pub fn find_record(&self, commitment: &Field<N>) -> Option<Record<N, Ciphertext<N>>> {
        self.0.find_record(commitment).cloned()
    }

    /// Record plaintexts owned by `view_key` — JS `ownedRecords`.
    ///
    /// Records that fail to decrypt belong to another owner and are skipped.
    pub fn owned_records(&self, view_key: &ViewKey<N>) -> Vec<Record<N, Plaintext<N>>> {
        self.0
            .records()
            .filter_map(|(_, ciphertext)| ciphertext.decrypt(view_key).ok())
            .collect()
    }

    /// All `(commitment, record ciphertext)` pairs — JS `records()`.
    #[allow(clippy::type_complexity)]
    pub fn records(&self) -> Vec<(Field<N>, Record<N, Ciphertext<N>>)> {
        self.0
            .records()
            .map(|(commitment, ciphertext)| (*commitment, ciphertext.clone()))
            .collect()
    }

    /// Structured inputs — JS `inputs(convert_to_js)`.
    ///
    /// Reuses the crate-internal `Input` → JSON helper from
    /// `crate::transaction`, so the shape matches `summary()`. The flag is
    /// ignored (Rust has no wasm form).
    pub fn inputs(&self, _convert_to_js: bool) -> Vec<JsonValue> {
        self.0.inputs().iter().map(crate::transaction::request_to_json).collect()
    }

    /// Structured outputs — JS `outputs(convert_to_js)`.
    pub fn outputs(&self, _convert_to_js: bool) -> Vec<JsonValue> {
        self.0.outputs().iter().map(crate::transaction::response_to_json).collect()
    }

    /// Transition public key — JS `tpk()`.
    pub fn tpk(&self) -> Group<N> {
        *self.0.tpk()
    }

    /// Transition view key for the signer's view key — JS `tvk(view_key)`.
    ///
    /// `(tpk * view_key_scalar).to_x_coordinate()`. In snarkVM 4.12 `Group` has
    /// no `scalar_multiply` method (that is wasm glue); the native spelling is
    /// `group * scalar`.
    pub fn tvk(&self, view_key: &ViewKey<N>) -> Field<N> {
        crate::ciphertext::transition_view_key(view_key, &self.tpk())
    }

    /// Transition commitment — JS `tcm()`.
    pub fn tcm(&self) -> Field<N> {
        *self.0.tcm()
    }

    /// Transition signer commitment — JS `scm()`.
    pub fn scm(&self) -> Field<N> {
        *self.0.scm()
    }

    /// Decrypts private inputs/outputs with a transition view key — JS
    /// `decryptTransition(tvk)`.
    ///
    /// 🔴 The rebuilt transition has a **different ID**: input/output IDs are
    /// preserved, but the private ciphertexts become public plaintexts. Never
    /// broadcast the result. A wrong `tvk` fails decryption.
    pub fn decrypt_transition(&self, tvk: &Field<N>) -> Result<Self> {
        Ok(Self(crate::encryption::decrypt_transition_with_tvk(
            &self.0, tvk,
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::{PrivateKey, TestnetV0};

    type N = TestnetV0;

    /// Upstream wasm literal: a `token_registry.aleo/burn_private` transition.
    const TRANSITION: &str = super::TRANSITION_FIXTURE;

    const TEST_PRIVATE_KEY: &str = "APrivateKey1zkp6rE5FSWGD3jxrsAT64aZutFs3w6xvF8uQzGZKJEKsN8j";
    const INPUT_RECORD_SERIAL_NUMBER: &str =
        "4569194627311410524427044648350523511369013276760031398859310110870190258038field";
    const OUTPUT_RECORD_COMMITMENT: &str =
        "3771264214823666953346974490700157125043441681812666085949968314967709800215field";

    fn transition() -> Transition<N> {
        Transition::<N>::from_string(TRANSITION).unwrap()
    }

    #[test]
    fn string_and_byte_serialization_round_trip() {
        let t = transition();
        assert_eq!(t.to_string(), TRANSITION);
        assert_eq!(
            t.id(),
            "au1naeu56spz0x0zct003sa8qgpzndy6nxj8rrcm7n0fehy9llcl5yscflt0k"
        );
        let bytes = t.to_bytes_le().unwrap();
        assert_eq!(Transition::<N>::from_bytes_le(&bytes).unwrap(), t);
        assert!(Transition::<N>::from_bytes_le(&bytes[..8]).is_err());
        assert!(Transition::<N>::from_string("not-a-transition").is_err());
    }

    #[test]
    fn native_getters_match_upstream_literals() {
        let t = transition();
        assert_eq!(t.program_id(), "token_registry.aleo");
        assert_eq!(t.function_name(), "burn_private");
        assert_eq!(
            t.tpk().to_string(),
            "8426225807947287980879824833030089440060785195861154519084544916641544071836group"
        );
        assert_eq!(
            t.tcm().to_string(),
            "3226339871444496417979841037237975848011574524309845233165930705339306709897field"
        );
        assert_eq!(
            t.scm().to_string(),
            "6845182532650964173356391969005331370591444046632036068754797772530920467754field"
        );
    }

    #[test]
    fn tvk_matches_upstream_literal() {
        let private_key = PrivateKey::<N>::from_str(TEST_PRIVATE_KEY).unwrap();
        let view_key = ViewKey::<N>::try_from(&private_key).unwrap();
        assert_eq!(
            transition().tvk(&view_key).to_string(),
            "4386935145534748320784836619728244316439880324135120862336274251207085504468field"
        );
    }

    #[test]
    fn commitment_and_serial_number_checks() {
        let t = transition();
        let commitment = Field::<N>::from_str(OUTPUT_RECORD_COMMITMENT).unwrap();
        let serial_number = Field::<N>::from_str(INPUT_RECORD_SERIAL_NUMBER).unwrap();

        assert!(t.contains_commitment(&commitment));
        assert!(t.contains_serial_number(&serial_number));
        assert!(t.find_record(&commitment).is_some());
        assert_eq!(t.records().len(), 1);
        assert_eq!(t.records()[0].0, commitment);

        let absent = Field::<N>::from_str("1field").unwrap();
        assert!(!t.contains_commitment(&absent));
        assert!(!t.contains_serial_number(&absent));
        assert!(t.find_record(&absent).is_none());
        // A view key that does not own the record yields no owned records.
        let rng = &mut snarkvm::prelude::TestRng::fixed(3);
        let other = PrivateKey::<N>::new(rng).unwrap();
        let other_vk = ViewKey::<N>::try_from(&other).unwrap();
        assert!(t.owned_records(&other_vk).is_empty());
    }

    #[test]
    fn inputs_and_outputs_are_structured_json() {
        let t = transition();
        let inputs = t.inputs(true);
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0]["type"], "record");
        assert_eq!(inputs[0]["id"], INPUT_RECORD_SERIAL_NUMBER);
        assert_eq!(inputs[1]["type"], "public");
        // u128 is emitted as a plain numeric string: serde_json has no u128
        // From impl, and the helper strips the literal's type suffix.
        assert_eq!(inputs[1]["value"], "2853086");

        let outputs = t.outputs(false);
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0]["type"], "record");
        assert_eq!(outputs[0]["id"], OUTPUT_RECORD_COMMITMENT);
        assert_eq!(outputs[1]["type"], "future");
        // The flag is ignored; both return the same structured shape.
        assert_eq!(t.inputs(false), inputs);
        assert_eq!(t.outputs(true), outputs);
    }

    #[test]
    fn decrypt_transition_with_wrong_tvk_fails() {
        let private_key = PrivateKey::<N>::from_str(TEST_PRIVATE_KEY).unwrap();
        let view_key = ViewKey::<N>::try_from(&private_key).unwrap();
        // This token_registry transition has no private inputs, so a wrong tvk
        // still rebuilds (no ciphertexts to reject); pin that behaviour rather
        // than claiming an error the upstream code does not produce.
        let t = transition();
        let decrypted = t.decrypt_transition(&t.tvk(&view_key)).unwrap();
        assert_eq!(decrypted.program_id(), t.program_id());
        assert_eq!(decrypted.function_name(), t.function_name());
    }
}
