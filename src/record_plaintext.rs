//! # RecordPlaintext — parity with the JS SDK's wasm `RecordPlaintext`.
//!
//! A decrypted Aleo record. The JS class is a wasm newtype over snarkVM's
//! `Record<CurrentNetwork, Plaintext<CurrentNetwork>>`; this module keeps that
//! shape but stays generic over [`Network`], and reuses the JSON/sender helpers
//! this crate already built for the `Plaintext` and `EncryptionToolkit` pages.
//!
//! ## JS `RecordPlaintext` → Rust mapping
//!
//! | # | JS | Rust equivalent | Where |
//! |---|---|---|---|
//! | 1 | `fromString(record)` | [`RecordPlaintext::from_string`] | native `FromStr` |
//! | 2 | `toString()` | `record.to_string()` | `Display` (blanket `ToString`) |
//! | 3 | `commitment(program_id, name, rvk)` | [`RecordPlaintext::commitment`] | native `to_commitment` + parse |
//! | 4 | `getMember(input)` | [`RecordPlaintext::get_member`] | **this module** (entry unwrapping) |
//! | 5 | `owner()` | [`RecordPlaintext::owner`] | **this module** (public/private owner) |
//! | 6 | `toJsObject()` | [`RecordPlaintext::to_js_object`] | `crate::plaintext::to_json_value` |
//! | 7 | `fromBytesLe(bytes)` | [`RecordPlaintext::from_bytes_le`] | native `FromBytes` |
//! | 8 | `toBytesLe()` | [`RecordPlaintext::to_bytes_le`] | native `ToBytes` |
//! | 9 | `toBitsLe()` | [`RecordPlaintext::to_bits_le`] | native `ToBits` |
//! | 10 | `toFields()` | [`RecordPlaintext::to_fields`] | native `ToFields` |
//! | 11 | `microcredits()` | [`RecordPlaintext::microcredits`] | **this module** (returns 0 when absent) |
//! | 12 | `nonce()` | [`RecordPlaintext::nonce`] | native getter |
//! | 13 | `serialNumberString(pk, pid, name, rvk)` | [`RecordPlaintext::serial_number_string`] | native `Record::serial_number` |
//! | 14 | `tag(graph_key, commitment)` | [`RecordPlaintext::tag`] | native `Record::tag` |
//! | 15 | `recordViewKey(view_key)` | [`RecordPlaintext::record_view_key`] | **this module** (`nonce · vk` → x) |
//! | 16 | `decryptSender(view_key, ct)` | [`RecordPlaintext::decrypt_sender`] | [`crate::encryption::decrypt_sender`] |
//! | 17 | `clone()` | `record.clone()` | derived `Clone` |
//!
//! The upstream source also has `gamma(program_id, record_name, private_key)`
//! (not listed on this doc page); [`RecordPlaintext::gamma`] implements it so
//! the serial-number formula is fully covered.
//!
//! ## Reuse, not reimplementation
//!
//! * `toJsObject` inserts `owner` and `_nonce` as strings, then every data
//!   entry converted by `crate::plaintext::to_json_value`. 🔴 It is
//!   **lossy**: visibility (`.private`/`.public`) and `_version` are dropped,
//!   so the result cannot be parsed back into a record. JS returns BigInt for
//!   64/128-bit integers; Rust keeps `u64`/`i64` exact in `serde_json::Number`
//!   and emits `u128`/`i128` as strings (serde_json has no 128-bit number).
//! * `decryptSender` forwards to [`crate::encryption::decrypt_sender`], which
//!   derives the record view key and inverts
//!   `sender_ciphertext = signer_x + hash_psd4([encryption_domain, rvk, 1])`.
//! * `serialNumberString` chains [`RecordPlaintext::commitment`] into the native
//!   `Record::serial_number(private_key, commitment)` — no second copy of the
//!   `hash_to_group_psd2` / `commit_bhp512` formula.
//!
//! ## 🔴 `nonce()` returns a type, not a string
//!
//! The JS page returns a `string` for `nonce()`, while `recordViewKey` and
//! `decryptSender` need the group element itself. Rust returns [`Group<N>`];
//! `.to_string()` yields exactly the JS string. The same `Group * Scalar`
//! substitution applies: snarkVM 4.12 has no `Group::scalar_multiply`.
//!
//! ## Example
//!
//! ```
//! use aleo_rust_sdk::record_plaintext::{RecordPlaintext, CREDITS_RECORD_FIXTURE};
//! use snarkvm::prelude::{FromStr, PrivateKey, TestnetV0, ViewKey};
//!
//! let record = RecordPlaintext::<TestnetV0>::from_string(CREDITS_RECORD_FIXTURE).unwrap();
//! assert_eq!(record.microcredits(), 1_500_000_000_000_000);
//! assert_eq!(
//!     record.owner().unwrap().to_string(),
//!     "aleo1j7qxyunfldj2lp8hsvy7mw5k8zaqgjfyr72x2gh3x4ewgae8v5gscf5jh3"
//! );
//!
//! let private_key = PrivateKey::<TestnetV0>::from_str(
//!     "APrivateKey1zkpDeRpuKmEtLNPdv57aFruPepeH1aGvTkEjBo8bqTzNUhE",
//! )
//! .unwrap();
//! let view_key = ViewKey::try_from(&private_key).unwrap();
//! let rvk = record.record_view_key(&view_key);
//! let serial_number = record
//!     .serial_number_string(&private_key, "credits.aleo", "credits", &rvk.to_string())
//!     .unwrap();
//! assert_eq!(
//!     serial_number,
//!     "8170619507075647151199239049653235187042661744691458644751012032123701508940field"
//! );
//! ```

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use snarkvm::prelude::{
    Address, Entry, Field, FromBytes, GraphKey, Group, Identifier, Literal, Network, Owner,
    Plaintext, PrivateKey, ProgramID, Record, ToBits, ToBytes, ToFields, ViewKey,
};
use std::{fmt, ops::Deref, str::FromStr};

/// Upstream JS SDK wasm `RecordPlaintext` test vector
/// (`wasm/src/record/record_plaintext.rs`). Exposed so examples and downstream
/// tests can parse the exact same literal the JS binding uses.
pub const CREDITS_RECORD_FIXTURE: &str = r"{
  owner: aleo1j7qxyunfldj2lp8hsvy7mw5k8zaqgjfyr72x2gh3x4ewgae8v5gscf5jh3.private,
  microcredits: 1500000000000000u64.private,
  _nonce: 3077450429259593211617823051143573281856129402760267155982965992208217472983group.public,
  _version: 0u8.public
}";

/// A decrypted Aleo record, wrapping snarkVM's native `Record<N, Plaintext<N>>`.
#[derive(Clone, PartialEq, Eq)]
pub struct RecordPlaintext<N: Network>(Record<N, Plaintext<N>>);

/// The `Entry` visibility wrapper carries no data for a plaintext record's
/// JSON view — all three variants hold the same `Plaintext<N>`.
fn entry_plaintext<N: Network>(entry: &Entry<N, Plaintext<N>>) -> &Plaintext<N> {
    match entry {
        Entry::Constant(value) | Entry::Public(value) | Entry::Private(value) => value,
    }
}

impl<N: Network> RecordPlaintext<N> {
    /// Parses a plaintext record string — JS `fromString(record)`.
    ///
    /// # Errors
    /// Fails when the string is not a valid record (bad owner, malformed
    /// literal, reserved `_nonce`, or missing visibility).
    pub fn from_string(record: &str) -> Result<Self> {
        Self::from_str(record)
    }

    /// Computes the record commitment — JS `commitment(program_id, record_name, rvk)`.
    ///
    /// The JS binding takes three strings and parses them internally; Rust
    /// keeps the same ergonomics but reports which of the three failed.
    ///
    /// # Errors
    /// Fails when any argument does not parse, or when the BHP hash fails.
    pub fn commitment(
        &self,
        program_id: &str,
        record_name: &str,
        record_view_key: &str,
    ) -> Result<Field<N>> {
        let program_id =
            ProgramID::<N>::from_str(program_id).context("Invalid record program ID")?;
        let record_name = Identifier::<N>::from_str(record_name).context("Invalid record name")?;
        let record_view_key =
            Field::<N>::from_str(record_view_key).context("Invalid record view key")?;
        self.0.to_commitment(&program_id, &record_name, &record_view_key)
    }

    /// Returns a data member — JS `getMember(input)`.
    ///
    /// All three visibility variants (`constant`/`public`/`private`) hold the
    /// same plaintext after decryption, so the wrapper is simply unwrapped.
    /// The reserved `owner`/`_nonce`/`_version` fields are **not** in `data()`;
    /// use [`Self::owner`] and [`Self::nonce`] for those.
    ///
    /// # Errors
    /// Fails when the key is not a valid identifier or has no entry.
    pub fn get_member(&self, key: &str) -> Result<Plaintext<N>> {
        let identifier = Identifier::<N>::from_str(key).context("Invalid record member name")?;
        let entry = self
            .0
            .data()
            .get(&identifier)
            .with_context(|| format!("Record member `{key}` not found"))?;
        Ok(entry_plaintext(entry).clone())
    }

    /// Returns the owner address — JS `owner()`.
    ///
    /// A decrypted record normally has a private owner, stored as an address
    /// literal inside a [`Plaintext`]; both variants are handled.
    ///
    /// # Errors
    /// Fails only if a private owner is not an address literal (corrupt input).
    pub fn owner(&self) -> Result<Address<N>> {
        match self.0.owner() {
            Owner::Public(address) => Ok(*address),
            Owner::Private(Plaintext::Literal(Literal::Address(address), ..)) => Ok(*address),
            Owner::Private(_) => bail!("Private owner is not an address literal"),
        }
    }

    /// Converts the record to a JSON object — JS `toJsObject()`.
    ///
    /// 🔴 **Not reversible**: visibility markers and `_version` are dropped.
    /// Returns `owner` and `_nonce` as strings, plus every data member with
    /// literals mapped to JSON numbers/strings and structs to nested objects.
    /// 128-bit integers become strings because `serde_json::Number` has no
    /// 128-bit variant (JS uses BigInt).
    ///
    /// # Errors
    /// Fails when the owner is not an address literal.
    pub fn to_js_object(&self) -> Result<Value> {
        let mut object = Map::new();
        object.insert(
            "owner".to_string(),
            Value::String(self.owner()?.to_string()),
        );
        object.insert(
            "_nonce".to_string(),
            Value::String(self.nonce().to_string()),
        );
        for (key, entry) in self.0.data() {
            object.insert(
                key.to_string(),
                crate::plaintext::to_json_value(entry_plaintext(entry)),
            );
        }
        Ok(Value::Object(object))
    }

    /// Reconstructs a record from little-endian bytes — JS `fromBytesLe(bytes)`.
    ///
    /// # Errors
    /// Fails when the bytes are not a valid plaintext record.
    pub fn from_bytes_le(bytes: &[u8]) -> Result<Self> {
        Ok(Self(Record::<N, Plaintext<N>>::read_le(bytes)?))
    }

    /// Serializes to little-endian bytes — JS `toBytesLe()`.
    ///
    /// # Errors
    /// Fails when the record cannot be serialized.
    pub fn to_bytes_le(&self) -> Result<Vec<u8>> {
        self.0.to_bytes_le()
    }

    /// Returns the little-endian bit representation — JS `toBitsLe()`.
    ///
    /// Rust returns a `Vec<bool>` instead of a JS `Array`.
    pub fn to_bits_le(&self) -> Vec<bool> {
        self.0.to_bits_le()
    }

    /// Returns the field-element representation — JS `toFields()`.
    ///
    /// # Errors
    /// Fails when the record exceeds the network's maximum data size.
    pub fn to_fields(&self) -> Result<Vec<Field<N>>> {
        self.0.to_fields()
    }

    /// Returns the `microcredits` entry, or 0 when it is absent/not `u64` —
    /// JS `microcredits()`.
    ///
    /// The upstream binding calls a `Credits` trait that is not part of
    /// snarkVM's `Record`; reading the entry directly keeps the same
    /// `unwrap_or(0)` semantics without introducing a new trait.
    pub fn microcredits(&self) -> u64 {
        let Ok(identifier) = Identifier::<N>::from_str("microcredits") else {
            return 0;
        };
        match self.0.data().get(&identifier).map(entry_plaintext) {
            Some(Plaintext::Literal(Literal::U64(value), ..)) => **value,
            _ => 0,
        }
    }

    /// Returns the record nonce — JS `nonce()` (JS returns its string form).
    pub fn nonce(&self) -> Group<N> {
        *self.0.nonce()
    }

    /// Computes the serial number string — JS `serialNumberString(pk, pid, name, rvk)`.
    ///
    /// Chains [`Self::commitment`] into the native
    /// `Record::serial_number(private_key, commitment)`.
    ///
    /// # Errors
    /// Fails when any argument does not parse or the commitment/serial-number
    /// primitive fails.
    pub fn serial_number_string(
        &self,
        private_key: &PrivateKey<N>,
        program_id: &str,
        record_name: &str,
        record_view_key: &str,
    ) -> Result<String> {
        let commitment = self.commitment(program_id, record_name, record_view_key)?;
        let serial_number = Record::<N, Plaintext<N>>::serial_number(*private_key, commitment)?;
        Ok(serial_number.to_string())
    }

    /// Computes the record tag — JS `tag(graph_key, commitment)`.
    ///
    /// Like the upstream binding, `self` is unused: the formula is
    /// `hash_psd2(sk_tag, commitment)`.
    ///
    /// # Errors
    /// Fails only if the network hash primitive fails.
    pub fn tag(&self, graph_key: &GraphKey<N>, commitment: Field<N>) -> Result<Field<N>> {
        Record::<N, Plaintext<N>>::tag(graph_key.sk_tag(), commitment)
    }

    /// Derives this record's view key — JS `recordViewKey(view_key)`.
    ///
    /// `(nonce * view_key).to_x_coordinate()`.
    pub fn record_view_key(&self, view_key: &ViewKey<N>) -> Field<N> {
        (*self.0.nonce() * **view_key).to_x_coordinate()
    }

    /// Recovers the sender address — JS `decryptSender(view_key, sender_ciphertext)`.
    ///
    /// 🔴 Any field is a valid sender ciphertext, so a wrong view key yields
    /// *some* address rather than an error. Compare against an expected signer
    /// when sender identity is security-relevant.
    ///
    /// # Errors
    /// Fails when the decrypted x-coordinate is not a valid address.
    pub fn decrypt_sender(
        &self,
        view_key: &ViewKey<N>,
        sender_ciphertext: &Field<N>,
    ) -> Result<Address<N>> {
        crate::encryption::decrypt_sender(view_key, &self.0, sender_ciphertext)
    }

    /// Computes the record's `gamma` — upstream `gamma(pid, name, pk)`.
    ///
    /// Not listed on the doc page but present in the upstream wasm source.
    /// `gamma = sk_sig · HashToGroup(serial_number_domain, commitment)`; the
    /// native `Record::serial_number` uses exactly this value, which the tests
    /// pin via `serial_number_from_gamma`.
    ///
    /// # Errors
    /// Fails when the program ID/record name do not parse or a hash primitive
    /// fails.
    pub fn gamma(
        &self,
        program_id: &str,
        record_name: &str,
        private_key: &PrivateKey<N>,
    ) -> Result<Group<N>> {
        let view_key = ViewKey::<N>::try_from(private_key).context("Invalid private key")?;
        let program_id =
            ProgramID::<N>::from_str(program_id).context("Invalid record program ID")?;
        let name = Identifier::<N>::from_str(record_name).context("Invalid record name")?;
        let record_view_key = (*self.0.nonce() * *view_key).to_x_coordinate();
        let commitment = self.0.to_commitment(&program_id, &name, &record_view_key)?;
        let h = N::hash_to_group_psd2(&[N::serial_number_domain(), commitment])?;
        Ok(h * private_key.sk_sig())
    }
}

impl<N: Network> Deref for RecordPlaintext<N> {
    type Target = Record<N, Plaintext<N>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<N: Network> fmt::Debug for RecordPlaintext<N> {
    /// The native `Record` has no `Debug`, so print the canonical record text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RecordPlaintext").field(&self.0.to_string()).finish()
    }
}

impl<N: Network> fmt::Display for RecordPlaintext<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<N: Network> FromStr for RecordPlaintext<N> {
    type Err = anyhow::Error;

    fn from_str(plaintext: &str) -> Result<Self> {
        Record::<N, Plaintext<N>>::from_str(plaintext).map(Self)
    }
}

impl<N: Network> From<Record<N, Plaintext<N>>> for RecordPlaintext<N> {
    fn from(record: Record<N, Plaintext<N>>) -> Self {
        Self(record)
    }
}

impl<N: Network> From<RecordPlaintext<N>> for Record<N, Plaintext<N>> {
    fn from(record: RecordPlaintext<N>) -> Self {
        record.0
    }
}

impl<N: Network> AsRef<Record<N, Plaintext<N>>> for RecordPlaintext<N> {
    fn as_ref(&self) -> &Record<N, Plaintext<N>> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::{One, SizeInDataBits, TestnetV0};

    type N = TestnetV0;

    /// Upstream `wasm/src/record/record_plaintext.rs` test vectors.
    const BATTLESHIP_RECORD: &str = r"{
  owner: aleo1kh5t7m30djl0ecdn4f5vuzp7dx0tcwh7ncquqjkm4matj2p2zqpqm6at48.private,
  metadata: {
    player1: aleo1kh5t7m30djl0ecdn4f5vuzp7dx0tcwh7ncquqjkm4matj2p2zqpqm6at48.private,
    player2: aleo1dreuxnmg9cny8ee9v2u0wr4v4affnwm09u2pytfwz0f2en2shgqsdsfjn6.private,
    nonce: 660310649780728486489183263981322848354071976582883879926426319832534836534field.private
  },
  id: 1953278585719525811355617404139099418855053112960441725284031425961000152405field.private,
  positions: 50794271u64.private,
  attempts: 0u64.private,
  hits: 0u64.private,
  _nonce: 5668100912391182624073500093436664635767788874314097667746354181784048204413group.public,
  _version: 0u8.public
}";
    const PRIVATE_KEY: &str = "APrivateKey1zkpDeRpuKmEtLNPdv57aFruPepeH1aGvTkEjBo8bqTzNUhE";
    const EXPECTED_SERIAL_NUMBER: &str =
        "8170619507075647151199239049653235187042661744691458644751012032123701508940field";
    /// From `wasm/src/record/record_ciphertext.rs` — the same credits record.
    const OWNER_VIEW_KEY: &str = "AViewKey1ccEt8A2Ryva5rxnKcAbn7wgTaTsb79tzkKHFpeKsm9NX";
    const RECORD_TAG: &str =
        "1796466189545157638691489609907096471289658804813960182690905095269699169603field";
    /// From `wasm/src/utilities/test/records.rs` — upstream sender decryption.
    const CREDITS_RECORD_VIEW_KEY: &str =
        "5237002936265850807349726649400053591020997883662246784632368923777787639801field";
    const CREDITS_SENDER_CIPHERTEXT: &str =
        "1182590395568997043375432557467567048762179115999922880321493200728848194550field";
    const CREDITS_SENDER_PLAINTEXT: &str =
        "aleo1j92w9mhqznj2hvufad796y8suykjppk7f6n6xmncmktfm95vggzqx4sjlh";

    fn credits() -> RecordPlaintext<N> {
        RecordPlaintext::<N>::from_string(CREDITS_RECORD_FIXTURE).expect("fixture parses")
    }

    fn private_key() -> PrivateKey<N> {
        PrivateKey::<N>::from_str(PRIVATE_KEY).expect("literal private key parses")
    }

    #[test]
    fn string_roundtrip_clone_and_invalid_input() {
        let record = credits();
        assert_eq!(record.to_string(), CREDITS_RECORD_FIXTURE);
        assert_eq!(record.clone(), record);
        assert_eq!(
            RecordPlaintext::<N>::from_str(CREDITS_RECORD_FIXTURE).unwrap(),
            record
        );
        assert!(RecordPlaintext::<N>::from_string("string").is_err());
    }

    #[test]
    fn bytes_bits_fields_and_nonce() {
        let record = credits();
        let bytes = record.to_bytes_le().unwrap();
        assert!(!bytes.is_empty());
        assert_eq!(RecordPlaintext::<N>::from_bytes_le(&bytes).unwrap(), record);
        assert!(RecordPlaintext::<N>::from_bytes_le(&[0u8; 4]).is_err());

        let bits = record.to_bits_le();
        assert!(!bits.is_empty());
        let fields = record.to_fields().unwrap();
        assert_eq!(
            fields.len(),
            (bits.len() + 1).div_ceil(Field::<N>::size_in_data_bits())
        );
        assert_eq!(
            record.nonce().to_string(),
            "3077450429259593211617823051143573281856129402760267155982965992208217472983group"
        );
    }

    #[test]
    fn owner_and_microcredits_match_upstream() {
        let record = credits();
        assert_eq!(
            record.owner().unwrap().to_string(),
            "aleo1j7qxyunfldj2lp8hsvy7mw5k8zaqgjfyr72x2gh3x4ewgae8v5gscf5jh3"
        );
        assert_eq!(record.microcredits(), 1_500_000_000_000_000);
        // A record without a `microcredits` entry returns 0, like upstream's
        // `.unwrap_or(0)`.
        assert_eq!(
            RecordPlaintext::<N>::from_string(BATTLESHIP_RECORD).unwrap().microcredits(),
            0
        );
    }

    #[test]
    fn get_member_matches_upstream_literals() {
        let record = RecordPlaintext::<N>::from_string(BATTLESHIP_RECORD).unwrap();
        assert_eq!(
            record.get_member("positions").unwrap().to_string(),
            "50794271u64"
        );
        assert_eq!(record.get_member("hits").unwrap().to_string(), "0u64");
        let metadata = record.get_member("metadata").unwrap();
        let object = crate::plaintext::to_json_value(&metadata);
        assert_eq!(
            object["player1"],
            Value::String("aleo1kh5t7m30djl0ecdn4f5vuzp7dx0tcwh7ncquqjkm4matj2p2zqpqm6at48".into())
        );
        assert_eq!(
            object["player2"],
            Value::String("aleo1dreuxnmg9cny8ee9v2u0wr4v4affnwm09u2pytfwz0f2en2shgqsdsfjn6".into())
        );
        assert_eq!(
            object["nonce"],
            Value::String(
                "660310649780728486489183263981322848354071976582883879926426319832534836534field"
                    .into()
            )
        );
        assert!(record.get_member("missing").is_err());
        assert!(record.get_member("not an identifier").is_err());
    }

    #[test]
    fn to_js_object_matches_upstream_shape() {
        let record = RecordPlaintext::<N>::from_string(BATTLESHIP_RECORD).unwrap();
        let object = record.to_js_object().unwrap();
        assert_eq!(
            object["owner"],
            Value::String("aleo1kh5t7m30djl0ecdn4f5vuzp7dx0tcwh7ncquqjkm4matj2p2zqpqm6at48".into())
        );
        assert_eq!(
            object["_nonce"],
            Value::String(
                "5668100912391182624073500093436664635767788874314097667746354181784048204413group"
                    .into()
            )
        );
        // Lossy conversion: visibility markers and `_version` are gone.
        assert_eq!(object["positions"], Value::from(50_794_271_u64));
        assert_eq!(object["attempts"], Value::from(0));
        assert_eq!(object["hits"], Value::from(0));
        assert!(object.get("_version").is_none());
        assert!(object["metadata"].is_object());
    }

    #[test]
    fn serial_number_matches_upstream_literal_twice() {
        let record = credits();
        let pk = private_key();
        let vk = ViewKey::<N>::try_from(&pk).unwrap();
        let rvk = record.record_view_key(&vk);
        let rvk_string = rvk.to_string();
        // Upstream pins that the derivation is deterministic across calls.
        for _ in 0..2 {
            assert_eq!(
                record
                    .serial_number_string(&pk, "credits.aleo", "credits", &rvk_string)
                    .unwrap(),
                EXPECTED_SERIAL_NUMBER
            );
        }
        assert!(
            record
                .serial_number_string(&pk, "not a real program id", "credits", &rvk_string)
                .is_err()
        );
        assert!(
            record
                .serial_number_string(&pk, "credits.aleo", "not a real record name", &rvk_string)
                .is_err()
        );
        assert!(
            record
                .serial_number_string(&pk, "credits.aleo", "credits", "not a field")
                .is_err()
        );
    }

    #[test]
    fn commitment_and_tag_match_upstream_vectors() {
        let record = credits();
        let vk = ViewKey::<N>::from_str(OWNER_VIEW_KEY).unwrap();
        let rvk = record.record_view_key(&vk);
        let commitment = record.commitment("credits.aleo", "credits", &rvk.to_string()).unwrap();
        let graph_key = GraphKey::<N>::try_from(&vk).unwrap();
        assert_eq!(
            record.tag(&graph_key, commitment).unwrap().to_string(),
            RECORD_TAG
        );
    }

    #[test]
    fn gamma_feeds_the_native_serial_number_formula() {
        let record = credits();
        let pk = private_key();
        let vk = ViewKey::<N>::try_from(&pk).unwrap();
        let rvk = record.record_view_key(&vk);
        let commitment = record.commitment("credits.aleo", "credits", &rvk.to_string()).unwrap();
        let gamma = record.gamma("credits.aleo", "credits", &pk).unwrap();
        let from_gamma =
            Record::<N, Plaintext<N>>::serial_number_from_gamma(&gamma, commitment).unwrap();
        let direct = Record::<N, Plaintext<N>>::serial_number(pk, commitment).unwrap();
        assert_eq!(from_gamma, direct);
        assert_eq!(direct.to_string(), EXPECTED_SERIAL_NUMBER);
    }

    #[test]
    fn decrypt_sender_roundtrips_and_upstream_literals_decrypt() {
        let record = credits();
        let pk = private_key();
        let vk = ViewKey::<N>::try_from(&pk).unwrap();
        let rvk = record.record_view_key(&vk);
        let signer = Address::<N>::from_str(
            "aleo1j92w9mhqznj2hvufad796y8suykjppk7f6n6xmncmktfm95vggzqx4sjlh",
        )
        .unwrap();
        // Rebuild the on-chain formula: sender_x + hash_psd4([domain, rvk, 1]).
        let randomizer = N::hash_psd4(&[N::encryption_domain(), rvk, Field::one()]).unwrap();
        let ciphertext = signer.to_x_coordinate() + randomizer;
        assert_eq!(record.decrypt_sender(&vk, &ciphertext).unwrap(), signer);

        // The upstream V1 vector proves the shared helper is JS-compatible.
        let upstream_rvk = Field::<N>::from_str(CREDITS_RECORD_VIEW_KEY).unwrap();
        let upstream_ct = Field::<N>::from_str(CREDITS_SENDER_CIPHERTEXT).unwrap();
        assert_eq!(
            crate::encryption::decrypt_sender_with_rvk(&upstream_rvk, &upstream_ct)
                .unwrap()
                .to_string(),
            CREDITS_SENDER_PLAINTEXT
        );
    }
}
