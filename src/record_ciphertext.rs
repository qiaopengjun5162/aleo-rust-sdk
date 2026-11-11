//! # RecordCiphertext — parity with the JS SDK's wasm `RecordCiphertext`.
//!
//! An encrypted Aleo record. The JS class is a wasm newtype over snarkVM's
//! `Record<CurrentNetwork, Ciphertext<CurrentNetwork>>`; this module keeps that
//! exact shape but stays generic over [`Network`], and delegates the two
//! non-trivial decryptions to helpers this crate already has.
//!
//! ## JS `RecordCiphertext` → Rust mapping
//!
//! | # | JS | Rust equivalent | Where |
//! |---|---|---|---|
//! | 1 | `fromString(record)` | [`RecordCiphertext::from_string`] | native `FromStr` |
//! | 2 | `toString()` | `ct.to_string()` | `Display` (blanket `ToString`) |
//! | 3 | `decrypt(view_key)` | [`RecordCiphertext::decrypt`] | native `Record::decrypt` (checked) |
//! | 4 | `recordViewKey(view_key)` | [`RecordCiphertext::record_view_key`] | **this module** (`nonce · vk` → x) |
//! | 5 | `isOwner(view_key)` | [`RecordCiphertext::is_owner`] | native `Record::is_owner` |
//! | 6 | `tag(graph_key, commitment)` | [`RecordCiphertext::tag`] | native `Record::tag` (static) |
//! | 7 | `fromBytesLe(bytes)` | [`RecordCiphertext::from_bytes_le`] | native `FromBytes` |
//! | 8 | `toBytesLe()` | [`RecordCiphertext::to_bytes_le`] | native `ToBytes` |
//! | 9 | `toBitsLe()` | [`RecordCiphertext::to_bits_le`] | native `ToBits` |
//! | 10 | `toFields()` | [`RecordCiphertext::to_fields`] | native `ToFields` |
//! | 11 | `decryptWithRecordViewKey(rvk)` | [`RecordCiphertext::decrypt_with_record_view_key`] | [`crate::encryption::decrypt_record_with_rvk`] |
//! | 12 | `nonce()` | [`RecordCiphertext::nonce`] | native getter |
//! | 13 | `clone()` | `ct.clone()` | derived `Clone` |
//!
//! ## Reuse, not reimplementation
//!
//! * The upstream wasm binding reimplements `decryptWithRecordViewKey` by
//!   counting randomizers and calling `hash_many_psd8` by hand. snarkVM 4.12
//!   exposes that as `Record::decrypt_symmetric_unchecked`, already wrapped by
//!   [`crate::encryption::decrypt_record_with_rvk`]. This module calls that one
//!   helper instead of copying the algorithm.
//! * `tag` is a **static** method even though it is listed on the instance
//!   page: it only needs `sk_tag` and the record commitment, never the
//!   ciphertext itself. The JS binding does the same
//!   (`RecordCiphertext.tag(graphKey, commitment)`).
//! * `recordViewKey` is `(nonce * view_key_scalar).to_x_coordinate()`. The JS
//!   binding calls `nonce.scalar_multiply(viewKey.toScalar())`; snarkVM 4.12 has
//!   no `Group::scalar_multiply`, so the Rust form is `group * scalar`. This is
//!   the same substitution used for `tvk` in [`crate::transition`].
//!
//! ## 🔴 `decrypt` checks ownership, `decryptWithRecordViewKey` does not
//!
//! [`RecordCiphertext::decrypt`] derives the record view key from the supplied
//! view key **and** verifies that the decrypted owner matches it. A wrong view
//! key is an error.
//! [`RecordCiphertext::decrypt_with_record_view_key`] is *unchecked*: a wrong
//! record view key produces garbage or a parse error, never an ownership
//! rejection. Share the record view key, not the account-wide view key, when a
//! third party should read exactly one record.
//!
//! ## Example
//!
//! ```
//! use aleo_rust_sdk::record_ciphertext::{RecordCiphertext, RECORD_CIPHERTEXT_FIXTURE};
//! use snarkvm::prelude::{FromStr, TestnetV0, ViewKey};
//!
//! let ct = RecordCiphertext::<TestnetV0>::from_string(RECORD_CIPHERTEXT_FIXTURE).unwrap();
//! let vk = ViewKey::<TestnetV0>::from_str(
//!     "AViewKey1ccEt8A2Ryva5rxnKcAbn7wgTaTsb79tzkKHFpeKsm9NX",
//! )
//! .unwrap();
//!
//! // JS: ct.isOwner(viewKey) / ct.recordViewKey(viewKey)
//! assert!(ct.is_owner(&vk));
//! let rvk = ct.record_view_key(&vk);
//! assert_eq!(
//!     rvk.to_string(),
//!     "4445718830394614891114647247073357094867447866913203502139893824059966201724field"
//! );
//!
//! // JS: ct.decrypt(viewKey) — returns a typed record plaintext in Rust.
//! let plaintext = ct.decrypt(&vk).unwrap();
//! assert!(plaintext.to_string().contains("microcredits"));
//!
//! // JS: ct.decryptWithRecordViewKey(rvk) — same record, no ownership check.
//! let again = ct.decrypt_with_record_view_key(&rvk).unwrap();
//! assert_eq!(plaintext.to_string(), again.to_string());
//! ```

use anyhow::Result;
use snarkvm::prelude::{
    Ciphertext, Field, FromBytes, GraphKey, Group, Network, Plaintext, Record, ToBits, ToBytes,
    ToFields, ViewKey,
};
use std::{fmt, ops::Deref, str::FromStr};

/// Upstream JS SDK wasm `RecordCiphertext` test vector
/// (`wasm/src/record/record_ciphertext.rs`). Exposed so examples and downstream
/// tests can parse the exact same literal the JS binding uses.
pub const RECORD_CIPHERTEXT_FIXTURE: &str = "record1qyqsqpe2szk2wwwq56akkwx586hkndl3r8vzdwve32lm7elvphh37rsyqyxx66trwfhkxun9v35hguerqqpqzqrtjzeu6vah9x2me2exkgege824sd8x2379scspmrmtvczs0d93qttl7y92ga0k0rsexu409hu3vlehe3yxjhmey3frh2z5pxm5cmxsv4un97q";

/// An encrypted Aleo record, wrapping snarkVM's native `Record<N, Ciphertext<N>>`.
#[derive(Clone, PartialEq, Eq)]
pub struct RecordCiphertext<N: Network>(Record<N, Ciphertext<N>>);

impl<N: Network> RecordCiphertext<N> {
    /// Parses a `record1…` ciphertext string — JS `fromString(record)`.
    ///
    /// # Errors
    /// Fails when the bech32m string is malformed or its checksum does not
    /// match.
    pub fn from_string(record: &str) -> Result<Self> {
        Self::from_str(record)
    }

    /// Decrypts with a view key, checking ownership — JS `decrypt(view_key)`.
    ///
    /// Returns the typed [`Record<N, Plaintext<N>>`] rather than a string; call
    /// `.to_string()` for the canonical Aleo record text. The next parity page
    /// (`RecordPlaintext`) wraps this same native type.
    ///
    /// # Errors
    /// Fails when the record does not belong to this view key.
    pub fn decrypt(&self, view_key: &ViewKey<N>) -> Result<Record<N, Plaintext<N>>> {
        self.0.decrypt(view_key)
    }

    /// Derives this record's view key — JS `recordViewKey(view_key)`.
    ///
    /// `(nonce * view_key).to_x_coordinate()`. The result decrypts **only this
    /// record**, so it can be shared without exposing the account view key.
    pub fn record_view_key(&self, view_key: &ViewKey<N>) -> Field<N> {
        (*self.0.nonce() * **view_key).to_x_coordinate()
    }

    /// Tests record ownership — JS `isOwner(view_key)`.
    ///
    /// Cheaper than [`Self::decrypt`]: it decrypts only the owner field, not
    /// every data entry.
    pub fn is_owner(&self, view_key: &ViewKey<N>) -> bool {
        self.0.is_owner(view_key)
    }

    /// Computes the record tag — JS `tag(graph_key, commitment)`.
    ///
    /// Static because the formula is `hash_psd2(sk_tag, commitment)`; it never
    /// reads the ciphertext. The commitment comes from the decrypted record's
    /// `to_commitment(program_id, record_name, record_view_key)`.
    ///
    /// # Errors
    /// Fails only if the network hash primitive fails.
    pub fn tag(graph_key: &GraphKey<N>, commitment: Field<N>) -> Result<Field<N>> {
        Record::<N, Ciphertext<N>>::tag(graph_key.sk_tag(), commitment)
    }

    /// Reconstructs a ciphertext from little-endian bytes — JS `fromBytesLe(bytes)`.
    ///
    /// # Errors
    /// Fails when the bytes are not a valid record ciphertext.
    pub fn from_bytes_le(bytes: &[u8]) -> Result<Self> {
        Ok(Self(Record::<N, Ciphertext<N>>::read_le(bytes)?))
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
    /// Like the native `ToFields` implementation, this appends a terminus bit
    /// before packing bits into fields.
    ///
    /// # Errors
    /// Fails when the record exceeds the network's maximum data size.
    pub fn to_fields(&self) -> Result<Vec<Field<N>>> {
        self.0.to_fields()
    }

    /// Decrypts with a record view key — JS `decryptWithRecordViewKey(rvk)`.
    ///
    /// 🔴 **Unchecked**: no owner verification. Delegates to
    /// [`crate::encryption::decrypt_record_with_rvk`], which wraps snarkVM's
    /// `decrypt_symmetric_unchecked`.
    ///
    /// # Errors
    /// Fails when the key cannot decrypt the ciphertext into a valid record.
    pub fn decrypt_with_record_view_key(
        &self,
        record_view_key: &Field<N>,
    ) -> Result<Record<N, Plaintext<N>>> {
        crate::encryption::decrypt_record_with_rvk(record_view_key, &self.0)
    }

    /// Returns the record nonce — JS `nonce()`.
    pub fn nonce(&self) -> Group<N> {
        *self.0.nonce()
    }
}

impl<N: Network> Deref for RecordCiphertext<N> {
    type Target = Record<N, Ciphertext<N>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<N: Network> fmt::Debug for RecordCiphertext<N> {
    /// The native `Record` has no `Debug`, so supply one that prints the
    /// canonical (public) ciphertext string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RecordCiphertext").field(&self.0.to_string()).finish()
    }
}

impl<N: Network> fmt::Display for RecordCiphertext<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<N: Network> FromStr for RecordCiphertext<N> {
    type Err = anyhow::Error;

    fn from_str(ciphertext: &str) -> Result<Self> {
        Record::<N, Ciphertext<N>>::from_str(ciphertext).map(Self)
    }
}

impl<N: Network> From<Record<N, Ciphertext<N>>> for RecordCiphertext<N> {
    fn from(record: Record<N, Ciphertext<N>>) -> Self {
        Self(record)
    }
}

impl<N: Network> From<RecordCiphertext<N>> for Record<N, Ciphertext<N>> {
    fn from(record: RecordCiphertext<N>) -> Self {
        record.0
    }
}

impl<N: Network> AsRef<Record<N, Ciphertext<N>>> for RecordCiphertext<N> {
    fn as_ref(&self) -> &Record<N, Ciphertext<N>> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::{Identifier, ProgramID, SizeInDataBits, TestnetV0};

    type N = TestnetV0;

    /// Upstream wasm test vectors (`wasm/src/record/record_ciphertext.rs`).
    const OWNER_VIEW_KEY: &str = "AViewKey1ccEt8A2Ryva5rxnKcAbn7wgTaTsb79tzkKHFpeKsm9NX";
    const NON_OWNER_VIEW_KEY: &str = "AViewKey1e2WyreaH5H4RBcioLL2GnxvHk5Ud46EtwycnhTdXLmXp";
    const OWNER_PLAINTEXT: &str = r"{
        owner: aleo1j7qxyunfldj2lp8hsvy7mw5k8zaqgjfyr72x2gh3x4ewgae8v5gscf5jh3.private,
        microcredits: 1500000000000000u64.private,
        _nonce: 3077450429259593211617823051143573281856129402760267155982965992208217472983group.public
      }";
    const RECORD_TAG: &str =
        "1796466189545157638691489609907096471289658804813960182690905095269699169603field";
    const RECORD_VIEW_KEY: &str =
        "4445718830394614891114647247073357094867447866913203502139893824059966201724field";

    fn ciphertext() -> RecordCiphertext<N> {
        RecordCiphertext::<N>::from_string(RECORD_CIPHERTEXT_FIXTURE).expect("fixture parses")
    }

    fn view_key(s: &str) -> ViewKey<N> {
        ViewKey::<N>::from_str(s).expect("literal view key parses")
    }

    #[test]
    fn string_roundtrip_and_invalid_input() {
        let record = ciphertext();
        assert_eq!(record.to_string(), RECORD_CIPHERTEXT_FIXTURE);
        assert_eq!(
            RecordCiphertext::<N>::from_str(RECORD_CIPHERTEXT_FIXTURE).unwrap(),
            record
        );
        assert!(RecordCiphertext::<N>::from_string("garbage").is_err());
    }

    #[test]
    fn clone_keeps_the_same_ciphertext() {
        let record = ciphertext();
        let cloned = record.clone();
        assert_eq!(record, cloned);
        assert_eq!(record.to_string(), cloned.to_string());
    }

    #[test]
    fn decrypt_matches_upstream_plaintext() {
        let record = ciphertext();
        let plaintext = record.decrypt(&view_key(OWNER_VIEW_KEY)).unwrap();
        let expected = Record::<N, Plaintext<N>>::from_str(OWNER_PLAINTEXT).unwrap();
        assert_eq!(plaintext.to_string(), expected.to_string());
        assert!(plaintext.to_string().contains("1500000000000000u64.private"));
    }

    #[test]
    fn non_owner_cannot_decrypt() {
        let record = ciphertext();
        let wrong = view_key(NON_OWNER_VIEW_KEY);
        assert!(record.decrypt(&wrong).is_err());
        assert!(!record.is_owner(&wrong));
    }

    #[test]
    fn is_owner_for_the_real_owner() {
        assert!(ciphertext().is_owner(&view_key(OWNER_VIEW_KEY)));
    }

    #[test]
    fn record_view_key_matches_upstream_vector() {
        let rvk = ciphertext().record_view_key(&view_key(OWNER_VIEW_KEY));
        assert_eq!(rvk.to_string(), RECORD_VIEW_KEY);
        assert_eq!(Field::<N>::from_str(RECORD_VIEW_KEY).unwrap(), rvk);
    }

    #[test]
    fn decrypt_with_record_view_key_roundtrips() {
        let record = ciphertext();
        let expected = record.decrypt(&view_key(OWNER_VIEW_KEY)).unwrap();
        let rvk = record.record_view_key(&view_key(OWNER_VIEW_KEY));
        assert_eq!(
            record.decrypt_with_record_view_key(&rvk).unwrap().to_string(),
            expected.to_string()
        );
    }

    #[test]
    fn decrypt_with_wrong_record_view_key_fails() {
        let record = ciphertext();
        let wrong = record.record_view_key(&view_key(NON_OWNER_VIEW_KEY));
        assert!(record.decrypt_with_record_view_key(&wrong).is_err());
    }

    #[test]
    fn tag_matches_upstream_vector() {
        let record = ciphertext();
        let vk = view_key(OWNER_VIEW_KEY);
        let rvk = record.record_view_key(&vk);
        let plaintext = record.decrypt(&vk).unwrap();
        let program_id = ProgramID::<N>::from_str("credits.aleo").unwrap();
        let record_name = Identifier::<N>::from_str("credits").unwrap();
        let commitment = plaintext.to_commitment(&program_id, &record_name, &rvk).unwrap();
        let graph_key = GraphKey::<N>::try_from(&vk).unwrap();
        let tag = RecordCiphertext::<N>::tag(&graph_key, commitment).unwrap();
        assert_eq!(tag.to_string(), RECORD_TAG);
    }

    #[test]
    fn bytes_bits_fields_and_nonce() {
        let record = ciphertext();

        let bytes = record.to_bytes_le().unwrap();
        assert!(!bytes.is_empty());
        let restored = RecordCiphertext::<N>::from_bytes_le(&bytes).unwrap();
        assert_eq!(restored.to_string(), record.to_string());
        assert!(RecordCiphertext::<N>::from_bytes_le(&[0u8; 4]).is_err());

        let bits = record.to_bits_le();
        assert!(!bits.is_empty());
        let fields = record.to_fields().unwrap();
        assert!(!fields.is_empty());
        // `to_fields` packs `to_bits_le` plus a terminus bit into data-bit-sized chunks.
        let expected_len = (bits.len() + 1).div_ceil(Field::<N>::size_in_data_bits());
        assert_eq!(fields.len(), expected_len);
        assert_eq!(record.nonce(), *record.as_ref().nonce());
    }
}
