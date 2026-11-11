//! Aleo `ViewKey` — parity with the JS SDK's wasm `ViewKey` class.
//!
//! This is the thinnest of the account-page parities: snarkVM's
//! [`ViewKey<N>`] **already implements every method** on the JS page natively.
//! [`ViewKey<N>`] is `Copy`, `Deref`s to its inner `Scalar<N>`, and snarkVM
//! even derives `Zeroize` on it — so the wasm `Drop` zeroization the JS class
//! relies on is already handled by the native type (no wrapper needed here,
//! unlike the wasm binding's `ViewKey(ViewKeyNative)` shell).
//!
//! ## JS `ViewKey` → Rust mapping
//!
//! | # | JS `ViewKey` | Rust equivalent | Where |
//! |---|---|---|---|
//! | 1 | `ViewKey.fromPrivateKey(pk)` | [`from_private_key`] / `ViewKey::try_from(&pk)` | snarkVM (`TryFrom`) |
//! | 2 | `ViewKey.fromString(s)` | [`from_string`] / `ViewKey::from_str(s)` | snarkVM (`FromStr`) |
//! | 3 | `viewKey.toString()` | `vk.to_string()` | snarkVM (`Display`) |
//! | 4 | `viewKey.toString()` (JS `toString` alias) | `vk.to_string()` | snarkVM (`Display`) |
//! | 5 | `viewKey.toBytesLe()` | [`to_bytes_le`] / `vk.to_bytes_le()` | snarkVM (`ToBytes`) |
//! | 6 | `ViewKey.fromBytesLe(b)` | [`from_bytes_le`] / `ViewKey::read_le(&b[..])` | snarkVM (`FromBytes`) |
//! | 7 | `viewKey.toAddress()` | [`to_address`] / `vk.to_address()` | snarkVM (method) |
//! | 8 | `viewKey.toScalar()` | [`to_scalar`] | **this module** (deref trap) |
//! | 9 | `viewKey.toField()` | [`to_field`] / `vk.to_field()` | snarkVM (`ToField`, via `Deref`) |
//! | 10 | `viewKey.decrypt(ciphertext)` | [`decrypt`] | **this module** (record-ciphertext dance) |
//!
//! ## 🔴 `toScalar()` is not `toField()`
//!
//! The view key's inner value is a **scalar-field** element, not a base-field
//! element. JS exposes both `toScalar()` and `toField()`, and they return
//! **different fields**. Rust mirrors this exactly:
//!
//! - [`to_scalar`] returns `Scalar::from(*vk)`. The `*vk` derefs the
//!   [`ViewKey<N>`] to its inner `Scalar<N>` (which is `Copy`), then the
//!   reflexive `From<Scalar> for Scalar` keeps it as-is. This is the raw view
//!   key scalar.
//! - [`to_field`] returns `vk.to_field()`, which goes through `Scalar`'s
//!   `ToField` impl and **re-encodes the scalar into the base field**. The two
//!   results are not equal — calling `toField()` when you meant `toScalar()`
//!   (or vice versa) is a silent, hard-to-spot bug.
//!
//! ## `decrypt` bundles three steps
//!
//! The JS `decrypt(ciphertext)` hides the fact that it must first parse the
//! ciphertext string into a `Record<N, Ciphertext<N>>`, then call `decrypt` with
//! the view key, then render the resulting record plaintext back to a string.
//! [`decrypt`] does all three so Rust callers get the same one-call ergonomics.
//! A ciphertext produced by a different view key decrypts to an error (the
//! underlying AEAD check fails), which the upstream tests pin with a
//! `NON_OWNER_VIEW_KEY` vector.
//!
//! ## Usage
//!
//! ```
//! use aleo_rust_sdk::view_key;
//! use snarkvm::prelude::{Address, PrivateKey, TestnetV0};
//! use std::str::FromStr;
//!
//! let pk = PrivateKey::<TestnetV0>::from_str(
//!     "APrivateKey1zkp4RyQ8Utj7aRcJgPQGEok8RMzWwUZzBhhgX6rhmBT8dcP",
//! )
//! .unwrap();
//!
//! // JS: ViewKey.fromPrivateKey(pk)
//! let vk = view_key::from_private_key(&pk).unwrap();
//! assert_eq!(
//!     vk.to_string(),
//!     "AViewKey1i3fn5SECcVBtQMCVtTPSvdApoMYmg3ToJfNDfgHJAuoD"
//! );
//!
//! // JS: viewKey.toAddress() — same address the private key controls.
//! assert_eq!(view_key::to_address(&vk), Address::try_from(&pk).unwrap());
//!
//! // JS: viewKey.decrypt(ciphertext) — the ciphertext below is owned by the
//! // key parsed on the next line, not by the derived `vk`.
//! let owner_vk = view_key::from_string::<TestnetV0>(
//!     "AViewKey1ccEt8A2Ryva5rxnKcAbn7wgTaTsb79tzkKHFpeKsm9NX",
//! )
//! .unwrap();
//! let plaintext = view_key::decrypt(
//!     &owner_vk,
//!     "record1qyqsqpe2szk2wwwq56akkwx586hkndl3r8vzdwve32lm7elvphh37rsyqyxx66trwfhkxun9v35hguerqqpqzqrtjzeu6vah9x2me2exkgege824sd8x2379scspmrmtvczs0d93qttl7y92ga0k0rsexu409hu3vlehe3yxjhmey3frh2z5pxm5cmxsv4un97q",
//! )
//! .unwrap();
//! assert!(plaintext.contains("microcredits"));
//! ```

use anyhow::Result;
use snarkvm::prelude::{
    Address, Ciphertext, Field, FromBytes, FromStr, Network, PrivateKey, Record, Scalar, ToBytes,
    ToField, ViewKey,
};

/// Derives the view key from a private key — JS `ViewKey.fromPrivateKey(pk)`.
///
/// The view key is the scalar component of the private key's compute key; it
/// can decrypt that account's records but cannot sign. The conversion is
/// infallible for a valid private key (the only failure is a malformed key).
///
/// # Arguments
/// * `private_key` - The private key to derive from.
pub fn from_private_key<N: Network>(private_key: &PrivateKey<N>) -> Result<ViewKey<N>> {
    ViewKey::try_from(private_key)
}

/// Parses a view key from its bech32m string — JS `ViewKey.fromString(s)`.
///
/// # Arguments
/// * `s` - A string like `AViewKey1…`.
pub fn from_string<N: Network>(s: &str) -> Result<ViewKey<N>> {
    ViewKey::from_str(s)
}

/// Returns the address this view key controls — JS `viewKey.toAddress()`.
///
/// The view key deterministically derives the same address as its private key,
/// so it can be used to check record ownership without holding the signing key.
///
/// # Arguments
/// * `view_key` - The view key.
pub fn to_address<N: Network>(view_key: &ViewKey<N>) -> Address<N> {
    view_key.to_address()
}

/// Returns the inner scalar of the view key — JS `viewKey.toScalar()`.
///
/// 🔴 This is the **scalar-field** element, not the base-field encoding. Use
/// [`to_field`] only when you specifically need the base-field re-encoding.
///
/// # Arguments
/// * `view_key` - The view key.
pub fn to_scalar<N: Network>(view_key: &ViewKey<N>) -> Scalar<N> {
    // `ViewKey<N>` derefs to its inner `Scalar<N>` (which is `Copy`). The double
    // deref is `&ViewKey -> ViewKey (Copy) -> Scalar (Deref)`. Written explicitly
    // so the scalar — rather than an accidental base-field cast — is what escapes.
    **view_key
}

/// Casts the view key to a base-field element — JS `viewKey.toField()`.
///
/// 🔴 `toField()` re-encodes the scalar into the base field. It is **not**
/// equal to [`to_scalar`]; pick the one the protocol step expects.
///
/// # Arguments
/// * `view_key` - The view key.
pub fn to_field<N: Network>(view_key: &ViewKey<N>) -> Result<Field<N>> {
    view_key.to_field()
}

/// Serializes the view key as little-endian bytes — JS `viewKey.toBytesLe()`.
///
/// # Arguments
/// * `view_key` - The view key.
pub fn to_bytes_le<N: Network>(view_key: &ViewKey<N>) -> Result<Vec<u8>> {
    view_key.to_bytes_le()
}

/// Reconstructs a view key from little-endian bytes — JS `ViewKey.fromBytesLe(b)`.
///
/// # Arguments
/// * `bytes` - The little-endian byte slice produced by [`to_bytes_le`].
pub fn from_bytes_le<N: Network>(bytes: &[u8]) -> Result<ViewKey<N>> {
    Ok(ViewKey::read_le(bytes)?)
}

/// Decrypts a record ciphertext with this view key — JS `viewKey.decrypt(ciphertext)`.
///
/// Bundles the three native steps: parse the `record1…` string into a
/// `Record<N, Ciphertext<N>>`, decrypt it with the view key, and render the
/// recovered record plaintext back to its canonical string form.
///
/// A ciphertext encrypted under a different view key fails to decrypt (the
/// AEAD tag check rejects it), so this returns `Err` rather than a junk
/// plaintext.
///
/// # Arguments
/// * `view_key` - The view key that owns (or does not own) the record.
/// * `ciphertext` - A `record1…` ciphertext string.
///
/// # Errors
/// Returns an error if the ciphertext string does not parse or if this view key
/// is not the one the record was encrypted under.
pub fn decrypt<N: Network>(view_key: &ViewKey<N>, ciphertext: &str) -> Result<String> {
    let ciphertext = Record::<N, Ciphertext<N>>::from_str(ciphertext)?;
    let plaintext = ciphertext.decrypt(view_key)?;
    Ok(plaintext.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use snarkvm::prelude::{Address, FromStr, PrivateKey, TestnetV0, ToField};

    type CurrentNetwork = TestnetV0;

    /// Upstream wasm test vectors (`wasm/src/account/view_key.rs`).
    const PRIVATE_KEY: &str = "APrivateKey1zkp4RyQ8Utj7aRcJgPQGEok8RMzWwUZzBhhgX6rhmBT8dcP";
    const DERIVED_VIEW_KEY: &str = "AViewKey1i3fn5SECcVBtQMCVtTPSvdApoMYmg3ToJfNDfgHJAuoD";
    const OWNER_VIEW_KEY: &str = "AViewKey1ccEt8A2Ryva5rxnKcAbn7wgTaTsb79tzkKHFpeKsm9NX";
    const NON_OWNER_VIEW_KEY: &str = "AViewKey1e2WyreaH5H4RBcioLL2GnxvHk5Ud46EtwycnhTdXLmXp";
    const OWNER_CIPHERTEXT: &str = "record1qyqsqpe2szk2wwwq56akkwx586hkndl3r8vzdwve32lm7elvphh37rsyqyxx66trwfhkxun9v35hguerqqpqzqrtjzeu6vah9x2me2exkgege824sd8x2379scspmrmtvczs0d93qttl7y92ga0k0rsexu409hu3vlehe3yxjhmey3frh2z5pxm5cmxsv4un97q";
    const RECORD_PLAINTEXT: &str = "{\n  owner: aleo1j7qxyunfldj2lp8hsvy7mw5k8zaqgjfyr72x2gh3x4ewgae8v5gscf5jh3.private,\n  microcredits: 1500000000000000u64.private,\n  _nonce: 3077450429259593211617823051143573281856129402760267155982965992208217472983group.public,\n  _version: 0u8.public\n}";

    fn pk(s: &str) -> PrivateKey<CurrentNetwork> {
        PrivateKey::from_str(s).expect("literal private key parses")
    }

    fn vk(s: &str) -> ViewKey<CurrentNetwork> {
        ViewKey::from_str(s).expect("literal view key parses")
    }

    // ── from_private_key / to_address ──────────────────────────────────

    #[test]
    fn from_private_key_matches_upstream_vector() {
        let view_key = from_private_key(&pk(PRIVATE_KEY)).unwrap();
        assert_eq!(view_key.to_string(), DERIVED_VIEW_KEY);

        // The derived view key must address the same account as the private key.
        let address = Address::try_from(&pk(PRIVATE_KEY)).unwrap();
        assert_eq!(to_address(&view_key), address);
    }

    // ── from_string / to_string ────────────────────────────────────────

    #[test]
    fn from_string_round_trips_through_display() {
        let view_key = from_string::<CurrentNetwork>(OWNER_VIEW_KEY).unwrap();
        assert_eq!(view_key.to_string(), OWNER_VIEW_KEY);
        // `fromString` and `toString` are the native `FromStr`/`Display`.
        assert_eq!(ViewKey::from_str(OWNER_VIEW_KEY).unwrap(), view_key);
    }

    #[test]
    fn from_string_rejects_malformed_view_key() {
        assert!(from_string::<CurrentNetwork>("not-a-view-key").is_err());
        // A truncated bech32m string fails the checksum/length check.
        assert!(from_string::<CurrentNetwork>(&OWNER_VIEW_KEY[..20]).is_err());
    }

    // ── to_scalar / to_field (the two different fields) ────────────────

    #[test]
    fn to_scalar_and_to_field_are_consistent() {
        let view_key = vk(OWNER_VIEW_KEY);
        let scalar = to_scalar(&view_key);
        // `to_field()` must be the base-field re-encoding of `to_scalar()` —
        // this pins that `to_field` does not silently hand back the scalar. The
        // two live in different fields (scalar vs base), so they are not the
        // same value; callers must pick the one the protocol step expects.
        assert_eq!(to_field(&view_key).unwrap(), scalar.to_field().unwrap());
    }

    // ── byte (de)serialization ─────────────────────────────────────────

    #[test]
    fn byte_serialization_round_trip() {
        let view_key = vk(OWNER_VIEW_KEY);
        let bytes = to_bytes_le(&view_key).unwrap();
        let recovered = from_bytes_le(&bytes).unwrap();
        assert_eq!(recovered, view_key);
    }

    #[test]
    fn from_bytes_le_rejects_truncated_input() {
        // Fewer than the 32 scalar bytes the native reader expects → error.
        assert!(from_bytes_le::<CurrentNetwork>(&[0u8; 8]).is_err());
    }

    // ── decrypt (the genuine gap) ──────────────────────────────────────

    #[test]
    fn decrypt_success_recovers_upstream_plaintext() {
        let plaintext = decrypt(&vk(OWNER_VIEW_KEY), OWNER_CIPHERTEXT).unwrap();
        assert_eq!(plaintext, RECORD_PLAINTEXT);
    }

    #[test]
    fn decrypt_fails_with_non_owner_view_key() {
        let ciphertext =
            Record::<CurrentNetwork, Ciphertext<CurrentNetwork>>::from_str(OWNER_CIPHERTEXT)
                .unwrap();
        // The AEAD tag check rejects a view key that does not own the record.
        assert!(ciphertext.decrypt(&vk(NON_OWNER_VIEW_KEY)).is_err());

        // The bundled helper surfaces the same failure as an `Err`.
        assert!(decrypt(&vk(NON_OWNER_VIEW_KEY), OWNER_CIPHERTEXT).is_err());
    }

    #[test]
    fn decrypt_rejects_unparsable_ciphertext() {
        assert!(decrypt(&vk(OWNER_VIEW_KEY), "not-a-ciphertext").is_err());
    }
}
