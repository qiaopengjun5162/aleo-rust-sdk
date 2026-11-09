//! Aleo `Signature` — parity with the JS SDK's wasm `Signature` class.
//!
//! Rust does not need a wrapper type here either: [`Signature<N>`] already
//! exists in snarkVM and covers **12 of the JS class's 16 methods**. This
//! module adds the four that have no one-step Rust equivalent, and documents
//! the rest.
//!
//! ## JS `Signature` → Rust mapping
//!
//! | # | JS `Signature` | Rust equivalent | Where |
//! |---|---|---|---|
//! | 1 | `Signature.sign(pk, bytes)` | `Signature::sign_bytes(&pk, &bytes, &mut rng)?` | snarkVM |
//! | 2 | `Signature.signValue(pk, value)` | [`sign_value`] | **this module** |
//! | 3 | `sig.verify(addr, bytes)` | `sig.verify_bytes(&addr, &bytes)` / [`crate::address::verify`] | snarkVM |
//! | 4 | `sig.verifyValue(addr, value)` | [`verify_value`] | **this module** |
//! | 5 | `sig.toAddress()` | `sig.to_address()` | snarkVM |
//! | 6 | `sig.challenge()` | `sig.challenge()` | snarkVM |
//! | 7 | `sig.response()` | `sig.response()` | snarkVM |
//! | 8 | `Signature.fromBytesLe(b)` | `Signature::from_bytes_le(&b)?` | snarkVM (`FromBytes`) |
//! | 9 | `sig.toBytesLe()` | `sig.to_bytes_le()?` | snarkVM (`ToBytes`) |
//! | 10 | `Signature.fromBitsLe(bits)` | `Signature::from_bits_le(&bits)?` | snarkVM (`FromBits`) |
//! | 11 | `sig.toBitsLe()` | `sig.to_bits_le()` | snarkVM (`ToBits`) |
//! | 12 | `sig.toFields()` | `sig.to_fields()?` | snarkVM (`ToFields`) |
//! | 13 | `Signature.fromString(s)` | `Signature::<N>::from_str(s)?` | snarkVM (`FromStr`) |
//! | 14 | `sig.toString()` / `to_string()` | `sig.to_string()` | snarkVM (`Display`) |
//! | 15 | `sig.toPlaintext()` | [`to_plaintext`] | **this module** |
//! | 16 | *(no JS equivalent)* | [`value_to_fields`] | **this module** |
//!
//! ## The one thing that actually matters here
//!
//! `sign_value` and `sign_bytes` **do not sign the same thing**, and a
//! signature produced by one will never verify through the other:
//!
//! - `Signature::sign_bytes(pk, bytes)` hashes the raw bytes into fields
//!   (`bytes.to_bits_le()`, packed in `Field::size_in_data_bits()` chunks).
//! - `sign_value(pk, "1u8")` parses the string as an Aleo [`Value`] and signs
//!   *its typed field encoding* — variant tag, type tag, value bits and the
//!   `true` terminator bit, all packed into fields.
//!
//! The two encodings coincide only by accident (and in practice never), so a
//! "simplification" that replaces `sign_value` with `sign_bytes(message.as_bytes())`
//! would silently break every signature the JS SDK produces over a record or a
//! struct. `sign_value_and_sign_bytes_are_not_interchangeable` pins that apart.
//!
//! There is a second trap one level down: `Value::to_fields()` is **not** the
//! same as calling `ToFields` on the literal it contains.
//! `U8::new(1).to_fields()` returns the bare `1field`, while
//! `value_to_fields("1u8")` returns `17246986276field` — the typed bits with a
//! `true` terminator bit, packed in `Field::size_in_data_bits()` chunks. Both
//! encode "one"; only the packed form is what a signature covers.
//! `value_fields_pack_typed_bits_not_direct_field_casts` keeps them apart.
//!
//! ## Differences from the JS class
//!
//! - `Signature.sign` and `Signature.signValue` in Rust take an explicit
//!   `rng`. Aleo's Schnorr-style scheme is randomized, so an RNG is required;
//!   the crate never reaches for a global one.
//! - `verifyValue` returns `Result<bool>` here. The JS method throws when the
//!   string is not a valid Aleo value and returns `false` when the signature
//!   does not match; conflating the two would let a malformed input look like
//!   a successful rejection.
//! - A **program ID parses as an address**. `Value::from_str("credits.aleo")`
//!   succeeds and yields the program's address, because snarkVM's literal
//!   parser has an implicit program-ID branch. Do not use `sign_value` /
//!   `verify_value` to validate that a string names a value type.
//! - `toPlaintext()` wraps the signature in `Literal::Signature(Box<..>)`, so
//!   the resulting [`Plaintext`] is a signature literal, not a field.
//!
//! ## Usage
//!
//! ```
//! use aleo_rust_sdk::signature;
//! use snarkvm::prelude::{PrivateKey, TestRng, TestnetV0};
//!
//! let rng = &mut TestRng::fixed(0);
//! let private_key = PrivateKey::<TestnetV0>::new(rng).unwrap();
//!
//! // JS: Signature.signValue(privateKey, "5u32")
//! let signature = signature::sign_value(&private_key, "5u32", rng).unwrap();
//!
//! // JS: signature.verifyValue(address, "5u32")
//! let address = signature.to_address();
//! assert!(signature::verify_value(&signature, &address, "5u32").unwrap());
//! assert!(!signature::verify_value(&signature, &address, "6u32").unwrap());
//! ```

use anyhow::{Context, Result};
use snarkvm::prelude::{
    Address, CryptoRng, Field, Literal, Network, Plaintext, PrivateKey, Rng, Signature, ToFields,
    Value,
};
use std::str::FromStr;

/// Parses an Aleo value string into the field vector that gets signed.
///
/// This is the step `signValue` and `verifyValue` share: the message of a
/// value signature is `Value::to_fields()`, not the string's bytes. Exposed
/// because it is the only way to see *what* was actually signed, which makes
/// cross-language debugging tractable.
///
/// Accepts every variant `Value` understands: literals (`"5u32"`,
/// `"100field"`, an address), plaintext structs and arrays, record plaintexts,
/// futures, and dynamic records.
///
/// # Arguments
/// * `message` - The string representation of the Aleo value.
///
/// # Errors
/// Returns an error if the string does not parse as a [`Value`], or if its
/// field encoding fails.
///
/// # Caveat
/// A program ID is a valid input: `"credits.aleo"` parses into the program's
/// address (snarkVM's literal parser allows implicit program IDs). That is the
/// same behaviour the JS SDK has, so it is preserved rather than rejected.
pub fn value_to_fields<N: Network>(message: &str) -> Result<Vec<Field<N>>> {
    let value = Value::<N>::from_str(message)
        .with_context(|| format!("Failed to parse '{message}' as an Aleo value"))?;
    value
        .to_fields()
        .with_context(|| format!("Failed to encode '{message}' as field elements"))
}

/// Signs an Aleo value — the JS `Signature.signValue(privateKey, message)`.
///
/// Unlike [`crate::AleoAccount::sign`], which signs raw bytes, this signs the
/// value's typed field encoding. See the module docs for why the two are not
/// interchangeable.
///
/// # Arguments
/// * `private_key` - The signer's private key.
/// * `message` - The string representation of the Aleo value to sign.
/// * `rng` - Randomness source. Aleo signatures are randomized: two signatures
///   over the same value differ and both verify.
///
/// # Errors
/// Returns an error if `message` does not parse as a [`Value`], or if the
/// signature cannot be produced.
pub fn sign_value<N: Network, R: Rng + CryptoRng>(
    private_key: &PrivateKey<N>,
    message: &str,
    rng: &mut R,
) -> Result<Signature<N>> {
    let fields = value_to_fields::<N>(message)?;
    Signature::sign(private_key, &fields, rng)
        .with_context(|| format!("Failed to sign the Aleo value '{message}'"))
}

/// Verifies a signature over an Aleo value — the JS
/// `signature.verifyValue(address, message)`.
///
/// # Arguments
/// * `signature` - The signature to check.
/// * `address` - The address the signature is expected to belong to.
/// * `message` - The string representation of the Aleo value that was signed.
///
/// # Returns
/// `Ok(true)` only when the signature is valid for `address` and `message`.
/// A well-formed value that simply does not match yields `Ok(false)`.
///
/// # Errors
/// Returns an error when `message` cannot be parsed as a [`Value`]. The JS
/// method throws in that case, so surfacing it as `Err` keeps malformed input
/// from being mistaken for a legitimate "signature does not match".
pub fn verify_value<N: Network>(
    signature: &Signature<N>,
    address: &Address<N>,
    message: &str,
) -> Result<bool> {
    let fields = value_to_fields::<N>(message)?;
    Ok(signature.verify(address, &fields))
}

/// Converts a signature to its plaintext literal — the JS
/// `signature.toPlaintext()`.
///
/// The result is a signature literal (`Literal::Signature`), so its string
/// form round-trips back through [`Signature::from_str`]. It is not a field:
/// `to_fields()` on a signature yields its `(challenge, response)` encoding,
/// which is a different thing from the literal wrapper.
///
/// # Arguments
/// * `signature` - The signature to convert.
///
/// # Returns
/// The `Plaintext` literal holding this signature. Cannot fail.
pub fn to_plaintext<N: Network>(signature: &Signature<N>) -> Plaintext<N> {
    Plaintext::from(Literal::Signature(Box::new(*signature)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::{FromStr, Plaintext, PrivateKey, TestRng, TestnetV0, U8};

    type N = TestnetV0;

    /// Literal vectors copied from the upstream JS SDK's wasm tests
    /// (`wasm/src/utilities/test/{plaintext,records}.rs`). Reusing them means a
    /// divergence shows up as a failed assertion here rather than as an
    /// incompatible signature in production.
    const NESTED_STRUCT: &str = "{ player: aleo13nnjqa7h2u4mpl95guz97nhzkhlde750zsjnw59tkgdwc85lyurs295lxc, health: 100u8, inventory: { coins: 5u32, snacks: { candies: 5u64, vegetals: 6u64 } }, secret: 2group, cipher: 2scalar, is_alive: true }";
    const INVALID_NESTED_STRUCT: &str = "{ player: aleo13nnjqa7h2u4mpl95guz97nhzkhlde750zsjnw59tkgdwc85lyurs295lxc, health: 100u8, inventory: { coins: 5u32, snacks: { candies: 5u64, vegetals: 6u64 } }, secret: 2group, cipher: 2scalar, is_alive: false }";
    const VALID_CREDITS_RECORD: &str = "{ owner: aleo1j7qxyunfldj2lp8hsvy7mw5k8zaqgjfyr72x2gh3x4ewgae8v5gscf5jh3.private, microcredits: 1500000000000000u64.private, _nonce: 3077450429259593211617823051143573281856129402760267155982965992208217472983group.public, _version: 0u8.public }";
    const INVALID_CREDITS_RECORD: &str = "{ owner: aleo1j7qxyunfldj2lp8hsvy7mw5k8zaqgjfyr72x2gh3x4ewgae8v5gscf5jh3.private, microcredits: 1400000000000000u64.private, _nonce: 3077450429259593211617823051143573281856129402760267155982965992208217472983group.public, _version: 0u8.public }";

    fn signer(seed: u64) -> (PrivateKey<N>, TestRng) {
        let mut rng = TestRng::fixed(seed);
        let private_key = PrivateKey::<N>::new(&mut rng).unwrap();
        (private_key, rng)
    }

    /// The message of `signValue("1u8")` is **not** `U8::new(1).to_fields()`.
    ///
    /// `Value::to_fields()` encodes the value as typed bits, appends a `true`
    /// terminator bit, then packs the result in `Field::size_in_data_bits()`
    /// chunks. A direct `ToFields` on the literal skips all of that and yields
    /// the bare `1field`. Both are legitimate encodings of "one"; only the
    /// packed one is what the signature covers.
    #[test]
    fn value_fields_pack_typed_bits_not_direct_field_casts() {
        let signed = value_to_fields::<N>("1u8").unwrap();
        let direct = U8::<N>::new(1).to_fields().unwrap();

        assert_eq!(direct, vec![Field::<N>::from_u8(1)]);
        assert_ne!(signed, direct);
        assert_eq!(signed.len(), 1);

        // It is exactly the plaintext encoding of the same string...
        assert_eq!(
            signed,
            Plaintext::<N>::from_str("1u8").unwrap().to_fields().unwrap()
        );

        // ...and reverting to the bare field would change the signed message.
        let (private_key, mut rng) = signer(8);
        let address = Address::try_from(&private_key).unwrap();
        let signature = sign_value(&private_key, "1u8", &mut rng).unwrap();
        assert!(!signature.verify(&address, &direct));
    }

    /// Bytes and values are different messages. If this ever passes, `sign_value`
    /// has been "simplified" into `sign_bytes` and JS-produced signatures over
    /// records and structs will stop verifying.
    #[test]
    fn sign_value_and_sign_bytes_are_not_interchangeable() {
        let (private_key, mut rng) = signer(0);
        let address = Address::try_from(&private_key).unwrap();

        let value_signature = sign_value(&private_key, "1u8", &mut rng).unwrap();
        let bytes_signature = private_key.sign_bytes(b"1u8", &mut rng).unwrap();

        // Each one verifies through its own path...
        assert!(verify_value(&value_signature, &address, "1u8").unwrap());
        assert!(bytes_signature.verify_bytes(&address, b"1u8"));

        // ...and fails through the other.
        assert!(!bytes_signature.verify(&address, &value_to_fields::<N>("1u8").unwrap()));
        assert!(!verify_value(&bytes_signature, &address, "1u8").unwrap());
        assert!(!value_signature.verify_bytes(&address, b"1u8"));
    }

    #[test]
    fn sign_value_round_trips() {
        let (private_key, mut rng) = signer(1);
        let address = Address::try_from(&private_key).unwrap();

        let signature = sign_value(&private_key, "42u32", &mut rng).unwrap();

        assert!(verify_value(&signature, &address, "42u32").unwrap());
        assert!(!verify_value(&signature, &address, "43u32").unwrap());
        assert_eq!(signature.to_address(), address);
    }

    /// Structs are signed field-by-field, so flipping any single leaf changes
    /// the message. This is the case a bytes-based shortcut cannot emulate.
    #[test]
    fn sign_value_covers_structs_and_records() {
        let (private_key, mut rng) = signer(2);
        let address = Address::try_from(&private_key).unwrap();

        let struct_signature = sign_value(&private_key, NESTED_STRUCT, &mut rng).unwrap();
        assert!(verify_value(&struct_signature, &address, NESTED_STRUCT).unwrap());
        assert!(!verify_value(&struct_signature, &address, INVALID_NESTED_STRUCT).unwrap());

        let record_signature = sign_value(&private_key, VALID_CREDITS_RECORD, &mut rng).unwrap();
        assert!(verify_value(&record_signature, &address, VALID_CREDITS_RECORD).unwrap());
        assert!(!verify_value(&record_signature, &address, INVALID_CREDITS_RECORD).unwrap());
    }

    /// A struct does not encode as one field per string byte; the field count
    /// follows the value's structure.
    #[test]
    fn value_fields_are_structural_not_byte_chunks() {
        let struct_fields = value_to_fields::<N>(NESTED_STRUCT).unwrap();
        let record_fields = value_to_fields::<N>(VALID_CREDITS_RECORD).unwrap();

        assert!(!struct_fields.is_empty());
        assert!(!record_fields.is_empty());
        assert_ne!(struct_fields, record_fields);
        // Two identical strings encode identically, so signatures agree.
        assert_eq!(value_to_fields::<N>(NESTED_STRUCT).unwrap(), struct_fields);
    }

    /// snarkVM's literal parser accepts a program ID and turns it into the
    /// program's address. Documented here because it makes `sign_value` a poor
    /// validator: `"credits.aleo"` is accepted, not rejected.
    ///
    /// The field vector holds more than one element: an address is ~253 bits of
    /// typed data plus the terminator, so it spills into a second field.
    #[test]
    fn a_program_id_parses_as_an_address() {
        let fields = value_to_fields::<N>("credits.aleo").unwrap();
        assert!(fields.len() > 1);

        let (private_key, mut rng) = signer(3);
        let address = Address::try_from(&private_key).unwrap();
        let signature = sign_value(&private_key, "credits.aleo", &mut rng).unwrap();
        assert!(verify_value(&signature, &address, "credits.aleo").unwrap());

        // It is the same message as the program's address spelled out.
        let program_address = crate::address::from_program_id::<N>("credits.aleo").unwrap();
        assert_eq!(
            value_to_fields::<N>(&program_address.to_string()).unwrap(),
            fields
        );
    }

    #[test]
    fn invalid_values_are_errors_not_false() {
        assert!(value_to_fields::<N>("this is not a valid Aleo value").is_err());

        let (private_key, mut rng) = signer(4);
        assert!(sign_value(&private_key, "not a value", &mut rng).is_err());

        let signature = sign_value(&private_key, "1u8", &mut rng).unwrap();
        let address = Address::try_from(&private_key).unwrap();
        assert!(verify_value(&signature, &address, "not a value").is_err());
    }

    /// Randomized signatures: same value, different bytes, both valid.
    #[test]
    fn signatures_are_randomized() {
        let (private_key, mut rng) = signer(5);
        let address = Address::try_from(&private_key).unwrap();

        let first = sign_value(&private_key, "7u16", &mut rng).unwrap();
        let second = sign_value(&private_key, "7u16", &mut rng).unwrap();

        assert_ne!(first.to_string(), second.to_string());
        assert!(verify_value(&first, &address, "7u16").unwrap());
        assert!(verify_value(&second, &address, "7u16").unwrap());
    }

    #[test]
    fn to_plaintext_round_trips() {
        let (private_key, mut rng) = signer(6);
        let signature = sign_value(&private_key, "9u8", &mut rng).unwrap();

        let plaintext = to_plaintext(&signature);

        assert!(matches!(
            plaintext,
            Plaintext::Literal(Literal::Signature(_), _)
        ));
        assert_eq!(
            Plaintext::<N>::from_str(&plaintext.to_string()).unwrap(),
            plaintext
        );
        assert_eq!(
            Signature::<N>::from_str(&plaintext.to_string()).unwrap(),
            signature
        );
    }

    /// A signature literal is not a field: `to_fields()` on the signature gives
    /// the `(challenge, response)` encoding, which is a different byte stream
    /// from the literal's typed bits.
    #[test]
    fn to_plaintext_is_not_the_signature_fields() {
        use snarkvm::prelude::ToBits;

        let (private_key, mut rng) = signer(7);
        let signature = sign_value(&private_key, "11u8", &mut rng).unwrap();

        let plaintext = to_plaintext(&signature);
        let plaintext_fields = plaintext.to_fields().unwrap();
        let signature_fields = signature.to_fields().unwrap();

        assert_ne!(plaintext_fields, signature_fields);
        assert_ne!(plaintext.to_bits_le(), signature.to_bits_le());
    }
}
