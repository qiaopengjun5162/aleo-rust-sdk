//! Aleo `Ciphertext` — parity with the JS SDK's wasm `Ciphertext` class.
//!
//! snarkVM's [`Ciphertext<N>`] already covers **9 of the 13 methods** on the
//! docs page: every serialization form (bytes, bits, fields, string) is a
//! `ToBytes` / `FromBytes` / `ToBits` / `FromBits` / `ToFields` / `FromFields` /
//! `FromStr` / `Display` impl, and the two raw decryption entry points are
//! inherent methods. The four that need work are the ones that *derive a key*
//! before decrypting, because those drag in the transition formula.
//!
//! ## JS `Ciphertext` → Rust mapping
//!
//! | # | JS `Ciphertext` | Rust equivalent | Where |
//! |---|---|---|---|
//! | 1 | `ct.decrypt(viewKey, nonce)` | `ct.decrypt(*view_key, nonce)?` | snarkVM |
//! | 2 | `ct.decryptWithTransitionInfo(vk, tpk, program, fn, index)` | [`decrypt_with_transition_info`] | **this module** |
//! | 3 | `ct.decryptWithTransitionViewKey(tvk, program, fn, index)` | [`decrypt_with_transition_view_key`] | **this module** |
//! | 4 | `ct.decryptSymmetric(key)` | `ct.decrypt_symmetric(key)?` | snarkVM |
//! | 5 | `Ciphertext.fromBytesLe(b)` | `Ciphertext::from_bytes_le(&b)?` | snarkVM (`FromBytes`) |
//! | 6 | `ct.toBytesLe()` | `ct.to_bytes_le()?` | snarkVM (`ToBytes`) |
//! | 7 | `Ciphertext.fromBitsLe(bits)` | `Ciphertext::from_bits_le(&bits)?` | snarkVM (`FromBits`) |
//! | 8 | `ct.toBitsLe()` | `ct.to_bits_le()` | snarkVM (`ToBits`) |
//! | 9 | `Ciphertext.fromFields(fields)` | `Ciphertext::from_fields(&fields)?` | snarkVM (`FromFields`) |
//! | 10 | `ct.toFields()` | `ct.to_fields()?` | snarkVM (`ToFields`) |
//! | 11 | `Ciphertext.fromString(s)` | `Ciphertext::<N>::from_str(s)?` | snarkVM (`FromStr`) |
//! | 12 | `ct.toBytes()` | `ct.to_bytes_le()?` | snarkVM (`ToBytes`) |
//! | 13 | `ct.toString()` | `ct.to_string()` | snarkVM (`Display`) |
//!
//! ## The three keys, and which method takes which
//!
//! All four decryption methods end in the same place — `decrypt_symmetric`
//! under some `Field` — and differ only in how that field is produced:
//!
//! - `decrypt(viewKey, nonce)` → `(nonce · view_key).x`. Used for record
//!   ciphertexts, where the nonce travels with the record.
//! - `decryptWithTransitionInfo(viewKey, tpk, program, function, index)` →
//!   first derive the transition view key `(tpk · view_key).x` ([`transition_view_key`]),
//!   then the per-slot key below.
//! - `decryptWithTransitionViewKey(tvk, program, function, index)` → the per-slot
//!   key directly: `hash_psd4([function_id, tvk, index])` ([`input_view_key`]),
//!   where `function_id = compute_function_id(network_id, program, function)`.
//! - `decryptSymmetric(key)` → the raw `Field`, no derivation at all.
//!
//! `index` is a **flat index over inputs *then* outputs**: the ciphertext of
//! output `j` is encrypted under `index = num_inputs + j`, not `j`. This is the
//! same convention [`crate::encryption::decrypt_transition_with_tvk`] relies
//! on, and getting it wrong fails decryption for every output while every input
//! still decrypts — which reads like a broken algorithm rather than a wrong
//! index.
//!
//! ## Encoding notes
//!
//! - **`toBytes()` and `toBytesLe()` are the same bytes.** The JS class has two
//!   names for one `to_bytes_le` call; Rust has only the latter.
//! - **A ciphertext is `plaintext fields ++ randomizers`**, so `from_fields`
//!   needs the *whole* array `to_fields` returned. Feeding it only the plaintext
//!   fields fails at `num_randomizers`.
//! - **Two different failure surfaces.** A bad `program` / `function` string
//!   fails while computing the function ID (parse error); a well-formed but
//!   wrong key fails inside `decrypt_symmetric` (verification error). The JS
//!   binding collapses the hash failure into
//!   `"The provided ciphertext decryption parameters are incorrect"`; here both
//!   arrive as `anyhow::Error` with distinct context, so check the chain.
//!
//! ## Usage
//!
//! ```
//! use aleo_rust_sdk::ciphertext;
//! use snarkvm::prelude::{Field, Plaintext, TestnetV0};
//! use std::str::FromStr;
//!
//! let plaintext = Plaintext::<TestnetV0>::from_str("2u32").unwrap();
//! let key = Field::from_u16(7);
//! let ciphertext = plaintext.encrypt_symmetric(key).unwrap();
//!
//! // JS: ct.decryptSymmetric(key)
//! assert_eq!(ciphertext.decrypt_symmetric(key).unwrap().to_string(), "2u32");
//!
//! // JS: ct.decryptWithTransitionViewKey(tvk, program, function, index) is the
//! // same call, with the key derived from (function_id, tvk, index) first.
//! let derived = ciphertext::input_view_key::<TestnetV0>(&Field::from_u16(1), &Field::from_u16(2), 0).unwrap();
//! let transition_ciphertext = plaintext.encrypt_symmetric(derived).unwrap();
//! assert_eq!(transition_ciphertext.decrypt_symmetric(derived).unwrap().to_string(), "2u32");
//! ```

use anyhow::{Context, Result};
use snarkvm::console::program::compute_function_id;
use snarkvm::prelude::{
    Ciphertext, Field, Group, Identifier, Network, Plaintext, ProgramID, U16, ViewKey,
};
use std::str::FromStr;

/// Derives the transition view key `(transition_public_key · view_key).x`.
///
/// This is the scalar multiplication the JS binding performs inline in
/// `decryptWithTransitionInfo`. Exposed separately because the result is what
/// [`decrypt_with_transition_view_key`] takes, and because it is the only piece
/// of the derivation that needs the signer's view key.
///
/// # Arguments
/// * `view_key` - The view key of the account that signed the transition.
/// * `transition_public_key` - The `tpk` of the transition.
pub fn transition_view_key<N: Network>(
    view_key: &ViewKey<N>,
    transition_public_key: &Group<N>,
) -> Field<N> {
    (*transition_public_key * **view_key).to_x_coordinate()
}

/// The per-input/output view key: `hash_psd4([function_id, tvk, index])`.
///
/// Shared by inputs and outputs because the index space is contiguous — see the
/// module docs on why outputs start at `num_inputs`.
///
/// # Arguments
/// * `function_id` - `compute_function_id(network_id, program_id, function_name)`.
/// * `transition_view_key` - The transition view key (see [`transition_view_key`]).
/// * `index` - The flat index of the encrypted input or output.
///
/// # Errors
/// Fails if the hash cannot be computed.
pub fn input_view_key<N: Network>(
    function_id: &Field<N>,
    transition_view_key: &Field<N>,
    index: u16,
) -> Result<Field<N>> {
    N::hash_psd4(&[*function_id, *transition_view_key, Field::from_u16(index)])
        .context("Failed to derive the ciphertext view key for this index")
}

/// Decrypts a ciphertext with a transition view key and a
/// `(program, function, index)` tuple — the JS `decryptWithTransitionViewKey`.
///
/// # Arguments
/// * `ciphertext` - The ciphertext to decrypt.
/// * `transition_view_key` - The transition view key, not the raw `tpk`.
/// * `program` - The program ID the transition belongs to (`"hello_hello.aleo"`).
/// * `function` - The function name (`"hello"`).
/// * `index` - The flat index of the encrypted input or output.
///
/// # Errors
/// Fails when `program` / `function` do not parse (the function ID cannot be
/// computed) or when the derived key does not decrypt the ciphertext.
pub fn decrypt_with_transition_view_key<N: Network>(
    ciphertext: &Ciphertext<N>,
    transition_view_key: &Field<N>,
    program: &str,
    function: &str,
    index: u16,
) -> Result<Plaintext<N>> {
    let function_id = function_id::<N>(program, function)?;
    let key = input_view_key::<N>(&function_id, transition_view_key, index)?;
    ciphertext
        .decrypt_symmetric(key)
        .with_context(|| format!("Ciphertext at index {index} does not decrypt with this key"))
}

/// Decrypts a ciphertext with the signer's view key, the transition public key
/// and a `(program, function, index)` tuple — the JS `decryptWithTransitionInfo`.
///
/// Equivalent to [`transition_view_key`] followed by
/// [`decrypt_with_transition_view_key`]; provided because that is the form the
/// JS API (and most callers, who hold a view key rather than a transition view
/// key) actually use.
///
/// # Arguments
/// * `ciphertext` - The ciphertext to decrypt.
/// * `view_key` - The view key of the account that signed the transition.
/// * `transition_public_key` - The `tpk` of the transition.
/// * `program` - The program ID the transition belongs to.
/// * `function` - The function name.
/// * `index` - The flat index of the encrypted input or output.
///
/// # Errors
/// Same failure modes as [`decrypt_with_transition_view_key`].
pub fn decrypt_with_transition_info<N: Network>(
    ciphertext: &Ciphertext<N>,
    view_key: &ViewKey<N>,
    transition_public_key: &Group<N>,
    program: &str,
    function: &str,
    index: u16,
) -> Result<Plaintext<N>> {
    let transition_view_key = transition_view_key(view_key, transition_public_key);
    decrypt_with_transition_view_key(ciphertext, &transition_view_key, program, function, index)
}

/// `compute_function_id(network_id, program_id, function_name)`, with the
/// strings parsed first.
fn function_id<N: Network>(program: &str, function: &str) -> Result<Field<N>> {
    let program_id = ProgramID::<N>::from_str(program)
        .with_context(|| format!("Failed to parse '{program}' as a program ID"))?;
    let function_name = Identifier::<N>::from_str(function)
        .with_context(|| format!("Failed to parse '{function}' as a function name"))?;
    compute_function_id(&U16::new(N::ID), &program_id, &function_name)
        .context("Failed to compute the function ID")
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::{
        Ciphertext, Field, FromBits, FromBytes, FromFields, Group, Plaintext, PrivateKey, TestRng,
        TestnetV0, ToBits, ToBytes, ToFields,
    };
    use snarkvm::utilities::rand::Uniform;

    type CurrentNetwork = TestnetV0;

    // Upstream wasm test vector (`wasm/src/programs/data/ciphertext.rs`): the
    // private input `2u32` of `hello_hello.aleo/hello`, its signer key, and the
    // `tpk` of the transition it belongs to.
    const CIPHERTEXT: &str =
        "ciphertext1qyq0m5mp0d2gzh2pv9p25z70gz2avhqdt3dp8y8thzwf3aq6g35zcqcuyptz3";
    const PRIVATE_KEY: &str = "APrivateKey1zkp8CZNn3yeCseEtxuVPbDCwSyhGW6yZKUYKfgXmcpoGPWH";
    const TRANSITION_PUBLIC_KEY: &str =
        "7532444547840484531569841377269810017844130178606467837628364672670182422388group";

    fn signer() -> (ViewKey<CurrentNetwork>, Group<CurrentNetwork>) {
        let private_key = PrivateKey::<CurrentNetwork>::from_str(PRIVATE_KEY).unwrap();
        let view_key = ViewKey::<CurrentNetwork>::try_from(&private_key).unwrap();
        let transition_public_key =
            Group::<CurrentNetwork>::from_str(TRANSITION_PUBLIC_KEY).unwrap();
        (view_key, transition_public_key)
    }

    #[test]
    fn golden_vector_decrypts_to_the_upstream_plaintext() {
        let (view_key, transition_public_key) = signer();
        let ciphertext = Ciphertext::<CurrentNetwork>::from_str(CIPHERTEXT).unwrap();

        // JS: ct.decryptWithTransitionInfo(viewKey, tpk, "hello_hello.aleo", "hello", 1)
        let via_info = decrypt_with_transition_info(
            &ciphertext,
            &view_key,
            &transition_public_key,
            "hello_hello.aleo",
            "hello",
            1,
        )
        .unwrap();
        assert_eq!(via_info.to_string(), "2u32");

        // JS: ct.decryptWithTransitionViewKey(tvk, "hello_hello.aleo", "hello", 1)
        let tvk = transition_view_key(&view_key, &transition_public_key);
        let via_tvk =
            decrypt_with_transition_view_key(&ciphertext, &tvk, "hello_hello.aleo", "hello", 1)
                .unwrap();
        assert_eq!(via_tvk.to_string(), "2u32");

        // The same ciphertext also decrypts through the record-style entry point:
        // `decryptSymmetric` under the per-index key is the end of every path.
        let function_id = function_id::<CurrentNetwork>("hello_hello.aleo", "hello").unwrap();
        let key = input_view_key::<CurrentNetwork>(&function_id, &tvk, 1).unwrap();
        assert_eq!(
            ciphertext.decrypt_symmetric(key).unwrap().to_string(),
            "2u32"
        );
    }

    #[test]
    fn wrong_index_function_program_or_key_does_not_decrypt() {
        let (view_key, transition_public_key) = signer();
        let ciphertext = Ciphertext::<CurrentNetwork>::from_str(CIPHERTEXT).unwrap();

        // Index 0 is the transition's *public* input, a different key entirely.
        assert!(
            decrypt_with_transition_info(
                &ciphertext,
                &view_key,
                &transition_public_key,
                "hello_hello.aleo",
                "hello",
                0
            )
            .is_err()
        );
        // A different function name shifts the function ID.
        assert!(
            decrypt_with_transition_info(
                &ciphertext,
                &view_key,
                &transition_public_key,
                "hello_hello.aleo",
                "goodbye",
                1
            )
            .is_err()
        );
        // As does a different program ID.
        assert!(
            decrypt_with_transition_info(
                &ciphertext,
                &view_key,
                &transition_public_key,
                "credits.aleo",
                "hello",
                1
            )
            .is_err()
        );
        // Malformed identifiers fail earlier, while computing the function ID.
        assert!(
            decrypt_with_transition_info(
                &ciphertext,
                &view_key,
                &transition_public_key,
                "not a program",
                "hello",
                1
            )
            .is_err()
        );
    }

    #[test]
    fn decrypt_with_a_view_key_and_nonce_matches_decrypt_symmetric() {
        let rng = &mut TestRng::fixed(0);
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let view_key = ViewKey::<CurrentNetwork>::try_from(&private_key).unwrap();
        let nonce: Group<CurrentNetwork> = Uniform::rand(rng);

        let plaintext = Plaintext::<CurrentNetwork>::from_str("12345u64").unwrap();
        let ciphertext =
            plaintext.encrypt_symmetric((nonce * *view_key).to_x_coordinate()).unwrap();

        // `decrypt(viewKey, nonce)` is `decrypt_symmetric((nonce · vk).x)`, nothing more.
        assert_eq!(
            ciphertext.decrypt(view_key, nonce).unwrap().to_string(),
            "12345u64"
        );
        assert_eq!(
            ciphertext
                .decrypt_symmetric((nonce * *view_key).to_x_coordinate())
                .unwrap()
                .to_string(),
            "12345u64"
        );
    }

    #[test]
    fn transition_view_key_is_the_shared_point_x_coordinate() {
        let rng = &mut TestRng::fixed(1);
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let view_key = ViewKey::<CurrentNetwork>::try_from(&private_key).unwrap();
        let transition_public_key: Group<CurrentNetwork> = Uniform::rand(rng);

        assert_eq!(
            transition_view_key(&view_key, &transition_public_key),
            (transition_public_key * *view_key).to_x_coordinate()
        );

        // A different tpk is a different shared point, hence a different key.
        let other: Group<CurrentNetwork> = Uniform::rand(rng);
        assert_ne!(
            transition_view_key(&view_key, &other),
            transition_view_key(&view_key, &transition_public_key)
        );
    }

    #[test]
    fn input_view_key_is_hash_psd4_of_the_function_tvk_and_index() {
        let function_id = Field::<CurrentNetwork>::from_u16(9);
        let tvk = Field::<CurrentNetwork>::from_u16(11);
        let index = Field::<CurrentNetwork>::from_u16(3);

        let expected = CurrentNetwork::hash_psd4(&[function_id, tvk, index]).unwrap();
        assert_eq!(
            input_view_key::<CurrentNetwork>(&function_id, &tvk, 3).unwrap(),
            expected
        );

        // The index is part of the hash: neighbours never share a key.
        assert_ne!(
            input_view_key::<CurrentNetwork>(&function_id, &tvk, 2).unwrap(),
            expected
        );
    }

    #[test]
    fn byte_bit_field_and_string_encodings_round_trip() {
        let ciphertext = Ciphertext::<CurrentNetwork>::from_str(CIPHERTEXT).unwrap();

        // 13: toString / 11: fromString.
        assert_eq!(
            Ciphertext::<CurrentNetwork>::from_str(&ciphertext.to_string()).unwrap(),
            ciphertext
        );

        // 12/6 — `toBytes` and `toBytesLe` are the same bytes.
        let bytes = ciphertext.to_bytes_le().unwrap();
        assert_eq!(
            Ciphertext::<CurrentNetwork>::from_bytes_le(&bytes).unwrap(),
            ciphertext
        );

        let bits = ciphertext.to_bits_le();
        assert_eq!(
            Ciphertext::<CurrentNetwork>::from_bits_le(&bits).unwrap(),
            ciphertext
        );

        // `to_fields` includes the randomizers, so `from_fields` needs all of them.
        let fields = ciphertext.to_fields().unwrap();
        assert_eq!(
            Ciphertext::<CurrentNetwork>::from_fields(&fields).unwrap(),
            ciphertext
        );
    }
}
