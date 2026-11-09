//! Aleo `Address` — parity with the JS SDK's wasm `Address` class.
//!
//! Rust does not need a wrapper type here: [`Address<N>`] already exists in
//! snarkVM and covers **13 of the JS class's 16 methods**. This module adds the
//! three that have no one-step Rust equivalent and documents the rest.
//!
//! ## JS `Address` → Rust mapping
//!
//! | # | JS `Address` | Rust equivalent | Where |
//! |---|---|---|---|
//! | 1 | `Address.fromPrivateKey(pk)` | `Address::<N>::try_from(&pk)?` | snarkVM (`TryFrom`) |
//! | 2 | `Address.fromViewKey(vk)` | `Address::try_from(&vk)?` / `vk.to_address()` | snarkVM (`TryFrom`) |
//! | 3 | `Address.fromComputeKey(ck)` | `Address::try_from(&ck)?` / `ck.to_address()` | snarkVM (`TryFrom`) |
//! | 4 | `Address.fromBytesLe(b)` | `Address::from_bytes_le(&b)?` | snarkVM (`FromBytes`) |
//! | 5 | `toBytesLe()` | `address.to_bytes_le()?` | snarkVM (`ToBytes`) |
//! | 6 | `Address.fromBitsLe(bits)` | `Address::from_bits_le(&bits)?` | snarkVM (`FromBits`) |
//! | 7 | `toBitsLe()` | `address.to_bits_le()` | snarkVM (`ToBits`) |
//! | 8 | `Address.fromFields(f)` | `Address::from_fields(&f)?` | snarkVM (`FromFields`) |
//! | 9 | `toFields()` | `address.to_fields()?` | snarkVM (`ToFields`) |
//! | 10 | `Address.fromGroup(g)` | `Address::new(g)` | snarkVM (constructor) |
//! | 11 | `toGroup()` | `address.to_group()` → `&Group<N>` | snarkVM |
//! | 12 | `Address.fromString(s)` | `Address::<N>::from_str(s)?` | snarkVM (`FromStr`) |
//! | 13 | `toString()` | `address.to_string()` | snarkVM (`Display`) |
//! | 14 | `toPlaintext()` | [`to_plaintext`] | **this module** |
//! | 15 | `verify(msg, sig)` | [`verify`] | **this module** |
//! | 16 | `Address.fromProgramId(id)` | [`from_program_id`] | **this module** |
//!
//! ## Differences from the JS class
//!
//! - `toGroup()` returns a **reference** (`&Group<N>`). `Group` is `Copy`, so
//!   dereference it (`*address.to_group()`) when an owned value is needed.
//!   `Address` also derefs to `Group`, so `*address` works too.
//! - `toBitsLe()` drops trailing zero bits, so the vector length is variable
//!   (at most `Field::size_in_bits()`, 253) rather than fixed. `fromBitsLe`
//!   tolerates extra trailing `false` bits, so round-trips are safe, but a
//!   bit-for-bit comparison with JS must pad first.
//! - `fromProgramId` accepts only `{name}.aleo`: the name is lowercase
//!   alphanumeric/underscore (not starting with a digit or underscore), the
//!   network-level domain must be the literal `aleo`, and nothing is trimmed.
//!   `"credits"`, `"Credits.aleo"`, `"credits.testnet"` and `"credits.aleo "`
//!   all fail.
//! - `toPlaintext()` produces **typed** plaintext bits (variant tag plus the
//!   literal's bits). Those are not `address.to_bits_le()`, and
//!   `Plaintext::to_fields()` is not `Address::to_fields()` — the latter holds
//!   exactly one field, the x-coordinate.
//! - `verify()` returns `false` for an over-long message; the upstream
//!   implementation also prints a line to stderr in that case. This wrapper
//!   keeps that behaviour rather than hiding it.
//! - Do **not** validate an address string with `Plaintext::from_str`: snarkVM's
//!   literal parser accepts a program ID there and silently converts it to an
//!   address. Use `Address::from_str` (63 characters, `aleo1` prefix).
//!
//! ## Usage
//!
//! ```
//! use aleo_rust_sdk::address;
//! use snarkvm::prelude::{Address, TestnetV0};
//! use std::str::FromStr;
//!
//! let addr = Address::<TestnetV0>::from_str(
//!     "aleo1r5fwayr4vhaz2mgyuqg7qer3apunn2zefe7m9cle94rar0dwcgyq6hg9ze",
//! )
//! .unwrap();
//!
//! // JS: address.toPlaintext()
//! let plaintext = address::to_plaintext(&addr);
//! assert_eq!(plaintext.to_string(), addr.to_string());
//!
//! // JS: Address.fromProgramId("credits.aleo")
//! let credits = address::from_program_id::<TestnetV0>("credits.aleo").unwrap();
//! assert_eq!(credits.to_string().len(), 63);
//! ```

use anyhow::{Context, Result};
use snarkvm::prelude::{Address, Literal, Network, Plaintext, ProgramID, Signature};
use std::str::FromStr;

/// Converts an address to its plaintext literal — the JS `address.toPlaintext()`.
///
/// Plaintext bits are **typed**: they carry the literal's variant tag, so they
/// differ from `address.to_bits_le()`. This is the form Leo programs expect
/// when an address is passed as a plaintext input, and it is the same recipe
/// the JS SDK uses in `Plaintext.fromString(address)`.
///
/// # Arguments
/// * `address` - The address to convert.
///
/// # Returns
/// The `Plaintext` literal holding this address. Cannot fail: `Address` is
/// already a validated value and the conversion is infallible.
pub fn to_plaintext<N: Network>(address: &Address<N>) -> Plaintext<N> {
    Plaintext::from(Literal::Address(*address))
}

/// Derives a program's address from its program ID — the JS
/// `Address.fromProgramId(programId)`.
///
/// The address is `HashToGroup_psd4([name, network])`, matching snarkVM's
/// [`ProgramID::to_address`].
///
/// # Arguments
/// * `program_id` - A program ID such as `"credits.aleo"`. Only `{name}.aleo`
///   is accepted; there is no `testnet`/`mainnet` suffix, and the string is
///   not trimmed.
///
/// # Errors
/// Returns an error if the program ID does not parse, or if the address
/// derivation fails. The error message keeps the caller's input, which
/// snarkVM's own parse error omits.
pub fn from_program_id<N: Network>(program_id: &str) -> Result<Address<N>> {
    let id = ProgramID::<N>::from_str(program_id)
        .with_context(|| format!("Failed to parse program ID '{program_id}'"))?;
    id.to_address()
        .with_context(|| format!("Failed to derive an address for program ID '{program_id}'"))
}

/// Verifies a signature against an arbitrary address — the JS
/// `address.verify(message, signature)`.
///
/// This is the free-standing counterpart of [`crate::AleoAccount::verify`],
/// which always checks the account's own address.
///
/// # Arguments
/// * `address` - The address the signature is expected to belong to.
/// * `message` - The signed message bytes (JS passes a `Uint8Array`).
/// * `signature` - The signature to check.
///
/// # Returns
/// `true` only when the signature is valid for `address` and `message`.
/// Every failure mode collapses to `false` — including a message longer than
/// `N::MAX_DATA_SIZE_IN_FIELDS`, for which snarkVM also writes a line to
/// stderr.
pub fn verify<N: Network>(address: &Address<N>, message: &[u8], signature: &Signature<N>) -> bool {
    signature.verify_bytes(address, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::{
        Address, FromStr, Literal, Plaintext, PrivateKey, ProgramID, TestRng, TestnetV0, ToBits,
    };

    type N = TestnetV0;

    /// Same recipient the JS SDK hardcodes in `constants.ts`.
    const RECIPIENT: &str = "aleo1r5fwayr4vhaz2mgyuqg7qer3apunn2zefe7m9cle94rar0dwcgyq6hg9ze";

    fn recipient() -> Address<N> {
        Address::from_str(RECIPIENT).unwrap()
    }

    fn signed_fixture(seed: u64) -> (Address<N>, Vec<u8>, Signature<N>) {
        let rng = &mut TestRng::fixed(seed);
        let private_key = PrivateKey::<N>::new(rng).unwrap();
        let address = Address::try_from(&private_key).unwrap();
        let message = b"aleo-rust-sdk/address/verify".to_vec();
        let signature = private_key.sign_bytes(&message, rng).unwrap();
        (address, message, signature)
    }

    #[test]
    fn to_plaintext_matches_plaintext_from_string() {
        let address = recipient();
        let plaintext = to_plaintext(&address);

        // Same value the JS `Plaintext.fromString(address.toString())` yields.
        assert_eq!(plaintext, Plaintext::<N>::from_str(RECIPIENT).unwrap());
        assert!(matches!(
            plaintext,
            Plaintext::Literal(Literal::Address(found), _) if found == address
        ));
    }

    #[test]
    fn to_plaintext_round_trips_through_display() {
        let address = recipient();
        let plaintext = to_plaintext(&address);

        assert_eq!(
            Address::<N>::from_str(&plaintext.to_string()).unwrap(),
            address
        );
        assert_eq!(
            Plaintext::<N>::from_str(&plaintext.to_string()).unwrap(),
            plaintext
        );
    }

    /// Typed plaintext bits are not raw address bits. A future "simplification"
    /// to `address.to_bits_le()` would change what Leo sees as an input, so the
    /// distinction is pinned here (same guard as `circle::generate_hook_data`).
    #[test]
    fn to_plaintext_uses_typed_bits_not_raw_address_bits() {
        let address = recipient();
        let plaintext_bits = to_plaintext(&address).to_bits_le();
        let address_bits = address.to_bits_le();

        assert_ne!(plaintext_bits, address_bits);
        assert!(plaintext_bits.len() > address_bits.len());
    }

    #[test]
    fn from_program_id_matches_program_id_to_address() {
        let derived = from_program_id::<N>("credits.aleo").unwrap();
        let expected = ProgramID::<N>::from_str("credits.aleo").unwrap().to_address().unwrap();

        assert_eq!(derived, expected);
        // Deterministic: hashing the same ID twice cannot drift.
        assert_eq!(derived, from_program_id::<N>("credits.aleo").unwrap());
        // Pinned literal, from snarkVM's own `Literal` parse tests; catches a
        // change in the hash-to-group recipe rather than a self-consistent bug.
        assert_eq!(
            derived.to_string(),
            "aleo1lqmly7ez2k48ajf5hs92ulphaqr05qm4n8qwzj8v0yprmasgpqgsez59gg"
        );
    }

    #[test]
    fn from_program_id_depends_on_program_name() {
        let credits = from_program_id::<N>("credits.aleo").unwrap();
        let hello = from_program_id::<N>("hello.aleo").unwrap();

        assert_ne!(credits, hello);
    }

    #[test]
    fn from_program_id_rejects_malformed_ids() {
        for program_id in [
            "",
            "credits",
            "Credits.aleo",
            "credits.testnet",
            "credits.aleo.extra",
            "_credits.aleo",
        ] {
            let error = from_program_id::<N>(program_id)
                .expect_err(&format!("'{program_id}' must not parse"));
            let message = error.to_string();
            assert!(
                message.contains("program ID"),
                "error for '{program_id}' lost its context: {message}"
            );
            assert!(
                message.contains(program_id),
                "error for '{program_id}' lost the caller's input: {message}"
            );
        }
    }

    #[test]
    fn verify_bytes_accepts_a_real_signature() {
        let (address, message, signature) = signed_fixture(1234);

        assert!(verify(&address, &message, &signature));
        // Same answer as calling snarkVM directly: guards against a swapped
        // address/message argument order in the wrapper.
        assert!(signature.verify_bytes(&address, &message));
    }

    #[test]
    fn verify_bytes_rejects_a_tampered_message() {
        let (address, mut message, signature) = signed_fixture(1234);
        message[0] ^= 0x01;

        assert!(!verify(&address, &message, &signature));
    }

    #[test]
    fn verify_bytes_rejects_the_wrong_address() {
        let (_, message, signature) = signed_fixture(1234);
        let (other_address, _, _) = signed_fixture(99);

        assert!(!verify(&other_address, &message, &signature));
    }

    #[test]
    fn verify_bytes_accepts_an_empty_message() {
        let rng = &mut TestRng::fixed(7);
        let private_key = PrivateKey::<N>::new(rng).unwrap();
        let address = Address::try_from(&private_key).unwrap();
        let signature = private_key.sign_bytes(&[], rng).unwrap();

        assert!(verify(&address, &[], &signature));
    }
}
