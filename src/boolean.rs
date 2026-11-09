//! Aleo `Boolean` — parity with the JS SDK's wasm `Boolean` class.
//!
//! As with [`crate::address`] and [`crate::signature`], no wrapper type is
//! needed: snarkVM's [`Boolean<N>`] already covers **14 of the 16 methods** the
//! docs page lists, because the class is a thin shell over the native type.
//! This module adds the two that are not a single call, and — where the real
//! value is — pins the encodings down with tests, because a plausible guess
//! about them is wrong in several places.
//!
//! ## JS `Boolean` → Rust mapping
//!
//! | # | JS `Boolean` | Rust equivalent | Where |
//! |---|---|---|---|
//! | 1 | `new Boolean(true)` | `Boolean::new(true)` | snarkVM |
//! | 2 | `Boolean.fromString("true")` | `Boolean::<N>::from_str("true")?` | snarkVM (`FromStr`) |
//! | 3 | `b.toString()` | `b.to_string()` | snarkVM (`Display`) |
//! | 4 | `Boolean.fromBytesLe(bytes)` | `Boolean::from_bytes_le(&bytes)?` | snarkVM (`FromBytes`) |
//! | 5 | `b.toBytesLe()` | `b.to_bytes_le()?` | snarkVM (`ToBytes`) |
//! | 6 | `Boolean.fromBitsLe(bits)` | `Boolean::from_bits_le(&bits)?` | snarkVM (`FromBits`) |
//! | 7 | `b.toBitsLe()` | `b.to_bits_le()` | snarkVM (`ToBits`) |
//! | 8 | `b.toPlaintext()` | [`to_plaintext`] | **this module** |
//! | 9 | `b.clone()` | `*b` — `Boolean` is `Copy`, so there is nothing to clone | std |
//! | 10 | `Boolean.random()` | [`random`] / `Uniform::rand(rng)` | **this module** |
//! | 11 | `b.not()` | `!b` | std (`Not`) |
//! | 12 | `b.and(other)` | `b & other` | std (`BitAnd`) |
//! | 13 | `b.or(other)` | `b \| other` | std (`BitOr`) |
//! | 14 | `b.xor(other)` | `b ^ other` | std (`BitXor`) |
//! | 15 | `b.nand(other)` | `b.nand(&other)` | snarkVM (`Nand` trait) |
//! | 16 | `b.nor(other)` | `b.nor(&other)` | snarkVM (`Nor` trait) |
//! | 17 | `b.equals(other)` | `b == other` | std (`PartialEq`) |
//!
//! `nand` and `nor` are the two that are *not* in the std operator set:
//! `use snarkvm::prelude::{Nand, Nor};` before calling them. Everything else on
//! the page either is an operator already in the prelude or a trait method.
//!
//! ## The encodings, pinned
//!
//! 1. **A boolean is exactly one byte, and only `0` / `1` decode.**
//!    `true.to_bytes_le() == [1]`, `false == [0]`. `from_bytes_le(&[2])` — or
//!    any other byte in `2..=255` — is an error, not "truthy". This is stricter
//!    than JS, where a hand-built `Uint8Array([2])` would have to be rejected by
//!    the decoder too; here snarkVM's `bool` decoder does it for free.
//!    Trailing bytes are **ignored** (`from_bytes_le(&[0, 9])` is `false`), so
//!    pass exactly what `to_bytes_le` produced.
//! 2. **`from_bits_le` wants one bit, not "however many you have".** `[]` and
//!    `[true, false]` both error. The JS class pre-checks the length and throws
//!    `"Boolean expects exactly 1 bit"`; snarkVM's message is
//!    `"Boolean::from_bits_le expects a list of one boolean, found N"`. Same
//!    rejection, different text — do not match on it.
//! 3. **`Boolean` derefs to `bool`.** `*b` is a real `bool`, which is how you
//!    feed it to `if`/`assert!`. Equality is asymmetric on purpose: snarkVM
//!    implements `PartialEq<Boolean<E>> for bool`, so `true == b` compiles
//!    while `b == true` does not — write `*b == true` or `true == b`.
//! 4. **`toPlaintext` produces a literal, not a field.** The result is
//!    `Plaintext::Literal(Literal::Boolean(..))`, whose `Display` is `"true"` /
//!    `"false"`. It is *not* `1field` / `0field`; the field cast is a separate
//!    conversion (see below).
//! 5. **Sampling needs an RNG, and that is deliberate.** The JS class reaches
//!    for a global generator; [`random`] takes one. Nothing in this crate
//!    samples silently.
//!
//! ## Casting a boolean (source-only, not on the docs page)
//!
//! The wasm source exposes 15 further methods the page omits — `toField`,
//! `toScalar`, `toGroup`, `toGroupLossy`, `toAddress`, `toAddressLossy`, and
//! `toU8` … `toI128`. Each is a one-liner, so no wrapper is added here:
//! [`Field::from_bits_le(&[*b])`](snarkvm::prelude::Field) packs the single bit
//! into `0field`/`1field` (the same for `Scalar`); the integer casts are
//! `U8::new(u8::from(*b))` and friends; the group/address casts go through that
//! field — strictly via `Group::from_field` (which can fail, since not every
//! field element is an x-coordinate) or lossily via the `CastLossy` trait.
//!
//! ## Usage
//!
//! ```
//! use aleo_rust_sdk::boolean;
//! use snarkvm::prelude::{Boolean, Nand, Nor, TestnetV0};
//!
//! let a = Boolean::<TestnetV0>::new(true);
//! let b = Boolean::<TestnetV0>::new(false);
//!
//! // Operators for and/or/xor/not …
//! assert_eq!(a & !b, Boolean::new(true));
//! // … traits for the two that have no operator.
//! assert_eq!(a.nand(&b), Boolean::new(true));
//! assert_eq!(a.nor(&b), Boolean::new(false));
//!
//! // JS: a.toPlaintext()
//! assert_eq!(boolean::to_plaintext(&a).to_string(), "true");
//! ```

use snarkvm::prelude::{Boolean, CryptoRng, Literal, Network, Plaintext, Rng};
use snarkvm::utilities::rand::Uniform;

/// Returns the boolean as an Aleo [`Plaintext`] — the JS `boolean.toPlaintext()`.
///
/// The result is a `Literal::Boolean`, so it renders as `"true"` / `"false"`
/// and round-trips through `Plaintext::from_str`. It is **not** a `Field`;
/// casting to `0field`/`1field` is `Field::from_bits_le(&[*b])`.
///
/// # Arguments
/// * `boolean` - The boolean to wrap.
pub fn to_plaintext<N: Network>(boolean: &Boolean<N>) -> Plaintext<N> {
    Plaintext::from(Literal::Boolean(*boolean))
}

/// Samples a uniformly random boolean — the JS `Boolean.random()`.
///
/// The JS class takes no argument because it uses a global generator; this
/// crate never samples implicitly, so the RNG is passed in.
///
/// # Arguments
/// * `rng` - The random number generator.
pub fn random<N: Network, R: Rng + CryptoRng>(rng: &mut R) -> Boolean<N> {
    Uniform::rand(rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::{
        Boolean, Field, FromBits, FromBytes, Nand, Nor, TestRng, TestnetV0, ToBits, ToBytes,
    };
    use std::str::FromStr;

    type CurrentNetwork = TestnetV0;

    fn b(value: bool) -> Boolean<CurrentNetwork> {
        Boolean::new(value)
    }

    #[test]
    fn bytes_are_a_single_byte_and_only_zero_or_one_decode() {
        assert_eq!(b(true).to_bytes_le().unwrap(), vec![1u8]);
        assert_eq!(b(false).to_bytes_le().unwrap(), vec![0u8]);

        assert_eq!(
            Boolean::<CurrentNetwork>::from_bytes_le(&[1]).unwrap(),
            b(true)
        );
        assert_eq!(
            Boolean::<CurrentNetwork>::from_bytes_le(&[0]).unwrap(),
            b(false)
        );

        // Every other byte is rejected, not treated as "truthy".
        for byte in [2u8, 3, 127, 128, 255] {
            assert!(
                Boolean::<CurrentNetwork>::from_bytes_le(&[byte]).is_err(),
                "byte {byte} must not decode to a boolean"
            );
        }
        assert!(Boolean::<CurrentNetwork>::from_bytes_le(&[]).is_err());

        // Trailing bytes are ignored: the decoder reads one byte and stops.
        assert_eq!(
            Boolean::<CurrentNetwork>::from_bytes_le(&[0, 9]).unwrap(),
            b(false)
        );
    }

    #[test]
    fn from_bits_le_requires_exactly_one_bit() {
        assert_eq!(
            Boolean::<CurrentNetwork>::from_bits_le(&[true]).unwrap(),
            b(true)
        );
        assert_eq!(
            Boolean::<CurrentNetwork>::from_bits_le(&[false]).unwrap(),
            b(false)
        );

        let empty = Boolean::<CurrentNetwork>::from_bits_le(&[]).unwrap_err().to_string();
        assert!(empty.contains("one boolean"), "unexpected error: {empty}");
        assert!(Boolean::<CurrentNetwork>::from_bits_le(&[true, false]).is_err());

        // The inverse is always exactly one bit.
        assert_eq!(b(true).to_bits_le(), vec![true]);
        assert_eq!(b(false).to_bits_le(), vec![false]);
    }

    #[test]
    fn plaintext_is_a_boolean_literal_not_a_field() {
        let plaintext = to_plaintext(&b(true));
        assert_eq!(plaintext.to_string(), "true");
        assert_eq!(to_plaintext(&b(false)).to_string(), "false");

        // Not the field cast: that one is `Field::from_bits_le`.
        assert_ne!(plaintext.to_string(), "1field");
        assert_eq!(
            Field::<CurrentNetwork>::from_bits_le(&[true]).unwrap().to_string(),
            "1field"
        );

        // And it round-trips through the plaintext parser.
        assert_eq!(
            Plaintext::<CurrentNetwork>::from_str("true").unwrap().to_string(),
            "true"
        );
        assert_eq!(
            Plaintext::<CurrentNetwork>::from_str("false").unwrap().to_string(),
            "false"
        );
    }

    #[test]
    fn operators_match_the_bool_truth_table() {
        for x in [true, false] {
            for y in [true, false] {
                let (a, c) = (b(x), b(y));

                assert_eq!(!a, b(!x), "not({x})");
                assert_eq!(a & c, b(x & y), "{x} and {y}");
                assert_eq!(a | c, b(x | y), "{x} or {y}");
                assert_eq!(a ^ c, b(x ^ y), "{x} xor {y}");
                // The two that need the `Nand` / `Nor` traits rather than an operator.
                assert_eq!(a.nand(&c), b(!(x & y)), "{x} nand {y}");
                assert_eq!(a.nor(&c), b(!(x | y)), "{x} nor {y}");
            }
        }
    }

    #[test]
    fn boolean_derefs_to_bool_and_compares_one_way() {
        let t = b(true);

        // `Deref<Target = bool>`: this is how a boolean reaches `if` / `assert!`.
        assert!(*t);

        // snarkVM implements `PartialEq<Boolean> for bool`, not the reverse,
        // so `true == t` compiles and `t == true` does not.
        assert!(true == t);
        assert!(false != t);
        assert!(t == b(true));
        assert!(b(true) != b(false));

        // `Copy`, so the JS `clone()` is free — no `.clone()` on a boolean.
        let copy = t;
        assert_eq!(copy, t);
    }

    #[test]
    fn from_string_accepts_only_the_two_literals() {
        assert_eq!(
            Boolean::<CurrentNetwork>::from_str("true").unwrap(),
            b(true)
        );
        assert_eq!(
            Boolean::<CurrentNetwork>::from_str("false").unwrap(),
            b(false)
        );

        for bad in ["TRUE", "True", "1", "0", "", "true ", " true"] {
            assert!(
                Boolean::<CurrentNetwork>::from_str(bad).is_err(),
                "{bad:?} must not parse as a boolean"
            );
        }
    }

    #[test]
    fn random_samples_both_values() {
        let rng = &mut TestRng::fixed(0);
        let mut seen_true = false;
        let mut seen_false = false;

        for _ in 0..64 {
            if *random::<CurrentNetwork, _>(rng) {
                seen_true = true;
            } else {
                seen_false = true;
            }
        }

        assert!(
            seen_true && seen_false,
            "expected both values in 64 samples"
        );
    }
}
