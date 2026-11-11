//! Aleo integer types — parity with the JS SDK's wasm `Integer Types` page.
//!
//! The JS SDK ships ten integer classes — `U8`, `U16`, `U32`, `U64`, `U128`,
//! `I8`, `I16`, `I32`, `I64`, `I128` — each a wasm newtype over snarkVM's
//! `Integer<E, I>`. **In Rust there is nothing to wrap.** The native types are
//! already the canonical ones that every snarkVM API accepts, and every method
//! on the JS page is already available — either inherent (`from_field_lossy`,
//! `to_scalar`) or as a trait method (`FromStr`, `Display`, `ToBytes`,
//! `AddWrapped`, …).
//!
//! So this module is a **mapping table plus three helpers**, not ten newtypes.
//! Mirroring the wasm shells here would hand Rust callers a parallel `U32` that
//! no `Process`, `Program` or `Record` in this crate would accept.
//!
//! ## JS `Integer Types` → Rust mapping
//!
//! All ten types share one API on both sides, so every row below applies to all
//! of them.
//!
//! | # | JS | Rust | Where |
//! |---|---|---|---|
//! | 1 | `fromString(s)` | `U32::from_str("42u32")` | snarkVM (`FromStr`) |
//! | 2 | `toString()` | `value.to_string()` | snarkVM (`Display`) |
//! | 3 | `fromBytesLe(b)` | `U32::read_le(&b[..])` | snarkVM (`FromBytes`) |
//! | 4 | `toBytesLe()` | `value.to_bytes_le()` | snarkVM (`ToBytes`) |
//! | 5 | `fromBitsLe(bits)` | `U32::from_bits_le(&bits)` | snarkVM (`FromBits`) |
//! | 6 | `toBitsLe()` | `value.to_bits_le()` | snarkVM (`ToBits`) |
//! | 7 | `absChecked()` | `value.abs_checked()` | snarkVM (`AbsChecked`) |
//! | 8 | `absWrapped()` | `value.abs_wrapped()` | snarkVM (`AbsWrapped`) |
//! | 9 | `addWrapped(o)` | `value.add_wrapped(&o)` | snarkVM (`AddWrapped`) |
//! | 10 | `subWrapped(o)` | `value.sub_wrapped(&o)` | snarkVM (`SubWrapped`) |
//! | 11 | `mulWrapped(o)` | `value.mul_wrapped(&o)` | snarkVM (`MulWrapped`) |
//! | 12 | `divWrapped(o)` | `value.div_wrapped(&o)` | snarkVM (`DivWrapped`) |
//! | 13 | `powU8(e)` | `value.pow(&u8_exponent)` | snarkVM (`Pow`) |
//! | 14 | `powU16(e)` | `value.pow(&u16_exponent)` | snarkVM (`Pow`) |
//! | 15 | `powU32(e)` | `value.pow(&u32_exponent)` | snarkVM (`Pow`) |
//! | 16 | `neg()` | `-value` | snarkVM (`Neg`, signed only) |
//! | 17 | `equals(o)` | `value == o` | snarkVM (`PartialEq`) |
//! | 18 | `rem(o)` | `value % o` | snarkVM (`Rem`) |
//! | 19 | `remWrapped(o)` | `value.rem_wrapped(&o)` | snarkVM (`RemWrapped`) |
//! | 20 | `toScalar()` | `value.to_scalar()` | snarkVM (inherent) |
//! | 21 | `toPlaintext()` | [`to_plaintext`] | **this module** |
//! | 22 | `fromField(f)` | `U32::from_field(&f)` | snarkVM (`FromField`) |
//! | 23 | `fromFields(fs)` | `U32::from_fields(&fs)` | snarkVM (`FromFields`) |
//! | 24 | `clone()` | `.clone()` (the types are `Copy`) | snarkVM (`Clone`) |
//!
//! Upstream also exposes a few methods that the doc page does not list:
//!
//! | JS | Rust | Where |
//! |---|---|---|
//! | `toField()` | `value.to_field()` | snarkVM (`ToField`) |
//! | `fromFieldLossy(f)` | `U32::from_field_lossy(&f)` | snarkVM (inherent) |
//! | `toBooleanLossy()` | [`to_boolean_lossy`] | **this module** |
//! | `toU8Lossy()` … `toI128Lossy()` (10 methods) | [`cast_lossy`] | **this module** |
//!
//! ## 🔴 "Checked" halts, it does not return `Result`
//!
//! `absChecked` and `rem` are not fallible in Rust — snarkVM implements them by
//! calling `E::halt(...)`, which panics on the `Console` environment used by
//! this crate. That is the right shape for the VM (a bad instruction aborts the
//! execution), but it means a library caller must bounds-check first:
//!
//! - `I8::MIN.abs_checked()` and any `abs_checked` on a signed type whose
//!   magnitude does not fit will panic.
//! - `a % 0` and `I8::MIN % -1` panic; `%` is a *checked* remainder.
//! - `-value` on an **unsigned** type panics — negation is signed-only.
//!
//! The wrapped variants only halt when the divisor is zero; overflow is handled
//! by two's-complement wrapping (`255u8.add_wrapped(&1u8) == 0u8`).
//!
//! ## Casts go through `Field`, exactly like upstream
//!
//! Every JS cross-cast (`toU8Lossy`, `toI128Lossy`, …) is
//! `source.to_field()` followed by `Target::from_field_lossy(&field)`, and
//! [`cast_lossy`] does the same. Two consequences worth knowing:
//!
//! - Narrowing truncates the low bits: `300u16` → `44u8`.
//! - A negative source casts as **two's complement** of its own width:
//!   `-1i8` → `255u8`, not an error.
//! - 🔴 **Widening does not sign-extend.** The field holds the source's raw bit
//!   pattern (`-1i8` → `field 255`), and the target reads only its own low bits,
//!   so `-1i8` cast to `i32` is **`255i32`**, not `-1i32`. Cross-casting keeps
//!   the *bits*; it does not preserve the arithmetic value. Convert through
//!   `to_scalar()` / `to_field()` round-trips only when the value is known to be
//!   non-negative, and prefer staying in one width otherwise.
//!
//! ## Usage
//!
//! ```
//! use aleo_rust_sdk::integer_types::{cast_lossy, to_boolean_lossy, to_plaintext};
//! use snarkvm::prelude::{TestnetV0, U8, U32};
//! use std::str::FromStr;
//!
//! let value = U32::<TestnetV0>::from_str("42u32").unwrap();
//!
//! // JS: integer.toPlaintext() — the literal form used when hashing.
//! assert_eq!(to_plaintext(&value).unwrap().to_string(), "42u32");
//!
//! // JS: integer.toBooleanLossy() — least-significant bit, so 42 is even.
//! assert_eq!(to_boolean_lossy(&value).to_string(), "false");
//!
//! // JS: integer.toU8Lossy() — 42 still fits in a byte.
//! let narrowed = cast_lossy::<TestnetV0, u32, u8>(&value).unwrap();
//! assert_eq!(narrowed, U8::<TestnetV0>::from_str("42u8").unwrap());
//! ```

use anyhow::Result;
use snarkvm::prelude::{
    Boolean, IntegerType, Network, Plaintext, ToBits, ToField, integers::Integer,
};
use std::str::FromStr;

/// JS `toPlaintext()` — wrap the integer in a `Plaintext::Literal`.
///
/// Hashing an integer in Leo/Aleo hashes its **plaintext literal** encoding.
/// Hashing the bare field encoding of the same value yields a different digest,
/// so a value only matches an on-chain hash once it is wrapped this way — which
/// is precisely why the JS SDK exposes the conversion.
///
/// The literal is produced through the type's own `Display`/`FromStr` pair
/// (`"42u32"`, `"-5i32"`), which parses back into the matching
/// `Literal::U32` / `Literal::I32` variant.
pub fn to_plaintext<N: Network, I: IntegerType>(value: &Integer<N, I>) -> Result<Plaintext<N>> {
    // snarkVM's `FromStr` for `Plaintext` already returns `anyhow::Result`, so
    // the literal is parsed straight back into a `Plaintext::Literal`.
    Plaintext::from_str(&value.to_string())
}

/// JS `toBooleanLossy()` — the least-significant bit as a `Boolean`.
///
/// "Lossy" is literal: every integer collapses to one bit, so `42u32` and
/// `40u32` both become `false`. Negative values follow two's complement, which
/// means `-1i8` is `true`.
pub fn to_boolean_lossy<N: Network, I: IntegerType>(value: &Integer<N, I>) -> Boolean<N> {
    let bits = value.to_bits_le();
    Boolean::new(bits.first().copied().unwrap_or(false))
}

/// JS `toU8Lossy()` … `toI128Lossy()` — one generic cast for all ten methods.
///
/// Mirrors upstream's cross-cast macro: convert to a field, then truncate into
/// the target width. No range check is performed, so `300u16` becomes `44u8`
/// and `-1i8` becomes `255u8` (two's complement), matching the JS behaviour.
///
/// The type parameters are the *native* primitive widths (`u32`, `i128`, …),
/// because those are what implement `IntegerType`.
pub fn cast_lossy<N: Network, S: IntegerType, T: IntegerType>(
    value: &Integer<N, S>,
) -> Result<Integer<N, T>> {
    Ok(Integer::<N, T>::from_field_lossy(&value.to_field()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::{
        AbsChecked, AbsWrapped, AddWrapped, DivWrapped, FromBytes, FromField, FromFields, I8, I32,
        Literal, MulWrapped, Pow, RemWrapped, SubWrapped, TestnetV0, ToBytes, U8, U16, U32, U128,
    };

    type CurrentNetwork = TestnetV0;

    fn u8_value(s: &str) -> U8<CurrentNetwork> {
        U8::from_str(s).unwrap()
    }

    fn u32_value(s: &str) -> U32<CurrentNetwork> {
        U32::from_str(s).unwrap()
    }

    #[test]
    fn to_plaintext_wraps_every_integer_kind() {
        // Unsigned and signed, including a negative value: the literal must
        // round-trip through Display unchanged for all ten types.
        assert_eq!(
            to_plaintext(&u8_value("200u8")).unwrap().to_string(),
            "200u8"
        );
        assert_eq!(
            to_plaintext(&u32_value("42u32")).unwrap().to_string(),
            "42u32"
        );
        assert_eq!(
            to_plaintext(
                &U128::<CurrentNetwork>::from_str("340282366920938463463374607431768211455u128")
                    .unwrap()
            )
            .unwrap()
            .to_string(),
            "340282366920938463463374607431768211455u128"
        );
        assert_eq!(
            to_plaintext(&I32::<CurrentNetwork>::from_str("-5i32").unwrap())
                .unwrap()
                .to_string(),
            "-5i32"
        );
    }

    #[test]
    fn to_plaintext_produces_the_literal_variant() {
        // The JS class builds `Literal::U32(value)`. Confirm the string round-trip
        // lands on the same variant rather than some other literal encoding.
        let value = u32_value("42u32");
        match to_plaintext(&value).unwrap() {
            Plaintext::Literal(Literal::U32(inner), _) => assert_eq!(inner, value),
            other => panic!("expected Literal::U32, got {other:?}"),
        }
    }

    #[test]
    fn to_boolean_lossy_matches_upstream_vectors() {
        // Literal vectors from the upstream wasm test `test_integer_to_boolean_lossy`.
        assert_eq!(to_boolean_lossy(&u32_value("0u32")).to_string(), "false");
        assert_eq!(to_boolean_lossy(&u32_value("1u32")).to_string(), "true");
        assert_eq!(to_boolean_lossy(&u32_value("4u32")).to_string(), "false");
        assert_eq!(to_boolean_lossy(&u32_value("5u32")).to_string(), "true");

        // Two's complement: -1 is all ones, therefore odd.
        assert_eq!(
            to_boolean_lossy(&I8::<CurrentNetwork>::from_str("-1i8").unwrap()).to_string(),
            "true"
        );
        assert_eq!(
            to_boolean_lossy(&I8::<CurrentNetwork>::from_str("-2i8").unwrap()).to_string(),
            "false"
        );
    }

    #[test]
    fn cast_lossy_identity_and_narrowing() {
        // Upstream `test_cross_cast_identity`.
        let value = u32_value("42u32");
        assert_eq!(
            cast_lossy::<CurrentNetwork, u32, u32>(&value).unwrap(),
            value
        );

        // 300 = 0b1_0010_1100 -> low byte 0b0010_1100 = 44.
        let wide = U16::<CurrentNetwork>::from_str("300u16").unwrap();
        assert_eq!(
            cast_lossy::<CurrentNetwork, u16, u8>(&wide).unwrap(),
            u8_value("44u8")
        );
    }

    #[test]
    fn cast_lossy_negative_is_twos_complement() {
        let minus_one = I8::<CurrentNetwork>::from_str("-1i8").unwrap();
        assert_eq!(
            cast_lossy::<CurrentNetwork, i8, u8>(&minus_one).unwrap(),
            u8_value("255u8")
        );

        // -128 is 0b1000_0000: still 128 when read as unsigned.
        let min = I8::<CurrentNetwork>::from_str("-128i8").unwrap();
        assert_eq!(
            cast_lossy::<CurrentNetwork, i8, u8>(&min).unwrap(),
            u8_value("128u8")
        );
    }

    #[test]
    fn cast_lossy_does_not_sign_extend() {
        // The cast moves *bits* through a field, so widening a negative i8 does
        // not reproduce the same arithmetic value: -1i8 is field 255, and i32
        // reads that back as 255, not -1. Upstream's cross-cast macro behaves
        // identically, so this is parity, not a bug in the wrapper.
        let minus_one = I8::<CurrentNetwork>::from_str("-1i8").unwrap();
        assert_eq!(
            cast_lossy::<CurrentNetwork, i8, i32>(&minus_one).unwrap().to_string(),
            "255i32"
        );

        // Non-negative values do survive widening unchanged.
        let forty_two = I8::<CurrentNetwork>::from_str("42i8").unwrap();
        assert_eq!(
            cast_lossy::<CurrentNetwork, i8, i32>(&forty_two).unwrap().to_string(),
            "42i32"
        );
    }

    #[test]
    fn cast_lossy_truncates_128_bit_values() {
        let big = U128::<CurrentNetwork>::from_str("36893488147419103237u128").unwrap(); // 2^65 + 5
        assert_eq!(
            cast_lossy::<CurrentNetwork, u128, u64>(&big).unwrap().to_string(),
            "5u64"
        );
    }

    #[test]
    fn checked_abs_handles_sign_and_wrapped_abs_saturates_min() {
        let negative = I8::<CurrentNetwork>::from_str("-5i8").unwrap();
        assert_eq!(negative.abs_checked().to_string(), "5i8");
        assert_eq!(negative.abs_wrapped().to_string(), "5i8");

        // -128 has no positive counterpart in i8: the wrapped form stays put.
        let min = I8::<CurrentNetwork>::from_str("-128i8").unwrap();
        assert_eq!(min.abs_wrapped().to_string(), "-128i8");

        // Unsigned values are returned unchanged by both.
        assert_eq!(u8_value("200u8").abs_checked().to_string(), "200u8");
        assert_eq!(u8_value("200u8").abs_wrapped().to_string(), "200u8");
    }

    #[test]
    fn wrapped_arithmetic_vectors() {
        assert_eq!(
            u8_value("255u8").add_wrapped(&u8_value("1u8")).to_string(),
            "0u8"
        );
        assert_eq!(
            u8_value("0u8").sub_wrapped(&u8_value("1u8")).to_string(),
            "255u8"
        );
        assert_eq!(
            u8_value("200u8").mul_wrapped(&u8_value("2u8")).to_string(),
            "144u8"
        );
        assert_eq!(
            u8_value("7u8").div_wrapped(&u8_value("2u8")).to_string(),
            "3u8"
        );
        assert_eq!(
            u8_value("7u8").rem_wrapped(&u8_value("4u8")).to_string(),
            "3u8"
        );

        // `I8::MIN % -1` overflows in checked mode but wraps to 0.
        let min = I8::<CurrentNetwork>::from_str("-128i8").unwrap();
        let minus_one = I8::<CurrentNetwork>::from_str("-1i8").unwrap();
        assert_eq!(min.rem_wrapped(&minus_one).to_string(), "0i8");

        // Exponentiation takes the JS `U8`/`U16`/`U32` exponent type directly.
        let base = u32_value("3u32");
        assert_eq!(
            base.pow(&U8::<CurrentNetwork>::from_str("5u8").unwrap()).to_string(),
            "243u32"
        );
        assert_eq!(
            base.pow(&U16::<CurrentNetwork>::from_str("2u16").unwrap()).to_string(),
            "9u32"
        );
    }

    #[test]
    fn field_and_scalar_conversions_round_trip() {
        let value = u32_value("42u32");
        let field = value.to_field().unwrap();
        assert_eq!(U32::<CurrentNetwork>::from_field(&field).unwrap(), value);
        assert_eq!(U32::<CurrentNetwork>::from_fields(&[field]).unwrap(), value);
        assert_eq!(value.to_scalar().to_string(), "42scalar");

        // `from_field_lossy` is the truncating counterpart used by the casts.
        assert_eq!(
            U8::<CurrentNetwork>::from_field_lossy(&field),
            u8_value("42u8")
        );
    }

    #[test]
    fn bytes_and_bits_round_trip() {
        let value = u32_value("42u32");
        let bytes = value.to_bytes_le().unwrap();
        assert_eq!(bytes.len(), 4);
        assert_eq!(U32::<CurrentNetwork>::read_le(&bytes[..]).unwrap(), value);

        let bits = value.to_bits_le();
        assert_eq!(bits.len(), 32);
        assert!(!bits[0]); // 42 is even
        assert_eq!(to_boolean_lossy(&value).to_string(), "false");
    }

    #[test]
    fn from_string_enforces_the_type_suffix() {
        assert!(U32::<CurrentNetwork>::from_str("42u32").is_ok());
        assert!(U32::<CurrentNetwork>::from_str("42u8").is_err()); // wrong suffix
        assert!(U8::<CurrentNetwork>::from_str("256u8").is_err()); // out of range
        assert!(U8::<CurrentNetwork>::from_str("-1u8").is_err()); // unsigned
        assert!(I8::<CurrentNetwork>::from_str("-128i8").is_ok());
        assert!(I8::<CurrentNetwork>::from_str("128i8").is_err()); // out of range
    }
}
