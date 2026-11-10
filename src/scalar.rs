//! Aleo `Scalar` — parity with the JS SDK's wasm `Scalar` class.
//!
//! No wrapper type is needed: snarkVM's [`Scalar<N>`] is already the native
//! type behind the wasm class. The docs page lists **37 methods**, most of
//! which are single trait calls. This module supplies the conversions that
//! are not, and pins the counter-intuitive semantics with tests.
//!
//! ## JS `Scalar` → Rust mapping
//!
//! | # | JS `Scalar` | Rust equivalent | Where |
//! |---|---|---|---|
//! | 1 | `Scalar.fromString(s)` | `Scalar::<N>::from_str(s)?` | snarkVM (`FromStr`) |
//! | 2 | `s.toString()` | `s.to_string()` | snarkVM (`Display`) |
//! | 3 | `Scalar.fromBytesLe(b)` | `Scalar::from_bytes_le(&b)?` | snarkVM (`FromBytes`) |
//! | 4 | `s.toBytesLe()` | `s.to_bytes_le()?` | snarkVM (`ToBytes`) |
//! | 5 | `Scalar.fromBitsLe(b)` | `Scalar::from_bits_le(&b)?` | snarkVM (`FromBits`) |
//! | 6 | `s.toBitsLe()` | `s.to_bits_le()` | snarkVM (`ToBits`) |
//! | 7 | `s.toPlaintext()` | [`to_plaintext`] | **this module** |
//! | 8 | `s.toField()` | [`to_field`] | **this module** |
//! | 9 | `s.clone()` | `s` — `Scalar` is `Copy` | std |
//! | 10 | `Scalar.random()` | [`random`] / `Uniform::rand(rng)` | **this module** |
//! | 11 | `s.add(t)` | `s + t` | std (`Add`) |
//! | 12 | `s.subtract(t)` | `s - t` | std (`Sub`) |
//! | 13 | `s.multiply(t)` | `s * t` | std (`Mul`) |
//! | 14 | `s.divide(t)` | `s / t` | std (`Div`) |
//! | 15 | `s.double()` | `s.double()` | snarkVM (`Double`) |
//! | 16 | `s.pow(t)` | `s.pow(t)` — exponent is a **Scalar** | snarkVM (`Pow`) |
//! | 17 | `s.inverse()` | [`negate`] — **not** the multiplicative inverse! | **this module** |
//! | 18 | `Scalar.one()` | `Scalar::one()` | snarkVM (`One`) |
//! | 19 | `Scalar.zero()` | `Scalar::zero()` | snarkVM (`Zero`) |
//! | 20 | `s.equals(t)` | `s == t` | std (`PartialEq`) |
//! | 21 | `s.toBoolean()` | [`to_boolean`] | **this module** |
//! | 22 | `s.toBooleanLossy()` | [`to_boolean_lossy`] | **this module** |
//! | 23 | `s.toGroup()` | [`to_group`] | **this module** |
//! | 24 | `s.toGroupLossy()` | [`to_group_lossy`] | **this module** |
//! | 25 | `s.toAddress()` | [`to_address`] | **this module** |
//! | 26 | `s.toAddressLossy()` | [`to_address_lossy`] | **this module** |
//! | 27–36 | `s.toU8Lossy()` … `s.toI128Lossy()` | [`to_field`] then `CastLossy` — see [Integer casts](#integer-casts) | snarkVM |
//!
//! Methods the page does **not** have: `toFields()` and `scalarMultiply()`
//! belong to `Group`/`Address`, not to `Scalar`.
//!
//! ## 🔴 `inverse()` is negation, not inversion
//!
//! The wasm implementation is `Scalar(-self.0)` — the **additive inverse**,
//! exactly like `Field.inverse()`. The docs say *"Invert the scalar element"*
//! which is wrong on both counts. The multiplicative inverse is `Inverse` in
//! snarkVM. The helper here is deliberately named [`negate`].
//!
//! Note the contrast with `Group.inverse()`, which **is** a true group inverse
//! (though the JS docs' geometric note about it is wrong — see [`crate::group`]).
//! Three classes, two different meanings of `inverse()`.
//!
//! ## 🔴 Every lossy cast goes through `toField()` first
//!
//! The upstream wasm code never casts a `Scalar` directly. For `toGroupLossy`
//! it does `self.0.to_field()` then `field.cast_lossy()`; for the ten integer
//! casts it does `IntegerNative::from_field_lossy(&self.0.to_field()?)`.
//! Consequently a `Scalar`'s lossy result is **identical** to the
//! [`crate::field`] helper applied to its `to_field()` value:
//!
//! ```text
//! scalar::to_group_lossy(&s)  == field::to_group_lossy(&scalar::to_field(&s)?)
//! scalar::to_boolean_lossy(&s) == scalar::to_field(&s)?.to_bits_le()[0]
//! ```
//!
//! The tests pin these identities. `toField()` itself is `ToField::to_field`
//! and returns a `Result` (it can fail on a non-canonical bit pattern), so all
//! the lossy helpers here also return `Result` even though JS's
//! `toBooleanLossy` cannot fail.
//!
//! ## Strict vs lossy
//!
//! `toBoolean` accepts only `0scalar` and `1scalar` and errors otherwise;
//! `toBooleanLossy` extracts the LSB (`2scalar → false`, `3scalar → true`).
//! `toGroup` / `toAddress` recover a curve point from the field as an
//! x-coordinate and fail when it is not valid — `1scalar` → `1field`, which
//! is **not** a valid x-coordinate (see [`crate::field`]). The `Lossy`
//! variants fall back to Elligator-2 (`1field` → generator) and never fail.
//!
//! ## Integer casts
//!
//! The ten integer lossy conversions are one-liners once you have the field.
//! No per-type wrapper is added — `CastLossy` covers all ten, just as in
//! [`crate::field`]:
//!
//! ```
//! use aleo_rust_sdk::scalar;
//! use snarkvm::prelude::{CastLossy, Scalar, TestnetV0, U8};
//! use std::str::FromStr;
//!
//! let s = Scalar::<TestnetV0>::from_str("258scalar").unwrap();
//! let field = scalar::to_field(&s).unwrap();
//! let small: U8<TestnetV0> = field.cast_lossy(); // 258 mod 256 = 2
//! assert_eq!(small, U8::new(2));
//! ```
//!
//! ## RNG injection
//!
//! `Scalar.random()` in JS reaches for a global generator. [`random`] takes
//! an explicit `rng`, as elsewhere in this crate.
//!
//! ## Usage
//!
//! ```
//! use aleo_rust_sdk::scalar;
//! use snarkvm::prelude::{Scalar, TestnetV0};
//! use std::str::FromStr;
//!
//! let s = Scalar::<TestnetV0>::from_str("3scalar").unwrap();
//!
//! // JS: s.inverse() — but it is *negation*, not 1/s.
//! assert_eq!(scalar::negate(&s), -s);
//!
//! // JS: s.toBooleanLossy() — LSB, not "is non-zero".
//! assert!(scalar::to_boolean_lossy(&s));
//! // ...while the strict cast rejects 3scalar.
//! assert!(scalar::to_boolean(&s).is_err());
//! ```

use anyhow::{Context, Result};
use snarkvm::prelude::{
    Address, CastLossy, CryptoRng, Field, FromField, Group, Literal, Network, One, Plaintext, Rng,
    Scalar, ToBits, ToField, Zero,
};
use snarkvm::utilities::rand::Uniform;

/// Returns the additive inverse of the scalar — the JS `s.inverse()`.
///
/// 🔴 **This is negation, not the multiplicative inverse.** Named [`negate`]
/// so the upstream trap cannot be re-imported into Rust call sites.
///
/// # Arguments
/// * `scalar` - The scalar element to negate.
pub fn negate<N: Network>(scalar: &Scalar<N>) -> Scalar<N> {
    -*scalar
}

/// Returns the scalar as an Aleo [`Plaintext`] — the JS `s.toPlaintext()`.
///
/// The result is a `Literal::Scalar`, so it renders as `"Nscalar"` and
/// round-trips through `Plaintext::from_str`.
///
/// # Arguments
/// * `scalar` - The scalar element to wrap.
pub fn to_plaintext<N: Network>(scalar: &Scalar<N>) -> Plaintext<N> {
    Plaintext::from(Literal::Scalar(*scalar))
}

/// Samples a uniformly random scalar — the JS `Scalar.random()`.
///
/// # Arguments
/// * `rng` - The random number generator.
pub fn random<N: Network, R: Rng + CryptoRng>(rng: &mut R) -> Scalar<N> {
    Uniform::rand(rng)
}

/// Converts a scalar into its field representation — the JS `s.toField()`.
///
/// This is the bridge every other cast in the wasm class goes through.
/// Returns a `Result` because `ToField::to_field` can reject a non-canonical
/// bit pattern.
///
/// # Arguments
/// * `scalar` - The scalar element to convert.
pub fn to_field<N: Network>(scalar: &Scalar<N>) -> Result<Field<N>> {
    ToField::to_field(scalar).context("Failed to convert scalar to field")
}

/// Casts the scalar to a `bool`, strictly — the JS `s.toBoolean()`.
///
/// `Ok(false)` for `0scalar`, `Ok(true)` for `1scalar`, an error otherwise.
///
/// # Arguments
/// * `scalar` - The scalar element to cast.
pub fn to_boolean<N: Network>(scalar: &Scalar<N>) -> Result<bool> {
    if *scalar == Scalar::zero() {
        Ok(false)
    } else if *scalar == Scalar::one() {
        Ok(true)
    } else {
        anyhow::bail!("Failed to convert scalar to boolean: scalar is not zero or one")
    }
}

/// Casts the scalar to a `bool` by extracting the least-significant bit —
/// the JS `s.toBooleanLossy()`.
///
/// **Not** "is non-zero": `2scalar` → `false`, `3scalar` → `true`.
///
/// # Arguments
/// * `scalar` - The scalar element to cast.
pub fn to_boolean_lossy<N: Network>(scalar: &Scalar<N>) -> bool {
    ToBits::to_bits_le(scalar)[0]
}

/// Casts the scalar to a [`Group`] element, strictly — the JS `s.toGroup()`.
///
/// Converts to a field first, then recovers the group element from it as an
/// x-coordinate. Fails when the field is not a valid x-coordinate.
///
/// # Arguments
/// * `scalar` - The scalar element to cast.
pub fn to_group<N: Network>(scalar: &Scalar<N>) -> Result<Group<N>> {
    let field = to_field(scalar)?;
    <Group<N> as FromField>::from_field(&field).context("Field is not a valid x-coordinate")
}

/// Casts the scalar to a [`Group`] element, lossily — the JS `s.toGroupLossy()`.
///
/// Converts to a field first, then applies `CastLossy` (x-coordinate recovery
/// with an Elligator-2 fallback). `1scalar` maps to the generator.
///
/// # Arguments
/// * `scalar` - The scalar element to cast.
pub fn to_group_lossy<N: Network>(scalar: &Scalar<N>) -> Result<Group<N>> {
    let field = to_field(scalar)?;
    Ok(CastLossy::cast_lossy(&field))
}

/// Casts the scalar to an [`Address`], strictly — the JS `s.toAddress()`.
///
/// Goes through [`to_group`] and inherits its strictness.
///
/// # Arguments
/// * `scalar` - The scalar element to cast.
pub fn to_address<N: Network>(scalar: &Scalar<N>) -> Result<Address<N>> {
    Ok(Address::new(to_group(scalar)?))
}

/// Casts the scalar to an [`Address`], lossily — the JS `s.toAddressLossy()`.
///
/// Goes through [`to_group_lossy`].
///
/// # Arguments
/// * `scalar` - The scalar element to cast.
pub fn to_address_lossy<N: Network>(scalar: &Scalar<N>) -> Result<Address<N>> {
    Ok(Address::new(to_group_lossy(scalar)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::{
        Boolean, Double, FromBits, FromBytes, I8, I16, I32, I64, I128, Inverse, Pow, TestRng,
        TestnetV0, ToBytes, U8, U16, U32, U64, U128,
    };
    use std::str::FromStr;

    type CurrentNetwork = TestnetV0;

    fn s(value: u128) -> Scalar<CurrentNetwork> {
        Scalar::from_str(&format!("{value}scalar")).expect("literal scalar parses")
    }

    // ── negate: the inverse() trap ────────────────────────────────────

    #[test]
    fn negate_is_additive_inverse_not_multiplicative() {
        let three = s(3);
        assert_eq!(negate(&three), -three);
        assert_eq!(three + negate(&three), Scalar::zero());
        assert_eq!(negate(&negate(&three)), three);

        // The real multiplicative inverse is a different value.
        let third = Inverse::inverse(&three).unwrap();
        assert_eq!(three * third, Scalar::one());
        assert_ne!(negate(&three), third);
    }

    // ── toPlaintext ───────────────────────────────────────────────────

    #[test]
    fn to_plaintext_is_a_scalar_literal() {
        let plaintext = to_plaintext(&s(42));
        assert_eq!(plaintext.to_string(), "42scalar");
        assert_eq!(
            Plaintext::<CurrentNetwork>::from_str("42scalar").unwrap().to_string(),
            "42scalar"
        );
    }

    // ── toField: the bridge ───────────────────────────────────────────

    #[test]
    fn to_field_matches_snarkvm_and_preserves_small_values() {
        for value in [0u128, 1, 2, 3, 42, 258, 123456789] {
            let scalar = s(value);
            let field = to_field(&scalar).unwrap();
            assert_eq!(field, ToField::to_field(&scalar).unwrap());
            // Small values keep their numeric value.
            assert_eq!(field, Field::<CurrentNetwork>::from_u128(value));
        }
    }

    // ── strict vs lossy boolean ───────────────────────────────────────

    #[test]
    fn to_boolean_strict_accepts_only_zero_and_one() {
        assert!(!to_boolean(&s(0)).unwrap());
        assert!(to_boolean(&s(1)).unwrap());
        for bad in [s(2), s(3), s(255), negate(&Scalar::one())] {
            let err = to_boolean(&bad).unwrap_err().to_string();
            assert!(
                err.contains("scalar is not zero or one"),
                "unexpected error: {err}"
            );
        }
    }

    #[test]
    fn to_boolean_lossy_extracts_lsb_not_nonzero() {
        assert!(!to_boolean_lossy(&s(0)));
        assert!(to_boolean_lossy(&s(1)));
        assert!(!to_boolean_lossy(&s(2)));
        assert!(to_boolean_lossy(&s(3)));
        assert!(to_boolean_lossy(&s(255)));
        assert!(!to_boolean_lossy(&s(256)));

        // Equals the LSB of the field representation, and CastLossy<Boolean>
        // applied to that field — the upstream goes through the field too.
        let scalar = s(12345);
        let field = to_field(&scalar).unwrap();
        assert_eq!(to_boolean_lossy(&scalar), field.to_bits_le()[0]);
        let cast: Boolean<CurrentNetwork> = CastLossy::cast_lossy(&field);
        assert_eq!(to_boolean_lossy(&scalar), cast == Boolean::new(true));
        assert_eq!(
            to_boolean_lossy(&scalar),
            crate::field::to_boolean_lossy(&field)
        );
    }

    // ── strict vs lossy group / address ───────────────────────────────

    #[test]
    fn to_group_strict_fails_for_non_x_coordinate() {
        // 1scalar → 1field, which is NOT a valid x-coordinate.
        assert!(to_group(&s(1)).is_err());
        // 2scalar → 2field, which happens to be valid on BLS12-377.
        assert_eq!(to_group(&s(2)).unwrap(), to_group_lossy(&s(2)).unwrap());
        // 0scalar → zero group.
        assert_eq!(to_group(&s(0)).unwrap(), Group::<CurrentNetwork>::zero());
    }

    #[test]
    fn lossy_group_and_address_match_the_field_parity_helpers() {
        for value in [0u128, 1, 2, 3, 42, 258, 987654321] {
            let scalar = s(value);
            let field = to_field(&scalar).unwrap();
            assert_eq!(
                to_group_lossy(&scalar).unwrap(),
                crate::field::to_group_lossy(&field),
                "group mismatch for {value}"
            );
            assert_eq!(
                to_address_lossy(&scalar).unwrap(),
                crate::field::to_address_lossy(&field),
                "address mismatch for {value}"
            );
        }

        // 1scalar → 1field → generator (the documented Elligator-2 fallback).
        assert_eq!(
            to_group_lossy(&s(1)).unwrap(),
            Group::<CurrentNetwork>::generator()
        );
    }

    #[test]
    fn to_address_strict_inherits_group_strictness() {
        assert!(to_address(&s(1)).is_err());
        assert_eq!(
            to_address(&s(0)).unwrap(),
            Address::<CurrentNetwork>::zero()
        );
        let generator_addr = to_address_lossy(&s(1)).unwrap();
        assert_eq!(
            generator_addr.to_group(),
            &Group::<CurrentNetwork>::generator()
        );
        // Strict and lossy agree when the x-coordinate is valid.
        assert_eq!(to_address(&s(2)).unwrap(), to_address_lossy(&s(2)).unwrap());
    }

    // ── integer lossy casts ───────────────────────────────────────────

    #[test]
    fn integer_lossy_casts_truncate_low_bits() {
        let field = to_field(&s(258)).unwrap();
        let u8_val: U8<CurrentNetwork> = CastLossy::cast_lossy(&field);
        assert_eq!(u8_val, U8::new(2), "258 mod 256 = 2");
        let u16_val: U16<CurrentNetwork> = CastLossy::cast_lossy(&field);
        assert_eq!(u16_val, U16::new(258));
        let u32_val: U32<CurrentNetwork> = CastLossy::cast_lossy(&field);
        assert_eq!(u32_val, U32::new(258));
        let u64_val: U64<CurrentNetwork> = CastLossy::cast_lossy(&field);
        assert_eq!(u64_val, U64::new(258));
        let u128_val: U128<CurrentNetwork> = CastLossy::cast_lossy(&field);
        assert_eq!(u128_val, U128::new(258));

        let i8_val: I8<CurrentNetwork> = CastLossy::cast_lossy(&field);
        assert_eq!(i8_val, I8::new(2));
        let i16_val: I16<CurrentNetwork> = CastLossy::cast_lossy(&field);
        assert_eq!(i16_val, I16::new(258));
        let i32_val: I32<CurrentNetwork> = CastLossy::cast_lossy(&field);
        assert_eq!(i32_val, I32::new(258));
        let i64_val: I64<CurrentNetwork> = CastLossy::cast_lossy(&field);
        assert_eq!(i64_val, I64::new(258));
        let i128_val: I128<CurrentNetwork> = CastLossy::cast_lossy(&field);
        assert_eq!(i128_val, I128::new(258));

        // Signed truncation reinterprets the low bits as two's complement.
        let f255 = to_field(&s(255)).unwrap();
        let signed: I8<CurrentNetwork> = CastLossy::cast_lossy(&f255);
        assert_eq!(signed, I8::new(-1));

        // The upstream binding calls `IntegerNative::from_field_lossy(&field)`;
        // in snarkVM that is exactly what `CastLossy` on the field does.
        let via_from_field = U8::<CurrentNetwork>::from_field_lossy(&field);
        assert_eq!(u8_val, via_from_field);
    }

    // ── native method smoke tests (the "thin shell" ones) ─────────────

    #[test]
    fn native_string_byte_and_bit_round_trips() {
        let original = s(123456789);
        let text = original.to_string();
        assert!(text.ends_with("scalar"));
        assert_eq!(Scalar::<CurrentNetwork>::from_str(&text).unwrap(), original);
        assert_eq!(
            Scalar::<CurrentNetwork>::from_bytes_le(&original.to_bytes_le().unwrap()).unwrap(),
            original
        );
        assert_eq!(
            Scalar::<CurrentNetwork>::from_bits_le(&original.to_bits_le()).unwrap(),
            original
        );
    }

    #[test]
    fn native_arithmetic_uses_scalar_exponent() {
        let a = s(10);
        let b = s(3);
        assert_eq!(a + b, s(13));
        assert_eq!(a - b, s(7));
        assert_eq!(a * b, s(30));
        assert_eq!(a / b * b, a);
        assert_eq!(Double::double(&a), s(20));
        assert_eq!(Pow::pow(s(2), s(3)), s(8));
        assert_eq!(Scalar::<CurrentNetwork>::zero(), s(0));
        assert_eq!(Scalar::<CurrentNetwork>::one(), s(1));
        assert!(a != b);
        assert_eq!(a, s(10));
    }

    #[test]
    fn random_samples_and_needs_rng() {
        let rng = &mut TestRng::fixed(0);
        let a = random::<CurrentNetwork, _>(rng);
        let b = random::<CurrentNetwork, _>(rng);
        assert_ne!(a, b, "two samples should differ");
    }
}
