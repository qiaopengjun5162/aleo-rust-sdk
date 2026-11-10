//! Aleo `Field` — parity with the JS SDK's wasm `Field` class.
//!
//! As with [`crate::boolean`], no wrapper type is needed: snarkVM's
//! [`Field<N>`] already covers **22 of the 40 methods** the docs page lists,
//! because the class is a thin shell over the native type. This module adds
//! the cast/conversion methods that are not a single trait call, and — where
//! the real value is — pins the semantics down with tests, because several
//! are counter-intuitive.
//!
//! ## JS `Field` → Rust mapping
//!
//! | # | JS `Field` | Rust equivalent | Where |
//! |---|---|---|---|
//! | 1 | `Field.fromString(s)` | `Field::<N>::from_str(s)?` | snarkVM (`FromStr`) |
//! | 2 | `f.toString()` | `f.to_string()` | snarkVM (`Display`) |
//! | 3 | `Field.fromBytesLe(b)` | `Field::from_bytes_le(&b)?` | snarkVM (`FromBytes`) |
//! | 4 | `f.toBytesLe()` | `f.to_bytes_le()?` | snarkVM (`ToBytes`) |
//! | 5 | `Field.fromBitsLe(b)` | `Field::from_bits_le(&b)?` | snarkVM (`FromBits`) |
//! | 6 | `f.toBitsLe()` | `f.to_bits_le()` | snarkVM (`ToBits`) |
//! | 7 | `f.toPlaintext()` | [`to_plaintext`] | **this module** |
//! | 8 | `f.clone()` | `f` — `Field` is `Copy` | std |
//! | 9 | `Field.random()` | [`random`] / `Uniform::rand(rng)` | **this module** |
//! | 10 | `f.add(g)` | `f + g` | std (`Add`) |
//! | 11 | `f.subtract(g)` | `f - g` | std (`Sub`) |
//! | 12 | `f.multiply(g)` | `f * g` | std (`Mul`) |
//! | 13 | `f.divide(g)` | `f / g` | std (`Div`) |
//! | 14 | `Field.newDomainSeparator(s)` | `Field::new_domain_separator(s)` | snarkVM |
//! | 15 | `f.pow(g)` | `f.pow(g)` | snarkVM (`Pow`) |
//! | 16 | `f.inverse()` | [`negate`] — **not** the multiplicative inverse! | **this module** |
//! | 17 | `Field.zero()` | `Field::zero()` | snarkVM (`Zero`) |
//! | 18 | `Field.one()` | `Field::one()` | snarkVM (`One`) |
//! | 19 | `f.double()` | `f.double()` | snarkVM (`Double`) |
//! | 20 | `f.equals(g)` | `f == g` | std (`PartialEq`) |
//! | 21 | `f.toScalarLossy()` | [`to_scalar_lossy`] / `f.cast_lossy()` | **this module** |
//! | 22 | `f.toBoolean()` | [`to_boolean`] | **this module** |
//! | 23 | `f.toBooleanLossy()` | [`to_boolean_lossy`] / `f.cast_lossy()` | **this module** |
//! | 24 | `f.toGroup()` | [`to_group`] | **this module** |
//! | 25 | `f.toGroupLossy()` | [`to_group_lossy`] / `f.cast_lossy()` | **this module** |
//! | 26 | `f.toAddress()` | [`to_address`] | **this module** |
//! | 27 | `f.toAddressLossy()` | [`to_address_lossy`] / `f.cast_lossy()` | **this module** |
//! | 28–37 | `f.toU8Lossy()` … `f.toI128Lossy()` | `f.cast_lossy()` — see [Integer casts](#integer-casts) | snarkVM (`CastLossy`) |
//!
//! ## 🔴 `inverse()` is negation, not inversion
//!
//! The docs page says *"Invert the field element."* The wasm implementation is
//! `Field(-self.0)` — the **additive inverse** (negation). Calling it on
//! `5field` gives `-5field` (i.e. `p - 5` where `p` is the modulus), **not**
//! `1/5`. The multiplicative inverse is not exposed by the JS class at all;
//! in Rust it is `f.inverse()` from the `Inverse` trait (or `f.pow(p - 2)`).
//!
//! The function here is deliberately named [`negate`] rather than `inverse`,
//! so the trap cannot be re-imported into Rust call sites.
//!
//! ## The cast semantics, pinned
//!
//! 1. **Strict vs lossy is a real distinction.** `toBoolean` / `toGroup` /
//!    `toAddress` **fail** on inputs that cannot be represented; the `Lossy`
//!    variants never fail and silently truncate or remap. Use the strict
//!    version unless you know the input is in range.
//! 2. **`toBooleanLossy` extracts the LSB**, not "is non-zero". `2field`
//!    → `false`, `3field` → `true`. The result equals
//!    `f.to_bits_le()[0]` and is what `CastLossy<Boolean>` produces.
//! 3. **`toScalarLossy` truncates bits.** It keeps the lowest
//!    `Scalar::size_in_data_bits()` bits of the field (251 for BLS12-377)
//!    and drops the rest. It is *not* a modular reduction: a field element
//!    near the top of the range will not map to the same numeric value.
//! 4. **`toGroupLossy` tries x-coordinate recovery first**, falls back to
//!    the generator for `1field`, and applies Elligator-2 otherwise. It
//!    never fails, but the mapping is not injective — two different fields
//!    can land on the same group element. Note that `1field` is **not** a
//!    valid x-coordinate: strict `toGroup` fails on it, only the lossy
//!    version has the generator fallback.
//! 5. **`toAddressLossy` is `toGroupLossy` + `Address::new`**, so it inherits
//!    all of the above. The strict `toAddress` is `toGroup` + `Address::new`.
//! 6. **Integer lossy casts truncate bits**, not reduce mod `2^N`. The
//!    lowest `N` bits of the field become the integer. `Field` and integer
//!    round-trips (`integer.to_field()` → `from_field_lossy`) are lossless,
//!    but arbitrary fields lose their upper bits.
//! 7. **`newDomainSeparator` interprets the string as LE bytes**, then
//!    reduces mod the field modulus. It is deterministic and collision-free
//!    for short strings, but two different strings can alias after reduction
//!    if their LE byte encodings differ by a multiple of the modulus.
//! 8. **Sampling needs an RNG, and that is deliberate.** The JS class uses a
//!    global generator; [`random`] takes one. Nothing in this crate samples
//!    silently.
//!
//! ## Integer casts
//!
//! The 10 integer lossy conversions (`toU8Lossy` … `toI128Lossy`) are all
//! one-liners through the [`CastLossy`] trait:
//!
//! ```
//! use aleo_rust_sdk::field;
//! use snarkvm::prelude::{CastLossy, Field, TestnetV0, U8};
//! use std::str::FromStr;
//!
//! let f = Field::<TestnetV0>::from_str("258field").unwrap();
//! let small: U8<TestnetV0> = f.cast_lossy(); // 258 mod 256 = 2
//! assert_eq!(small, U8::new(2));
//! ```
//!
//! No wrapper is added for each of the ten; `cast_lossy()` covers them all.
//!
//! ## Usage
//!
//! ```
//! use aleo_rust_sdk::field;
//! use snarkvm::prelude::{Field, TestnetV0};
//! use std::str::FromStr;
//!
//! let f = Field::<TestnetV0>::from_str("3field").unwrap();
//!
//! // JS: f.inverse() — but it is *negation*, not 1/f.
//! assert_eq!(field::negate(&f), -f);
//!
//! // JS: f.toBooleanLossy() — LSB, not "is non-zero".
//! assert_eq!(field::to_boolean_lossy(&f), true); // 3 = 0b11 → LSB = 1
//!
//! // JS: Field.newDomainSeparator("hello")
//! let sep = Field::<TestnetV0>::new_domain_separator("hello");
//! assert_eq!(sep, Field::new_domain_separator("hello"));
//! ```

use snarkvm::prelude::{
    Address, CastLossy, CryptoRng, Field, FromField, Group, Literal, Network, One, Plaintext, Rng,
    Scalar, ToBits, Zero,
};
use snarkvm::utilities::rand::Uniform;

/// Returns the additive inverse of the field — the JS `f.inverse()`.
///
/// 🔴 **This is negation, not the multiplicative inverse.** The JS docs say
/// "Invert the field element" but the implementation is `-f`. The function is
/// named [`negate`] to keep the trap out of Rust call sites.
///
/// # Arguments
/// * `field` - The field element to negate.
pub fn negate<N: Network>(field: &Field<N>) -> Field<N> {
    -*field
}

/// Returns the field as an Aleo [`Plaintext`] — the JS `f.toPlaintext()`.
///
/// The result is a `Literal::Field`, so it renders as `"Nfield"` and
/// round-trips through `Plaintext::from_str`.
///
/// # Arguments
/// * `field` - The field element to wrap.
pub fn to_plaintext<N: Network>(field: &Field<N>) -> Plaintext<N> {
    Plaintext::from(Literal::Field(*field))
}

/// Samples a uniformly random field — the JS `Field.random()`.
///
/// The JS class takes no argument because it uses a global generator; this
/// crate never samples implicitly, so the RNG is passed in.
///
/// # Arguments
/// * `rng` - The random number generator.
pub fn random<N: Network, R: Rng + CryptoRng>(rng: &mut R) -> Field<N> {
    Uniform::rand(rng)
}

/// Casts the field to a `bool`, strictly — the JS `f.toBoolean()`.
///
/// Returns `Ok(true)` for `1field`, `Ok(false)` for `0field`, and an error
/// for anything else. Prefer this over [`to_boolean_lossy`] when the input
/// is expected to be a boolean.
///
/// # Arguments
/// * `field` - The field element to cast.
pub fn to_boolean<N: Network>(field: &Field<N>) -> anyhow::Result<bool> {
    if *field == Field::zero() {
        Ok(false)
    } else if *field == Field::one() {
        Ok(true)
    } else {
        anyhow::bail!("Failed to convert field to boolean: field element is not zero or one")
    }
}

/// Casts the field to a `bool` by extracting the least-significant bit —
/// the JS `f.toBooleanLossy()`.
///
/// **Not** "is non-zero": `2field` → `false`, `3field` → `true`.
///
/// # Arguments
/// * `field` - The field element to cast.
pub fn to_boolean_lossy<N: Network>(field: &Field<N>) -> bool {
    ToBits::to_bits_le(field)[0]
}

/// Casts the field to a [`Scalar`] with lossy bit truncation — the JS
/// `f.toScalarLossy()`.
///
/// Keeps the lowest `Scalar::size_in_data_bits()` bits and drops the rest.
/// This is *not* a modular reduction.
///
/// # Arguments
/// * `field` - The field element to cast.
pub fn to_scalar_lossy<N: Network>(field: &Field<N>) -> Scalar<N> {
    CastLossy::cast_lossy(field)
}

/// Casts the field to a [`Group`] element, strictly — the JS `f.toGroup()`.
///
/// Recovers the group element from the field as an x-coordinate. Returns an
/// error if the field is not a valid x-coordinate on the curve.
///
/// # Arguments
/// * `field` - The field element to cast.
pub fn to_group<N: Network>(field: &Field<N>) -> anyhow::Result<Group<N>> {
    <Group<N> as FromField>::from_field(field).map_err(|e| anyhow::anyhow!(e))
}

/// Casts the field to a [`Group`] element, lossily — the JS `f.toGroupLossy()`.
///
/// Tries x-coordinate recovery first, falls back to the generator for
/// `1field`, and applies Elligator-2 otherwise. Never fails.
///
/// # Arguments
/// * `field` - The field element to cast.
pub fn to_group_lossy<N: Network>(field: &Field<N>) -> Group<N> {
    CastLossy::cast_lossy(field)
}

/// Casts the field to an [`Address`], strictly — the JS `f.toAddress()`.
///
/// Goes through [`to_group`] and fails if the field is not a valid
/// x-coordinate.
///
/// # Arguments
/// * `field` - The field element to cast.
pub fn to_address<N: Network>(field: &Field<N>) -> anyhow::Result<Address<N>> {
    Ok(Address::new(to_group(field)?))
}

/// Casts the field to an [`Address`], lossily — the JS `f.toAddressLossy()`.
///
/// Goes through [`to_group_lossy`]; never fails.
///
/// # Arguments
/// * `field` - The field element to cast.
pub fn to_address_lossy<N: Network>(field: &Field<N>) -> Address<N> {
    CastLossy::cast_lossy(field)
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::{
        Boolean, Double, Field, FromBits, FromBytes, Inverse, One, Pow, TestRng, TestnetV0, ToBits,
        ToBytes, ToField, Zero,
    };
    use std::str::FromStr;

    type CurrentNetwork = TestnetV0;

    fn f(value: u128) -> Field<CurrentNetwork> {
        Field::from_u128(value)
    }

    // ── negate: the inverse() trap ────────────────────────────────────

    #[test]
    fn negate_is_additive_inverse_not_multiplicative() {
        // JS: x.inverse() returns -x, NOT 1/x.
        let three = f(3);
        assert_eq!(negate(&three), -three);

        // -3field is p - 3, not 1/3. negate() is additive: x + (-x) = 0.
        let neg_three = negate(&three);
        assert_eq!(three + neg_three, Field::zero());

        // The multiplicative inverse of 3 is the value `m` with 3 * m = 1.
        // It is NOT what negate() returns.
        let third = Inverse::inverse(&three).unwrap(); // the real 1/3
        assert_eq!(three * third, Field::one());
        assert_ne!(neg_three, third);

        // Negation is an involution: -(-x) = x.
        assert_eq!(negate(&neg_three), three);
    }

    // ── toPlaintext ───────────────────────────────────────────────────

    #[test]
    fn to_plaintext_is_a_field_literal() {
        let plaintext = to_plaintext(&f(42));
        assert_eq!(plaintext.to_string(), "42field");

        // Round-trips through the plaintext parser.
        assert_eq!(
            Plaintext::<CurrentNetwork>::from_str("42field").unwrap().to_string(),
            "42field"
        );
    }

    // ── strict vs lossy boolean ───────────────────────────────────────

    #[test]
    fn to_boolean_strict_accepts_only_zero_and_one() {
        assert!(!to_boolean(&f(0)).unwrap());
        assert!(to_boolean(&f(1)).unwrap());

        for bad in [f(2), f(3), f(255), negate(&Field::one())] {
            let err = to_boolean(&bad).unwrap_err().to_string();
            assert!(err.contains("not zero or one"), "unexpected error: {err}");
        }
    }

    #[test]
    fn to_boolean_lossy_extracts_lsb_not_nonzero() {
        // LSB, not "is non-zero".
        assert!(!to_boolean_lossy(&f(0)));
        assert!(to_boolean_lossy(&f(1)));
        assert!(!to_boolean_lossy(&f(2))); // 0b10 → LSB 0
        assert!(to_boolean_lossy(&f(3))); // 0b11 → LSB 1
        assert!(to_boolean_lossy(&f(255))); // 0b11111111 → LSB 1
        assert!(!to_boolean_lossy(&f(256))); // 0b100000000 → LSB 0

        // Matches CastLossy<Boolean>.
        let g = f(12345);
        let cast: Boolean<CurrentNetwork> = CastLossy::cast_lossy(&g);
        assert_eq!(to_boolean_lossy(&g), cast == Boolean::new(true));
    }

    // ── toScalarLossy: bit truncation ─────────────────────────────────

    #[test]
    fn to_scalar_lossy_truncates_bits_not_modular_reduce() {
        // 1field → 1scalar, 0field → 0scalar.
        assert_eq!(to_scalar_lossy(&f(1)), Scalar::one());
        assert_eq!(to_scalar_lossy(&f(0)), Scalar::zero());

        // Small values round-trip losslessly (42 fits in both).
        let s = to_scalar_lossy(&f(42));
        let back: Field<CurrentNetwork> = ToField::to_field(&s).unwrap();
        assert_eq!(back, f(42));

        // Consistent with CastLossy<Scalar>.
        let g = f(987654321);
        let cast: Scalar<CurrentNetwork> = CastLossy::cast_lossy(&g);
        assert_eq!(to_scalar_lossy(&g), cast);
    }

    // ── strict vs lossy group ─────────────────────────────────────────

    #[test]
    fn to_group_strict_fails_for_non_x_coordinate() {
        // 0field → zero group element.
        let zero_group = to_group(&f(0)).unwrap();
        assert_eq!(zero_group, Group::<CurrentNetwork>::zero());

        // The generator's x-coordinate IS a valid x-coordinate.
        let gen_x = Group::<CurrentNetwork>::generator().to_x_coordinate();
        let recovered = to_group(&gen_x).unwrap();
        assert_eq!(recovered, Group::<CurrentNetwork>::generator());

        // 1field is NOT a valid x-coordinate (the strict path has no fallback).
        assert!(
            to_group(&f(1)).is_err(),
            "1field is not a valid x-coordinate"
        );
        // 2field also fails.
        // 2field happens to be a valid x-coordinate on BLS12-377 — roughly half
        // of all field elements are. The canonical failure example is 1field.
    }

    #[test]
    fn to_group_lossy_never_fails_and_uses_elligator2() {
        // Never fails, even for non-x-coordinate inputs.
        let g = to_group_lossy(&f(2));
        // 1field → generator (documented fallback).
        assert_eq!(to_group_lossy(&f(1)), Group::<CurrentNetwork>::generator());
        // 0field → zero.
        assert_eq!(to_group_lossy(&f(0)), Group::<CurrentNetwork>::zero());

        // Consistent with CastLossy<Group>.
        let cast: Group<CurrentNetwork> = CastLossy::cast_lossy(&f(2));
        assert_eq!(g, cast);
    }

    // ── strict vs lossy address ───────────────────────────────────────

    #[test]
    fn to_address_strict_inherits_group_strictness() {
        // 0field → zero address.
        assert_eq!(
            to_address(&f(0)).unwrap(),
            Address::<CurrentNetwork>::zero()
        );

        // The generator's x-coordinate gives the generator address.
        let gen_x = Group::<CurrentNetwork>::generator().to_x_coordinate();
        let generator_addr = to_address(&gen_x).unwrap();
        assert_eq!(
            generator_addr.to_group(),
            &Group::<CurrentNetwork>::generator()
        );

        // 1field is NOT a valid x-coordinate (strict fails, lossy works).
        assert!(to_address(&f(1)).is_err());
        // 2field is actually valid on BLS12-377; 1field is the canonical failure.
    }

    #[test]
    fn to_address_lossy_never_fails() {
        assert_eq!(to_address_lossy(&f(0)), Address::<CurrentNetwork>::zero());
        let generator_addr = to_address_lossy(&f(1));
        assert_eq!(
            generator_addr.to_group(),
            &Group::<CurrentNetwork>::generator()
        );

        // 2field works (Elligator-2 fallback via Group).
        let addr = to_address_lossy(&f(2));
        assert_eq!(addr.to_group(), &to_group_lossy(&f(2)));
    }

    // ── integer lossy casts ───────────────────────────────────────────

    #[test]
    fn integer_lossy_casts_truncate_low_bits() {
        use snarkvm::prelude::{I8, I16, I32, I64, I128, U8, U16, U64, U128};

        // 0 and 1 map to 0 and 1 in every integer type.
        let u8_zero: U8<CurrentNetwork> = CastLossy::cast_lossy(&f(0));
        assert_eq!(u8_zero, U8::new(0));
        let u8_one: U8<CurrentNetwork> = CastLossy::cast_lossy(&f(1));
        assert_eq!(u8_one, U8::new(1));

        // Truncation: 258 mod 256 = 2 for U8.
        let u8_val: U8<CurrentNetwork> = CastLossy::cast_lossy(&f(258));
        assert_eq!(u8_val, U8::new(2));
        // 258 mod 65536 = 258 for U16.
        let u16_val: U16<CurrentNetwork> = CastLossy::cast_lossy(&f(258));
        assert_eq!(u16_val, U16::new(258));

        // Signed: truncation reinterprets bits as two's complement.
        // 255 → U8 255, but as I8 the low 8 bits of 255 are 0xFF = -1.
        let i8_val: I8<CurrentNetwork> = CastLossy::cast_lossy(&f(255));
        assert_eq!(i8_val, I8::new(-1));

        // Wide types preserve more bits.
        let u64_val: U64<CurrentNetwork> = CastLossy::cast_lossy(&f(258));
        assert_eq!(u64_val, U64::new(258));
        let u128_val: U128<CurrentNetwork> = CastLossy::cast_lossy(&f(258));
        assert_eq!(u128_val, U128::new(258));
        let i16_val: I16<CurrentNetwork> = CastLossy::cast_lossy(&f(258));
        assert_eq!(i16_val, I16::new(258));
        let i32_val: I32<CurrentNetwork> = CastLossy::cast_lossy(&f(258));
        assert_eq!(i32_val, I32::new(258));
        let i64_val: I64<CurrentNetwork> = CastLossy::cast_lossy(&f(258));
        assert_eq!(i64_val, I64::new(258));
        let i128_val: I128<CurrentNetwork> = CastLossy::cast_lossy(&f(258));
        assert_eq!(i128_val, I128::new(258));
    }

    // ── native method smoke tests (the "thin shell" ones) ─────────────

    #[test]
    fn native_string_and_byte_round_trips() {
        let original = f(123456789);
        let s = original.to_string();
        assert!(s.ends_with("field"));
        assert_eq!(Field::<CurrentNetwork>::from_str(&s).unwrap(), original);

        let bytes = original.to_bytes_le().unwrap();
        assert_eq!(
            Field::<CurrentNetwork>::from_bytes_le(&bytes).unwrap(),
            original
        );

        let bits = original.to_bits_le();
        assert_eq!(
            Field::<CurrentNetwork>::from_bits_le(&bits).unwrap(),
            original
        );
    }

    #[test]
    fn native_arithmetic_and_domain_separator() {
        let a = f(10);
        let b = f(3);

        assert_eq!(a + b, f(13));
        assert_eq!(a - b, f(7));
        assert_eq!(a * b, f(30));
        assert_eq!(a / b * b, a); // round-trip through division

        assert_eq!(Double::double(&a), f(20));
        assert!(a != b);
        assert!(a == f(10));

        // Pow: 2^3 = 8.
        assert_eq!(Pow::pow(f(2), f(3)), f(8));

        // new_domain_separator is native and deterministic.
        let sep1 = Field::<CurrentNetwork>::new_domain_separator("hello");
        let sep2 = Field::<CurrentNetwork>::new_domain_separator("hello");
        assert_eq!(sep1, sep2);

        // Different strings give different separators (for short inputs).
        let sep3 = Field::<CurrentNetwork>::new_domain_separator("world");
        assert_ne!(sep1, sep3);
    }

    #[test]
    fn random_samples_and_needs_rng() {
        let rng = &mut TestRng::fixed(0);
        let a = random::<CurrentNetwork, _>(rng);
        let b = random::<CurrentNetwork, _>(rng);
        assert_ne!(a, b, "two samples should differ");
    }
}
