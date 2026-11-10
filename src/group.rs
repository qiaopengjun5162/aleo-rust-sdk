//! Aleo `Group` — parity with the JS SDK's wasm `Group` class.
//!
//! As with [`crate::field`] and [`crate::boolean`], no wrapper type is needed:
//! snarkVM's [`Group<N>`] already covers **22 of the 35 methods** the docs
//! page lists, because the class is a thin shell over the native type. This
//! module adds the conversions that are not a single trait call — and, where
//! the semantics are surprising, pins them down with tests.
//!
//! ## JS `Group` → Rust mapping
//!
//! | # | JS `Group` | Rust equivalent | Where |
//! |---|------------|-----------------|-------|
//! | 1 | `Group.fromString(s)` | `Group::<N>::from_str(s)?` | snarkVM (`FromStr`) |
//! | 2 | `g.toString()` | `g.to_string()` | snarkVM (`Display`) |
//! | 3 | `Group.fromBytesLe(b)` | `Group::from_bytes_le(&b)?` | snarkVM (`FromBytes`) |
//! | 4 | `g.toBytesLe()` | `g.to_bytes_le()?` | snarkVM (`ToBytes`) |
//! | 5 | `Group.fromBitsLe(b)` | `Group::from_bits_le(&b)?` | snarkVM (`FromBits`) |
//! | 6 | `g.toBitsLe()` | `g.to_bits_le()` | snarkVM (`ToBits`) |
//! | 7 | `g.toFields()` | `g.to_fields()?` — **one** field, the x-coordinate | snarkVM (`ToFields`) |
//! | 8 | `g.toXCoordinate()` | `g.to_x_coordinate()` | snarkVM |
//! | 9 | `g.toField()` | `g.to_x_coordinate()` — alias of `toXCoordinate` | snarkVM |
//! | 10 | `Group.fromField(f)` | `Group::from_field(&f)?` | snarkVM (`FromField`) |
//! | 11 | `Group.fromFieldString(s)` | [`from_field_string`] | **this module** |
//! | 12 | `g.toPlaintext()` | [`to_plaintext`] | **this module** |
//! | 13 | `g.clone()` | `g` — `Group` is `Copy` | std |
//! | 14 | `Group.random()` | [`random`] / `Uniform::rand(rng)` | **this module** |
//! | 15 | `g.add(h)` | `g + h` | std (`Add`) |
//! | 16 | `g.subtract(h)` | `g - h` | std (`Sub`) |
//! | 17 | `g.scalarMultiply(s)` | `g * s` | std (`Mul<Scalar>`) |
//! | 18 | `g.double()` | `g.double()` | snarkVM (`Double`) |
//! | 19 | `g.inverse()` | `-g` — the group inverse, see below | std (`Neg`) |
//! | 20 | `g.equals(h)` | `g == h` | std (`PartialEq`) |
//! | 21 | `Group.zero()` | `Group::zero()` | snarkVM (`Zero`) |
//! | 22 | `Group.generator()` | `Group::generator()` | snarkVM |
//! | 23 | `g.toBooleanLossy()` | [`to_boolean_lossy`] | **this module** |
//! | 24 | `g.toScalarLossy()` | [`to_scalar_lossy`] | **this module** |
//! | 25 | `g.toAddress()` | [`to_address`] — **lossless** | **this module** |
//! | 26–35 | `g.toU8Lossy()` … `g.toI128Lossy()` | `g.to_x_coordinate().cast_lossy()` — see [Integer casts](#integer-casts) | snarkVM (`CastLossy`) |
//!
//! ## The semantics, pinned
//!
//! 1. 🔴 **Every `*Lossy` cast goes through the x-coordinate.** `Group` has
//!    no direct `CastLossy`: the wasm class implements each `to*Lossy` as
//!    `from_field_lossy(&self.0.to_x_coordinate())`. So `toU8Lossy` truncates
//!    the lowest 8 bits **of the x-coordinate** — not of the scalar
//!    multiplier, not of `toBytesLe`. [`to_boolean_lossy`] is the LSB of the
//!    x-coordinate, and [`to_scalar_lossy`] is the x-coordinate truncated to
//!    `Scalar::size_in_data_bits()` bits (not a modular reduction — same as
//!    [`crate::field::to_scalar_lossy`]).
//! 2. **`inverse()` is *not* the [`crate::field`] trap — but the geometry
//!    note is wrong.** For `Field`, JS `inverse()` is negation masquerading
//!    under a name that suggests `1/x`. For `Group`, `inverse()` is the
//!    honest group inverse — Rust's `-g` (`Neg`). However the docs describe
//!    it as *"the reflection of the point about the axis of symmetry i.e.
//!    (x,y) -> (x, -y)"*, which is **not** how BLS12-377's twisted Edwards
//!    model negates: it is `(x, y) -> (-x, y)`, so the **x-coordinate flips
//!    sign**. `-g` renders as `"{p - x}group"`, and
//!    `toXCoordinate(g.inverse()) == -toXCoordinate(g)`.
//! 3. **`fromField` is strict x-coordinate recovery.** Whether a field is a
//!    valid x-coordinate is decided by the curve — e.g. among `1..40field`
//!    only `2, 18, 26, 30, 33, 34, 36` work; `1field` is the canonical
//!    failure. [`from_field_string`] inherits the same strictness — it is
//!    `fromField` with a stringly-typed front door.
//! 4. **`toFields()` is exactly one field: the x-coordinate.** It is not the
//!    `Value::to_fields()` encoding from the record world, and nothing about
//!    the y-coordinate survives (it is recoverable, up to sign).
//! 5. **`toAddress()` is lossless** — `Address` wraps a `Group` — so unlike
//!    [`crate::field::to_address`] there is no strict/lossy split.
//!
//! ## Integer casts
//!
//! The ten integer casts all follow the same two-step path: take the
//! x-coordinate, then truncate its low bits:
//!
//! ```
//! use aleo_rust_sdk::group;
//! use snarkvm::prelude::{CastLossy, Group, TestnetV0, U8, Zero};
//!
//! let zero = Group::<TestnetV0>::zero();
//! // JS: zero.toU8Lossy() — U8 built from the x-coordinate (0), not the group bytes.
//! let u8_zero: U8<TestnetV0> = CastLossy::cast_lossy(&zero.to_x_coordinate());
//! assert_eq!(u8_zero, U8::new(0));
//! # let _ = group::to_address(&zero);
//! ```
//!
//! No wrapper is added for each of the ten; `g.to_x_coordinate().cast_lossy()`
//! covers them all.
//!
//! ## Usage
//!
//! ```
//! use aleo_rust_sdk::group;
//! use snarkvm::prelude::{Group, TestnetV0, ToBits};
//!
//! let g = Group::<TestnetV0>::generator();
//!
//! // JS: g.toBooleanLossy() — LSB of the x-coordinate.
//! let expected = ToBits::to_bits_le(&g.to_x_coordinate())[0];
//! assert_eq!(group::to_boolean_lossy(&g), expected);
//!
//! // JS: g.toAddress() — lossless; the Address just wraps the Group.
//! assert_eq!(group::to_address(&g).to_group(), &g);
//! ```

use snarkvm::prelude::{
    Address, CastLossy, CryptoRng, Field, FromField, Group, Literal, Network, Plaintext, Rng,
    Scalar, ToBits,
};
use snarkvm::utilities::rand::Uniform;
use std::str::FromStr;

/// Returns the group as an Aleo [`Plaintext`] — the JS `g.toPlaintext()`.
///
/// The result is a `Literal::Group`, so it renders as `"{x}group"` and
/// round-trips through `Plaintext::from_str`.
///
/// # Arguments
/// * `group` - The group element to wrap.
pub fn to_plaintext<N: Network>(group: &Group<N>) -> Plaintext<N> {
    Plaintext::from(Literal::Group(*group))
}

/// Samples a uniformly random group element — the JS `Group.random()`.
///
/// The JS class takes no argument because it uses a global generator; this
/// crate never samples implicitly, so the RNG is passed in.
///
/// # Arguments
/// * `rng` - The random number generator.
pub fn random<N: Network, R: Rng + CryptoRng>(rng: &mut R) -> Group<N> {
    Uniform::rand(rng)
}

/// Recovers the group element from a stringly-typed x-coordinate — the JS
/// `Group.fromFieldString(field)`.
///
/// Parses the string as a [`Field`] first, then performs the **strict**
/// x-coordinate recovery of `Group::from_field`. Errors if the string is not
/// a field literal, or if the field is not a valid x-coordinate (about half
/// of all field elements are not — `1field` is the canonical failure).
///
/// # Arguments
/// * `field` - The x-coordinate, as a field string (e.g. `"2field"`).
pub fn from_field_string<N: Network>(field: &str) -> anyhow::Result<Group<N>> {
    let x = Field::<N>::from_str(field)
        .map_err(|e| anyhow::anyhow!("failed to parse field '{field}': {e}"))?;
    <Group<N> as FromField>::from_field(&x)
        .map_err(|e| anyhow::anyhow!("failed to recover group from field: {e}"))
}

/// Casts the group to a `bool` by extracting the least-significant bit of the
/// **x-coordinate** — the JS `g.toBooleanLossy()`.
///
/// **Not** "is non-zero", and **not** anything about the scalar multiplier:
/// the answer is `to_bits_le(g.to_x_coordinate())[0]`.
///
/// # Arguments
/// * `group` - The group element to cast.
pub fn to_boolean_lossy<N: Network>(group: &Group<N>) -> bool {
    ToBits::to_bits_le(&group.to_x_coordinate())[0]
}

/// Casts the group to a [`Scalar`] with lossy bit truncation of the
/// **x-coordinate** — the JS `g.toScalarLossy()`.
///
/// Keeps the lowest `Scalar::size_in_data_bits()` bits of the x-coordinate
/// and drops the rest. This is *not* a modular reduction, and *not* the
/// discrete-log scalar that produced the point.
///
/// # Arguments
/// * `group` - The group element to cast.
pub fn to_scalar_lossy<N: Network>(group: &Group<N>) -> Scalar<N> {
    CastLossy::cast_lossy(&group.to_x_coordinate())
}

/// Casts the group to an [`Address`] — the JS `g.toAddress()`.
///
/// **Lossless**: `Address` wraps a `Group`, so the result round-trips through
/// [`Address::to_group`] exactly. (Unlike [`crate::field::to_address`] there
/// is no strict/lossy split to choose between.)
///
/// # Arguments
/// * `group` - The group element to wrap.
pub fn to_address<N: Network>(group: &Group<N>) -> Address<N> {
    Address::new(*group)
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::{
        Double, Field, FromBits, FromBytes, One, TestRng, TestnetV0, ToBytes, ToFields, Zero,
    };

    type CurrentNetwork = TestnetV0;

    fn f(value: u128) -> Field<CurrentNetwork> {
        Field::from_u128(value)
    }

    /// `from_field(f(value))` — `Some` only when `value` is a valid x-coordinate.
    fn g_from_x(value: u128) -> Option<Group<CurrentNetwork>> {
        <Group<CurrentNetwork> as FromField>::from_field(&f(value)).ok()
    }

    /// The first valid x-coordinate in `candidates`, with its group element.
    fn first_valid_x(candidates: &[u128]) -> (u128, Group<CurrentNetwork>) {
        for &x in candidates {
            if let Some(g) = g_from_x(x) {
                return (x, g);
            }
        }
        panic!("none of {candidates:?} is a valid x-coordinate");
    }

    // ── inverse(): the honest group inverse (NOT the Field trap) ──────

    #[test]
    fn inverse_is_the_group_negation_with_flipped_x() {
        // JS: g.inverse() is the group inverse — Rust's `-g`.
        // Unlike field::negate's `inverse()` trap, here the name is correct.
        let g = Group::<CurrentNetwork>::generator();
        let reflected = -g;

        // 🔴 The docs say "(x,y) -> (x, -y)", but BLS12-377 is twisted
        // Edwards: negation is (x, y) -> (-x, y) — the x-coordinate flips.
        assert_eq!(reflected.to_x_coordinate(), -g.to_x_coordinate());
        assert_ne!(reflected.to_x_coordinate(), g.to_x_coordinate());
        // It really is the group inverse: g + (-g) = zero.
        assert_eq!(g + reflected, Group::<CurrentNetwork>::zero());
        assert_eq!(g - g, Group::<CurrentNetwork>::zero());

        // Negation is an involution: -(-g) = g.
        assert_eq!(-(-g), g);

        // It is NOT the scalar inverse or anything multiplicative:
        // doubling is g + g, and 2g is not zero for the generator.
        assert_eq!(Double::double(&g), g + g);
        assert_ne!(g.double(), Group::<CurrentNetwork>::zero());
    }

    // ── toPlaintext ───────────────────────────────────────────────────

    #[test]
    fn to_plaintext_is_a_group_literal() {
        let g = Group::<CurrentNetwork>::generator();
        let plaintext = to_plaintext(&g);

        // Renders as the group literal itself (e.g. "...group").
        assert_eq!(plaintext.to_string(), g.to_string());
        assert!(plaintext.to_string().ends_with("group"));

        // Round-trips through the plaintext parser.
        assert_eq!(
            Plaintext::<CurrentNetwork>::from_str(&g.to_string()).unwrap(),
            plaintext
        );
    }

    // ── fromFieldString: strict x-coordinate recovery ─────────────────

    #[test]
    fn from_field_string_strictly_recovers_x_coordinate() {
        // The generator's x-coordinate round-trips to the generator.
        let gen_x = Group::<CurrentNetwork>::generator().to_x_coordinate();
        assert_eq!(
            from_field_string::<CurrentNetwork>(&gen_x.to_string()).unwrap(),
            Group::<CurrentNetwork>::generator()
        );

        // 2field IS a valid x-coordinate on BLS12-377 — round-trips.
        let g2 = from_field_string::<CurrentNetwork>("2field").unwrap();
        assert_eq!(g2.to_x_coordinate(), f(2));

        // 1field is NOT a valid x-coordinate — strict recovery fails.
        let err = from_field_string::<CurrentNetwork>("1field").unwrap_err().to_string();
        assert!(
            err.contains("failed to recover group"),
            "unexpected error: {err}"
        );

        // Not a field at all — parse error.
        let err = from_field_string::<CurrentNetwork>("not a field").unwrap_err().to_string();
        assert!(
            err.contains("failed to parse field"),
            "unexpected error: {err}"
        );
    }

    // ── toBooleanLossy: LSB of the x-coordinate ───────────────────────

    #[test]
    fn to_boolean_lossy_is_lsb_of_x_coordinate() {
        // Zero: x = 0 → LSB 0.
        assert!(!to_boolean_lossy(&Group::<CurrentNetwork>::zero()));

        // x = 2 = 0b10 → LSB 0 (a literal pin: NOT "is non-zero").
        let g2 = g_from_x(2).expect("2field is a valid x-coordinate on BLS12-377");
        assert!(!to_boolean_lossy(&g2));

        // x = 33 = 0b100001 → LSB 1 (33field is a valid x-coordinate).
        let g33 = g_from_x(33).expect("33field is a valid x-coordinate on BLS12-377");
        assert!(to_boolean_lossy(&g33));

        // Consistency with the definition for an arbitrary point.
        let g = Group::<CurrentNetwork>::generator();
        assert_eq!(
            to_boolean_lossy(&g),
            ToBits::to_bits_le(&g.to_x_coordinate())[0]
        );
    }

    // ── toScalarLossy: bit truncation of the x-coordinate ─────────────

    #[test]
    fn to_scalar_lossy_truncates_x_coordinate_bits() {
        // x = 2 → 2scalar (lossless for small values).
        let g2 = g_from_x(2).expect("2field is a valid x-coordinate on BLS12-377");
        let two_scalar = Scalar::<CurrentNetwork>::one() + Scalar::one();
        assert_eq!(to_scalar_lossy(&g2), two_scalar);
        assert_eq!(
            to_scalar_lossy(&Group::<CurrentNetwork>::zero()),
            Scalar::zero()
        );

        // Truncation of the x-coordinate, not a modular reduction — matches
        // field::to_scalar_lossy applied to the x-coordinate.
        let g = Group::<CurrentNetwork>::generator();
        let via_x: Scalar<CurrentNetwork> = CastLossy::cast_lossy(&g.to_x_coordinate());
        assert_eq!(to_scalar_lossy(&g), via_x);
    }

    // ── toAddress: lossless wrap ──────────────────────────────────────

    #[test]
    fn to_address_is_lossless_group_wrap() {
        let g = Group::<CurrentNetwork>::generator();
        assert_eq!(to_address(&g).to_group(), &g);
        assert_eq!(
            to_address(&Group::<CurrentNetwork>::zero()),
            Address::<CurrentNetwork>::zero()
        );

        // No strict/lossy split — it never fails.
        let g2 = g_from_x(2).expect("2field is a valid x-coordinate on BLS12-377");
        assert_eq!(to_address(&g2).to_group(), &g2);
    }

    // ── integer lossy casts: through the x-coordinate ─────────────────

    #[test]
    fn integer_lossy_casts_truncate_x_coordinate_bits() {
        use snarkvm::prelude::{I8, U8, U16};

        // x = 2 → 2 in every integer type.
        let g2 = g_from_x(2).expect("2field is a valid x-coordinate on BLS12-377");
        let u8_two: U8<CurrentNetwork> = CastLossy::cast_lossy(&g2.to_x_coordinate());
        assert_eq!(u8_two, U8::new(2));
        let u16_two: U16<CurrentNetwork> = CastLossy::cast_lossy(&g2.to_x_coordinate());
        assert_eq!(u16_two, U16::new(2));

        // Truncation pin: an x-coordinate ≡ 2 (mod 256) that overflows U8.
        // 258 = 2 + 256 → U8 2. Find the first valid x among the candidates.
        let (x, g) = first_valid_x(&[258, 514, 770, 1026, 1282, 1538, 1794, 2050]);
        assert_eq!(x % 256, 2);
        let u8_truncated: U8<CurrentNetwork> = CastLossy::cast_lossy(&g.to_x_coordinate());
        assert_eq!(u8_truncated, U8::new(2), "low 8 bits of x = {x}");

        // Signed reinterpretation of those bits: 2 → I8 2.
        let i8_two: I8<CurrentNetwork> = CastLossy::cast_lossy(&g.to_x_coordinate());
        assert_eq!(i8_two, I8::new(2));
    }

    // ── toFields is the x-coordinate ──────────────────────────────────

    #[test]
    fn to_fields_is_the_x_coordinate() {
        let g = Group::<CurrentNetwork>::generator();
        let fields = g.to_fields().unwrap();
        assert_eq!(fields, vec![g.to_x_coordinate()]);

        // Literal pin: the 2group element encodes as [2field].
        let g2 = g_from_x(2).expect("2field is a valid x-coordinate on BLS12-377");
        assert_eq!(g2.to_fields().unwrap(), vec![f(2)]);

        // Negation flips the x-coordinate (twisted Edwards), so toFields
        // flips with it — the y-coordinate never appears.
        assert_eq!((-g).to_fields().unwrap(), vec![-g.to_x_coordinate()]);
    }

    // ── native method smoke tests (the "thin shell" ones) ─────────────

    #[test]
    fn native_string_bytes_and_bits_round_trips() {
        let original = g_from_x(2).expect("2field is a valid x-coordinate on BLS12-377");
        let s = original.to_string();
        assert!(s.ends_with("group"));
        assert_eq!(Group::<CurrentNetwork>::from_str(&s).unwrap(), original);

        let bytes = original.to_bytes_le().unwrap();
        assert_eq!(
            Group::<CurrentNetwork>::from_bytes_le(&bytes).unwrap(),
            original
        );

        let bits = original.to_bits_le();
        assert_eq!(
            Group::<CurrentNetwork>::from_bits_le(&bits).unwrap(),
            original
        );
    }

    #[test]
    fn native_arithmetic_scalar_and_generator() {
        let g = Group::<CurrentNetwork>::generator();
        let h = g.double();

        // add / subtract.
        assert_eq!(g + g, h);
        assert_eq!(h - g, g);

        // scalarMultiply: g * 1 = g, g * 0 = zero, g * 2 = g.double().
        assert_eq!(g * Scalar::one(), g);
        assert_eq!(g * Scalar::zero(), Group::<CurrentNetwork>::zero());
        assert_eq!(g * (Scalar::one() + Scalar::one()), h);

        // equals / zero / generator.
        assert!(g == Group::<CurrentNetwork>::generator());
        assert!(g != Group::<CurrentNetwork>::zero());
        assert_eq!(Group::<CurrentNetwork>::zero() + g, g);
    }

    #[test]
    fn random_samples_and_needs_rng() {
        let rng = &mut TestRng::fixed(0);
        let a = random::<CurrentNetwork, _>(rng);
        let b = random::<CurrentNetwork, _>(rng);
        assert_ne!(a, b, "two samples should differ");
    }

    #[test]
    #[should_panic(expected = "is a valid x-coordinate")]
    fn first_valid_x_panics_when_no_candidate_is_valid() {
        // 1field is the canonical non-x-coordinate.
        first_valid_x(&[1]);
    }
}
