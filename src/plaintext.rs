//! Aleo `Plaintext` — parity with the JS SDK's wasm `Plaintext` class.
//!
//! snarkVM's [`Plaintext<N>`] covers **14 of the 18 methods** the docs page
//! lists natively. This module adds 4 helpers and pins the surprising
//! semantics with tests — several are counter-intuitive or outright wrong in
//! the docs.
//!
//! ## JS `Plaintext` → Rust mapping
//!
//! | # | JS `Plaintext` | Rust equivalent | Where |
//! |---|---|---|---|
//! | 1 | `p.find(name)` | `p.find(&[Identifier::from_str(name)?])` | snarkVM |
//! | 2 | `p.encrypt(addr, randomizer)` | `p.encrypt(addr, randomizer)` | snarkVM |
//! | 3 | `p.encryptSymmetric(tvk)` | `p.encrypt_symmetric(tvk)` | snarkVM |
//! | 4 | `Plaintext.fromString(s)` | `Plaintext::from_str(s)?` | snarkVM (`FromStr`) |
//! | 5 | `Plaintext.fromBytesLe(b)` | `Plaintext::from_bytes_le(&b)?` | snarkVM (`FromBytes`) |
//! | 6 | `p.toBytesLe()` | `p.to_bytes_le()?` | snarkVM (`ToBytes`) |
//! | 7 | `Plaintext.fromBitsLe(b)` | `Plaintext::from_bits_le(&b)?` | snarkVM (`FromBits`) |
//! | 8 | `p.toBitsLe()` | `p.to_bits_le()` | snarkVM (`ToBits`) |
//! | 9 | `Plaintext.fromFields(f)` | `Plaintext::from_fields(&f)?` | snarkVM (`FromFields`) |
//! | 10 | `p.toFields()` | `p.to_fields()?` | snarkVM (`ToFields`) |
//! | 11 | `p.toString()` | `p.to_string()` | snarkVM (`Display`) |
//! | 12 | `p.plaintextType()` | [`plaintext_type`] | **this module** |
//! | 13 | `p.toObject()` | [`to_json_value`] | **this module** |
//! | 14 | `p.toBytesRawLe()` | [`to_bytes_raw_le`] | **this module** |
//! | 15 | `p.toBytesRawBe()` | [`to_bytes_raw_be`] | **this module** |
//! | 16 | `p.toBitsRawLe()` | `p.to_bits_raw_le()` | snarkVM (`ToBitsRaw`) |
//! | 17 | `p.toBitsRawBe()` | `p.to_bits_raw_be()` | snarkVM (`ToBitsRaw`) |
//! | 18 | `p.toFieldsRaw()` | `p.to_fields_raw()?` | snarkVM (`ToFieldsRaw`) |
//!
//! ## 🔴 `toBitsLe` vs `toBitsRawLe` — variant bits
//!
//! `to_bits_le` includes **variant + identifier prefix bits** (the plaintext
//! type encoding needed for ciphertext derivation). `to_bits_raw_le` strips
//! them and returns **only the value bits**. For a `2u8` literal:
//!
//! - `to_bits_le()` → 38+ bits (prefix + variant + size + value)
//! - `to_bits_raw_le()` → exactly 8 bits `[0,1,0,0,0,0,0,0]`
//!
//! Never mix the two: `to_fields` additionally encodes the variant/identifier
//! prefix **and appends a terminus bit**, so for a small literal both produce
//! a single field — the **same length but a different value**.
//!
//! ## 🔴 `plaintextType()` returns "struct"/"array", not the struct name
//!
//! For a literal it returns the literal type name (`"u8"`, `"field"`,
//! `"boolean"` — note `"boolean"` not `"bool"`). For a struct it returns
//! `"struct"` — **not** the struct's declared name. For an array: `"array"`.
//!
//! ## 🔴 `toBytesRawBe` reverses the byte vector
//!
//! The upstream implementation packs BE bits into bytes then **reverses the
//! entire byte array**. For a struct `{a: 2u8, b: 3u8}`:
//!
//! - `to_bytes_raw_le()` → `[2, 3]` (member order preserved)
//! - `to_bytes_raw_be()` → `[3, 2]` (member order **reversed**)
//!
//! For a single-byte value the reverse is a no-op. For multi-byte values the
//! BE version returns the **LE byte order** — the name is misleading.
//!
//! ## `toObject()` → [`to_json_value`]
//!
//! JS `toObject()` returns a JS object. The Rust analogue returns
//! [`serde_json::Value`]:
//!
//! | Plaintext type | JSON type |
//! |---|---|
//! | `Boolean` | `Value::Bool` |
//! | `I8`…`I64`, `U8`…`U64` | `Value::Number` (exact) |
//! | `I128`, `U128` | `Value::String` (serde_json lacks 128-bit numbers) |
//! | `Address`, `Field`, `Group`, `Scalar`, `Signature`, `String`, `Identifier` | `Value::String` |
//! | `Struct` | `Value::Object` (keyed by member names) |
//! | `Array` | `Value::Array` |
//!
//! **JS divergence**: in JS all integers become `Number` (f64), so `u64`
//! values above 2^53 lose precision. Rust preserves exact values via
//! `serde_json::Number` (i64/u64) or `Value::String` (128-bit).
//!
//! ## `find` errors, not null
//!
//! The docs say *"Returns null if the plaintext is not a struct or the member
//! does not exist"* — but the source **errors** in both cases. The wasm
//! `Result<Plaintext, String>` is thrown as a JS exception, not returned as
//! `null`. Rust inherits the error semantics from snarkVM's `find`.
//!
//! ## Usage
//!
//! ```
//! use aleo_rust_sdk::plaintext;
//! use snarkvm::prelude::{Plaintext, TestnetV0};
//! use std::str::FromStr;
//!
//! let p = Plaintext::<TestnetV0>::from_str("2u8").unwrap();
//!
//! // JS: p.plaintextType() → "u8"
//! assert_eq!(plaintext::plaintext_type(&p), "u8");
//!
//! // JS: p.toObject() → 2 (JS number)
//! // Rust: Value::Number(2) (exact)
//! assert_eq!(plaintext::to_json_value(&p), serde_json::json!(2));
//! ```

use serde_json::{Number, Value};
use snarkvm::prelude::{FromBits, Literal, Network, Plaintext, ToBitsRaw, U8};

/// Returns the plaintext type name — the JS `p.plaintextType()`.
///
/// 🔴 For a struct this returns `"struct"`, **not** the struct's declared
/// name. For an array: `"array"`. For a literal: the literal type name
/// (`"u8"`, `"field"`, `"boolean"` — note `"boolean"` not `"bool"`).
///
/// # Arguments
/// * `plaintext` - The plaintext to inspect.
pub fn plaintext_type<N: Network>(plaintext: &Plaintext<N>) -> String {
    match plaintext {
        Plaintext::Literal(literal, _) => literal.to_type().type_name().to_string(),
        Plaintext::Struct(..) => "struct".to_string(),
        Plaintext::Array(..) => "array".to_string(),
    }
}

/// Converts a plaintext to a [`serde_json::Value`] — the Rust analogue of JS `p.toObject()`.
///
/// See the module docs for the type mapping table. Note the JS divergence:
/// JS uses f64 for all integers (precision loss above 2^53); Rust preserves
/// exact values via `serde_json::Number` (i64/u64) or `Value::String` (128-bit).
///
/// # Arguments
/// * `plaintext` - The plaintext to convert.
pub fn to_json_value<N: Network>(plaintext: &Plaintext<N>) -> Value {
    match plaintext {
        Plaintext::Literal(literal, _) => literal_to_json(literal),
        Plaintext::Struct(members, _) => {
            let mut map = serde_json::Map::new();
            for (key, value) in members {
                map.insert(key.to_string(), to_json_value(value));
            }
            Value::Object(map)
        }
        Plaintext::Array(elements, _) => Value::Array(elements.iter().map(to_json_value).collect()),
    }
}

fn literal_to_json<N: Network>(literal: &Literal<N>) -> Value {
    match literal {
        Literal::Boolean(b) => Value::Bool(**b),
        Literal::I8(v) => Value::Number(Number::from(**v as i64)),
        Literal::I16(v) => Value::Number(Number::from(**v as i64)),
        Literal::I32(v) => Value::Number(Number::from(**v as i64)),
        Literal::I64(v) => Value::Number(Number::from(**v)),
        Literal::U8(v) => Value::Number(Number::from(**v as u64)),
        Literal::U16(v) => Value::Number(Number::from(**v as u64)),
        Literal::U32(v) => Value::Number(Number::from(**v as u64)),
        Literal::U64(v) => Value::Number(Number::from(**v)),
        // serde_json::Number lacks 128-bit support; JS loses precision to f64.
        // Deref to the primitive: `v.to_string()` would carry the type suffix
        // ("100u128"), while JS `toObject()` yields the bare value.
        Literal::I128(v) => Value::String((**v).to_string()),
        Literal::U128(v) => Value::String((**v).to_string()),
        // Address, Field, Group, Scalar, Signature, String, Identifier → string.
        _ => Value::String(literal.to_string()),
    }
}

/// Packs raw LE bits into bytes — the JS `p.toBytesRawLe()`.
///
/// 🔴 A trailing short chunk is **zero-padded**, not rejected:
/// `U8::from_bits_le` accepts fewer than 8 bits, so a `Boolean` (1 raw bit)
/// yields `[1]` (or `[0]`), never an error. The `Result` is kept only to
/// mirror the upstream wasm signature.
///
/// # Arguments
/// * `plaintext` - The plaintext to encode.
pub fn to_bytes_raw_le<N: Network>(plaintext: &Plaintext<N>) -> anyhow::Result<Vec<u8>> {
    // `from_bits_le` cannot fail for a chunk of at most 8 bits, so there is no
    // real error path — dereferencing the `U8` to its `u8` avoids both the
    // upstream `collect::<Result<_>>()?` and the `to_bytes_le().unwrap()`.
    let bytes = plaintext
        .to_bits_raw_le()
        .chunks(8)
        .map(|chunk| *U8::<N>::from_bits_le(chunk).expect("at most 8 bits fit in a U8"))
        .collect();
    Ok(bytes)
}

/// Packs raw BE bits into bytes, then **reverses the byte vector** — the JS `p.toBytesRawBe()`.
///
/// 🔴 The upstream implementation reverses the entire byte array at the end.
/// For a struct `{a: 2u8, b: 3u8}` this returns `[3, 2]` (member order
/// reversed) while [`to_bytes_raw_le`] returns `[2, 3]`. For a single-byte
/// value the reverse is a no-op. The name "BE" is misleading — the result is
/// effectively LE byte order for multi-byte values.
///
/// # Arguments
/// * `plaintext` - The plaintext to encode.
pub fn to_bytes_raw_be<N: Network>(plaintext: &Plaintext<N>) -> anyhow::Result<Vec<u8>> {
    let mut bytes: Vec<u8> = plaintext
        .to_bits_raw_be()
        .chunks(8)
        .map(|chunk| *U8::<N>::from_bits_be(chunk).expect("at most 8 bits fit in a U8"))
        .collect();
    bytes.reverse();
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    use snarkvm::prelude::{
        Address, FromStr, Group, Identifier, Network, Plaintext, PrivateKey, Scalar, TestnetV0,
        ToBits, ToFields, ToFieldsRaw, Uniform, ViewKey,
    };
    use snarkvm::utilities::rand::TestRng;

    type CurrentNetwork = TestnetV0;

    /// Exact upstream test vector (`wasm/src/programs/data/plaintext.rs`).
    const STRUCT: &str = "{\n  microcredits: 100000000u64,\n  height: 1653124u32\n}";
    const NESTED_STRUCT: &str = "{ player: aleo13nnjqa7h2u4mpl95guz97nhzkhlde750zsjnw59tkgdwc85lyurs295lxc, health: 100u8, inventory: { coins: 5u32, snacks: { candies: 5u64, vegetals: 6u64 } }, secret: 2group, cipher: 2scalar, is_alive: true }";

    fn p(s: &str) -> Plaintext<CurrentNetwork> {
        Plaintext::from_str(s).expect("literal parses")
    }

    // ── literal round-trips (upstream vector) ──────────────────────────

    #[test]
    fn literal_round_trips_match_upstream() {
        for s in [
            "aleo13nnjqa7h2u4mpl95guz97nhzkhlde750zsjnw59tkgdwc85lyurs295lxc",
            "true",
            "1field",
            "2group",
            "100i8",
            "100i16",
            "100i32",
            "100i64",
            "100i128",
            "100u8",
            "100u16",
            "100u32",
            "100u64",
            "100u128",
            "1scalar",
        ] {
            let plaintext = p(s);
            assert_eq!(plaintext.to_string(), s, "round-trip failed for {s}");
        }
    }

    // ── find: struct member lookup + pinned errors ────────────────────

    #[test]
    fn find_returns_struct_members() {
        let plaintext = p(STRUCT);
        let microcredits = p("100000000u64");
        let height = p("1653124u32");

        let id_micro = Identifier::from_str("microcredits").unwrap();
        let id_height = Identifier::from_str("height").unwrap();
        assert_eq!(plaintext.find(&[id_micro]).unwrap(), microcredits);
        assert_eq!(plaintext.find(&[id_height]).unwrap(), height);
    }

    #[test]
    fn find_errors_are_pinned() {
        // Not a struct → error (docs say "returns null" — WRONG).
        let literal = p("1field");
        let id = Identifier::from_str("x").unwrap();
        let err = literal.find(&[id]).unwrap_err();
        assert_eq!(err.to_string(), "'1field' is not a struct");

        // Missing member → error.
        let plaintext = p(STRUCT);
        let id = Identifier::from_str("nope").unwrap();
        let err = plaintext.find(&[id]).unwrap_err();
        assert!(err.to_string().starts_with("Failed to locate member 'nope'"));
    }

    // ── plaintextType: "struct" not the struct name ───────────────────

    #[test]
    fn plaintext_type_is_type_name_not_struct_name() {
        assert_eq!(plaintext_type(&p("2u8")), "u8");
        assert_eq!(plaintext_type(&p("1field")), "field");
        assert_eq!(plaintext_type(&p("true")), "boolean"); // not "bool"!
        assert_eq!(plaintext_type(&p("2group")), "group");
        assert_eq!(plaintext_type(&p("1scalar")), "scalar");
        // Struct → "struct", NOT the struct name.
        assert_eq!(plaintext_type(&p(STRUCT)), "struct");
        // Array → "array".
        assert_eq!(plaintext_type(&p("[1u8, 2u8]")), "array");
    }

    // ── to_json_value: type mapping ──────────────────────────────────

    #[test]
    fn to_json_value_maps_types_correctly() {
        // Boolean → Bool.
        assert_eq!(to_json_value(&p("true")), serde_json::json!(true));
        // Small integers → Number (exact).
        assert_eq!(to_json_value(&p("2u8")), serde_json::json!(2));
        assert_eq!(to_json_value(&p("100i32")), serde_json::json!(100));
        assert_eq!(to_json_value(&p("100u64")), serde_json::json!(100));
        // 128-bit → String (serde_json lacks u128/i128).
        // Deref to primitive to strip the type suffix.
        assert_eq!(to_json_value(&p("100u128")), serde_json::json!("100"));
        assert_eq!(to_json_value(&p("100i128")), serde_json::json!("100"));
        // Field, Group, Scalar, Address → String.
        assert_eq!(to_json_value(&p("1field")), serde_json::json!("1field"));
        assert_eq!(to_json_value(&p("2group")), serde_json::json!("2group"));
        assert_eq!(to_json_value(&p("1scalar")), serde_json::json!("1scalar"));

        // Full integer matrix: every width must reach its own Number arm.
        // (JS would collapse all of these into f64; Rust keeps them exact.)
        for (literal, expected) in [
            ("2i8", 2i64),
            ("2i16", 2),
            ("2i32", 2),
            ("2i64", 2),
            ("2u8", 2),
            ("2u16", 2),
            ("2u32", 2),
            ("2u64", 2),
        ] {
            assert_eq!(
                to_json_value(&p(literal)),
                Value::Number(Number::from(expected)),
                "integer arm for {literal}"
            );
        }
        // Negative signed values stay exact.
        assert_eq!(to_json_value(&p("-3i8")), serde_json::json!(-3));
        assert_eq!(to_json_value(&p("-3i64")), serde_json::json!(-3));
    }

    #[test]
    fn to_json_value_struct_and_array() {
        // Struct → Object keyed by member names.
        let plaintext = p("{ a: 2u8, b: true }");
        let expected = serde_json::json!({ "a": 2, "b": true });
        assert_eq!(to_json_value(&plaintext), expected);

        // Array → Array.
        let plaintext = p("[1u8, 2u8, 3u8]");
        let expected = serde_json::json!([1, 2, 3]);
        assert_eq!(to_json_value(&plaintext), expected);

        // Nested struct (upstream NESTED_STRUCT vector).
        let plaintext = p(NESTED_STRUCT);
        let val = to_json_value(&plaintext);
        assert_eq!(
            val["player"],
            serde_json::json!("aleo13nnjqa7h2u4mpl95guz97nhzkhlde750zsjnw59tkgdwc85lyurs295lxc")
        );
        assert_eq!(val["health"], serde_json::json!(100));
        assert_eq!(val["is_alive"], serde_json::json!(true));
        assert_eq!(val["secret"], serde_json::json!("2group"));
    }

    #[test]
    fn to_json_value_preserves_struct_member_order() {
        // JS `toObject()` yields an object whose string keys keep declaration
        // order. With serde_json's default BTreeMap this would come out as
        // `{"a":..,"z":..}`; `preserve_order` keeps the struct's order.
        let plaintext = p("{ zebra: 1u8, apple: 2u8 }");
        let json = serde_json::to_string(&to_json_value(&plaintext)).unwrap();
        assert_eq!(
            json, r#"{"zebra":1,"apple":2}"#,
            "member order must be preserved"
        );
    }

    // ── raw vs non-raw bits: variant prefix ──────────────────────────

    #[test]
    fn raw_bits_exclude_variant_prefix() {
        let plaintext = p("2u8");
        let raw_bits = plaintext.to_bits_raw_le();
        let all_bits = plaintext.to_bits_le();

        // Raw bits = exactly 8 bits (value only).
        assert_eq!(raw_bits.len(), 8, "raw bits = 8 for u8 literal");
        assert_eq!(
            raw_bits,
            vec![false, true, false, false, false, false, false, false]
        );

        // Non-raw bits include variant/identifier prefix → much longer.
        assert!(
            all_bits.len() > raw_bits.len(),
            "non-raw includes variant prefix"
        );
    }

    #[test]
    fn to_fields_raw_differs_from_to_fields() {
        let plaintext = p("2u8");
        let fields_raw = plaintext.to_fields_raw().unwrap();
        let fields = plaintext.to_fields().unwrap();

        // 🔴 Both are a SINGLE field — the count is the same. `to_fields`
        // additionally encodes the variant/identifier prefix and appends a
        // terminus bit, so the VALUE differs while the length does not.
        assert_eq!(fields_raw.len(), fields.len(), "both fit in one field");
        assert_ne!(fields_raw, fields, "same length, different bits");
    }

    // ── toBytesRawBe reverses the byte vector ────────────────────────

    #[test]
    fn to_bytes_raw_le_preserves_member_order() {
        let plaintext = p("{ a: 2u8, b: 3u8 }");
        let bytes = to_bytes_raw_le(&plaintext).unwrap();
        assert_eq!(bytes, vec![2, 3], "LE preserves member order");
    }

    #[test]
    fn to_bytes_raw_be_reverses_member_order() {
        let plaintext = p("{ a: 2u8, b: 3u8 }");
        let bytes = to_bytes_raw_be(&plaintext).unwrap();
        // 🔴 Upstream reverses the byte vector → [3, 2], not [2, 3].
        assert_eq!(
            bytes,
            vec![3, 2],
            "BE reverses member order (upstream quirk)"
        );
    }

    #[test]
    fn to_bytes_raw_single_byte_is_noop() {
        let plaintext = p("2u8");
        let le = to_bytes_raw_le(&plaintext).unwrap();
        let be = to_bytes_raw_be(&plaintext).unwrap();
        assert_eq!(le, vec![2]);
        assert_eq!(be, vec![2], "single byte: reverse is a no-op");
    }

    // ── toBytesRaw* zero-pads trailing short chunks ──────────────────

    #[test]
    fn to_bytes_raw_zero_pads_short_chunks() {
        // 🔴 A Boolean has exactly 1 raw bit. `U8::from_bits_le` accepts it
        // and zero-pads, so there is NO error — the docs' "raw bytes" name
        // suggests byte alignment that is never enforced.
        let le = to_bytes_raw_le(&p("true")).unwrap();
        let be = to_bytes_raw_be(&p("true")).unwrap();
        assert_eq!(le, vec![1], "true → low bit set");
        assert_eq!(be, vec![1], "BE: single byte, reverse is a no-op");
        assert_eq!(to_bytes_raw_le(&p("false")).unwrap(), vec![0]);

        // A 1-byte + 1-bit plaintext still yields exactly two bytes.
        let mixed = to_bytes_raw_le(&p("{ a: 2u8, b: true }")).unwrap();
        assert_eq!(mixed.len(), 2, "9 raw bits pad out to 2 bytes");
    }

    // ── fromString rejects mode suffixes ─────────────────────────────

    #[test]
    fn from_string_rejects_mode_suffix() {
        assert!(Plaintext::<CurrentNetwork>::from_str("1field.private").is_err());
        assert!(Plaintext::<CurrentNetwork>::from_str("1field.public").is_err());
    }

    // ── encrypt / encryptSymmetric round-trip ────────────────────────

    #[test]
    fn encrypt_derives_view_key_from_address_times_randomizer() {
        let rng = &mut TestRng::fixed(0);
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let address = Address::try_from(&private_key).unwrap();
        let randomizer = Scalar::<CurrentNetwork>::rand(rng);

        let plaintext = p("{ a: 2u8, b: true }");

        // encrypt(address, randomizer) == encrypt_symmetric((address * randomizer).to_x_coordinate())
        let cipher1 = plaintext.encrypt(&address, randomizer).unwrap();
        let addr_group: Group<CurrentNetwork> = *address;
        let derived_tvk = (addr_group * randomizer).to_x_coordinate();
        let cipher2 = plaintext.encrypt_symmetric(derived_tvk).unwrap();
        assert_eq!(
            cipher1, cipher2,
            "encrypt == encrypt_symmetric(derived_tvk)"
        );
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let rng = &mut TestRng::fixed(0);
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let address = Address::try_from(&private_key).unwrap();
        let view_key = ViewKey::try_from(&private_key).unwrap();
        let randomizer = Scalar::<CurrentNetwork>::rand(rng);

        let plaintext = p("{ a: 2u8, b: true }");

        // Asymmetric: encrypt(address, randomizer) → decrypt(view_key, nonce).
        let cipher = plaintext.encrypt(&address, randomizer).unwrap();
        // 🔴 The record nonce MUST be `g_scalar_multiply(randomizer)` — the
        // account-encryption generator (GENERATOR_G), NOT the curve generator
        // `Group::generator()`. Encryption derives the tvk from
        // `address * randomizer`; decryption derives it from
        // `nonce * view_key`. These coincide only when
        // `address = g_scalar_multiply(view_key)` and
        // `nonce = g_scalar_multiply(randomizer)`. Using the wrong generator
        // silently yields a bogus tvk and fails with "Insufficient bits".
        let nonce = <CurrentNetwork as Network>::g_scalar_multiply(&randomizer);
        let decrypted = cipher.decrypt(view_key, nonce).unwrap();
        assert_eq!(decrypted, plaintext);

        // Symmetric: encrypt_symmetric(tvk) → decrypt_symmetric(tvk).
        let addr_group: Group<CurrentNetwork> = *address;
        let tvk = (addr_group * randomizer).to_x_coordinate();
        let cipher = plaintext.encrypt_symmetric(tvk).unwrap();
        let decrypted = cipher.decrypt_symmetric(tvk).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
