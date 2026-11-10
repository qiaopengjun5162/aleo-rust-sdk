//! Aleo `PrivateKey` — parity with the JS SDK's wasm `PrivateKey` class.
//!
//! snarkVM's [`PrivateKey<N>`] already covers most of the page natively. The
//! one real gap is the **encrypted-private-key format**: the JS SDK's
//! `Encryptor` uses Poseidon + a snarkVM [`Ciphertext<N>`] (`ciphertext1…`),
//! while [`crate::account`]'s `aleo-enc-v1:` helpers use AES-GCM/PBKDF2. The
//! two formats are **wire-incompatible** — a ciphertext produced by JS cannot
//! be opened by `AleoAccount::from_ciphertext`, and vice versa. This module
//! implements the upstream scheme so Rust and JS ciphertexts interoperate.
//!
//! ## JS `PrivateKey` → Rust mapping
//!
//! | # | JS `PrivateKey` | Rust equivalent | Where |
//! |---|---|---|---|
//! | 1 | `new PrivateKey()` | `PrivateKey::new(rng)?` | snarkVM |
//! | 2 | `from_seed_unchecked(seed)` | [`from_seed_unchecked`] | **this module** |
//! | 3 | `from_string(s)` | `PrivateKey::from_str(s)?` | snarkVM (`FromStr`) |
//! | 4 | `to_string()` | `pk.to_string()` | snarkVM (`Display`) |
//! | 5 | `to_view_key()` | `ViewKey::try_from(&pk)?` | snarkVM |
//! | 6 | `to_address()` | `Address::try_from(&pk)?` | snarkVM |
//! | 7 | `sign(bytes)` | `Signature::sign_bytes(&pk, bytes, rng)?` | snarkVM / [`crate::account`] |
//! | 8 | `newEncrypted(secret)` | [`new_encrypted`] | **this module** |
//! | 9 | `toCiphertext(secret)` | [`encrypt_private_key`] | **this module** |
//! | 10 | `fromPrivateKeyCiphertext(ct, secret)` | [`decrypt_private_key`] | **this module** |
//! | 11 | `signValue(message)` | [`crate::signature::sign_value`] | [`crate::signature`] (#53) |
//! | — | `toBytesLe()` / `fromBytesLe(b)` (page omits these) | `ToBytes` / `FromBytes` | snarkVM |
//!
//! ## 🔴 The two encryption formats are incompatible
//!
//! | | JS `PrivateKeyCiphertext` | `aleo-enc-v1:` (crate-local) |
//! |---|---|---|
//! | Representation | bech32m `ciphertext1…` (`Ciphertext<N>`) | hex, `aleo-enc-v1:` prefix |
//! | Primitive | Poseidon `hash_psd2` + field blinding | AES-256-GCM |
//! | Key derivation | `Field::new_domain_separator(secret)` | PBKDF2-HMAC-SHA256 |
//! | Storage | a struct `{ key, nonce }` encrypted symmetrically | raw private-key string |
//!
//! Both are secure for storage at rest, but **only this module's format can
//! be exchanged with the JS SDK**. Do not feed a `ciphertext1…` string to
//! [`crate::account::AleoAccount::from_ciphertext`] — it will reject the
//! prefix. The upstream literal vector in the tests pins interoperability:
//! decrypting a JS-produced ciphertext with the right secret recovers the
//! exact `APrivateKey1…` string.
//!
//! ## How the upstream scheme works
//!
//! ```text
//! domain  = Field::new_domain_separator("private_key")
//! secret  = Field::new_domain_separator(secret_string)   // NOT the raw string
//! nonce   = random Field
//! blinding = hash_psd2([domain, nonce, secret])
//! key      = blinding * private_key.seed()
//! plaintext = { key: key, nonce: nonce }
//! ciphertext = plaintext.encrypt_symmetric(secret)
//! ```
//!
//! Decryption divides `key` by the recomputed blinding to recover the seed,
//! then `PrivateKey::try_from(seed)` re-derives `sk_sig`/`r_sig`. The secret is
//! a **domain-separated field element**, not a byte string — using the raw
//! secret bytes would silently produce a different, undecryptable ciphertext.
//!
//! ## 🔴 `from_seed_unchecked` panics on a wrong-length seed in JS
//!
//! The upstream binding does `seed.try_into().unwrap()`: any slice that is not
//! exactly 32 bytes **panics** rather than returning an error. [`from_seed_unchecked`]
//! returns `Err` instead (a library should not panic on caller-supplied data).
//! Non-canonical seeds are reduced modulo the scalar-field order, so every
//! 32-byte input yields a key — "unchecked" refers to that reduction.
//!
//! ## RNG injection
//!
//! `new`, `sign`, and encryption all need randomness. The JS bindings reach
//! for a global RNG; every helper here takes an explicit `rng` so tests are
//! deterministic and callers control the entropy source.
//!
//! ## Usage
//!
//! ```
//! use aleo_rust_sdk::private_key::{decrypt_private_key, encrypt_private_key};
//! use snarkvm::prelude::{PrivateKey, TestnetV0};
//! use snarkvm::utilities::rand::TestRng;
//!
//! let rng = &mut TestRng::fixed(42);
//! let pk = PrivateKey::<TestnetV0>::new(rng).unwrap();
//! let ct = encrypt_private_key(&pk, "correct horse battery staple", rng).unwrap();
//! let recovered = decrypt_private_key(&ct, "correct horse battery staple").unwrap();
//! assert_eq!(pk, recovered);
//! ```

use anyhow::{Context, Result};
use indexmap::IndexMap;
use snarkvm::fields::PrimeField;
use snarkvm::prelude::{
    Ciphertext, CryptoRng, Environment, Field, Identifier, Literal, Network, Plaintext, PrivateKey,
    Rng,
};
use snarkvm::utilities::Uniform;
use std::str::FromStr;
use std::sync::OnceLock;

/// Domain separator used by the upstream `Encryptor` for private-key material.
const PRIVATE_KEY_DOMAIN: &str = "private_key";

/// Encrypts a private key into a JS-SDK-compatible `ciphertext1…` string.
///
/// Equivalent to JS `privateKey.toCiphertext(secret)` /
/// `PrivateKeyCiphertext.encryptPrivateKey(pk, secret)`.
///
/// The nonce is drawn from `rng`, so encrypting the same key twice with the
/// same secret produces different ciphertexts (both decrypt correctly).
///
/// # Arguments
/// * `private_key` - The key to encrypt.
/// * `secret` - The passphrase; domain-separated into a field element.
/// * `rng` - Randomness source for the blinding nonce.
pub fn encrypt_private_key<N: Network, R: Rng + CryptoRng>(
    private_key: &PrivateKey<N>,
    secret: &str,
    rng: &mut R,
) -> Result<Ciphertext<N>> {
    let domain = Field::<N>::new_domain_separator(PRIVATE_KEY_DOMAIN);
    let secret_field = Field::<N>::new_domain_separator(secret);
    let nonce: Field<N> = Uniform::rand(rng);

    let blinding = N::hash_psd2(&[domain, nonce, secret_field])
        .context("Failed to derive the blinding factor")?;
    let key = blinding * private_key.seed();

    let mut members = IndexMap::new();
    members.insert(
        Identifier::<N>::from_str("key").context("'key' is a valid identifier")?,
        Plaintext::from(Literal::Field(key)),
    );
    members.insert(
        Identifier::<N>::from_str("nonce").context("'nonce' is a valid identifier")?,
        Plaintext::from(Literal::Field(nonce)),
    );
    let plaintext = Plaintext::Struct(members, OnceLock::new());

    plaintext
        .encrypt_symmetric(secret_field)
        .context("Failed to encrypt the private key")
}

/// Decrypts a JS-SDK-compatible ciphertext back into a private key.
///
/// Equivalent to JS `PrivateKey.fromPrivateKeyCiphertext(ct, secret)` /
/// `privateKeyCiphertext.decryptToPrivateKey(secret)`.
///
/// A wrong secret fails (the decrypted struct's `nonce` will not match the
/// recomputed blinding, so the recovered seed is junk and key derivation
/// rejects it — or the symmetric decryption itself fails).
///
/// # Arguments
/// * `ciphertext` - The `Ciphertext<N>` (parse with `Ciphertext::from_str`).
/// * `secret` - The passphrase used at encryption time.
pub fn decrypt_private_key<N: Network>(
    ciphertext: &Ciphertext<N>,
    secret: &str,
) -> Result<PrivateKey<N>> {
    let domain = Field::<N>::new_domain_separator(PRIVATE_KEY_DOMAIN);
    let secret_field = Field::<N>::new_domain_separator(secret);

    let decrypted = ciphertext
        .decrypt_symmetric(secret_field)
        .context("Decryption failed (wrong secret or corrupt ciphertext)")?;
    let key = extract_field(&decrypted, "key")?;
    let nonce = extract_field(&decrypted, "nonce")?;

    let blinding = N::hash_psd2(&[domain, nonce, secret_field])
        .context("Failed to recompute the blinding factor")?;
    let seed = key / blinding;

    PrivateKey::try_from(seed).context("Recovered seed is not a valid private key")
}

/// Pulls a `Field` literal out of a decrypted plaintext struct member.
fn extract_field<N: Network>(plaintext: &Plaintext<N>, member: &str) -> Result<Field<N>> {
    let identifier =
        Identifier::<N>::from_str(member).context(format!("'{member}' is a valid identifier"))?;
    let value = plaintext
        .find(&[identifier])
        .context(format!("Missing or invalid '{member}' member"))?;
    match value {
        Plaintext::Literal(Literal::Field(field), ..) => Ok(field),
        other => anyhow::bail!("Expected '{member}' to be a field literal, got {other}"),
    }
}

/// Generates a fresh private key and returns it together with its encrypted form.
///
/// Equivalent to JS `PrivateKey.newEncrypted(secret)`. The JS method returns
/// **only** the ciphertext (the freshly generated key is discarded unless you
/// keep it) — a footgun if the caller forgets the ciphertext is the sole copy.
/// Returning both keeps the key available while preserving that behaviour.
///
/// # Arguments
/// * `secret` - The passphrase for the ciphertext.
/// * `rng` - Randomness source for both key generation and the nonce.
pub fn new_encrypted<N: Network, R: Rng + CryptoRng>(
    secret: &str,
    rng: &mut R,
) -> Result<(PrivateKey<N>, Ciphertext<N>)> {
    let private_key = PrivateKey::new(rng)?;
    let ciphertext = encrypt_private_key(&private_key, secret, rng)?;
    Ok((private_key, ciphertext))
}

/// Recovers a private key deterministically from a 32-byte seed.
///
/// Equivalent to JS `PrivateKey.from_seed_unchecked(seed)`. The seed is read
/// little-endian and **reduced modulo the scalar-field order** — every 32-byte
/// input is accepted (that is what "unchecked" means). Unlike the upstream
/// binding, a wrong-length seed returns `Err` instead of panicking.
///
/// # Arguments
/// * `seed` - Exactly 32 bytes.
pub fn from_seed_unchecked<N: Network>(seed: &[u8]) -> Result<PrivateKey<N>> {
    let bytes: [u8; 32] = seed
        .try_into()
        .context(format!("Seed must be exactly 32 bytes, got {}", seed.len()))?;
    let field =
        Field::<N>::new(<<N as Environment>::Field as PrimeField>::from_bytes_le_mod_order(&bytes));
    PrivateKey::try_from(field).context("Private key derivation failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    use snarkvm::prelude::{Address, FromBytes, Signature, TestnetV0, ToBytes, ViewKey};
    use snarkvm::utilities::rand::TestRng;

    type CurrentNetwork = TestnetV0;

    /// Upstream wasm test vectors (`wasm/src/account/private_key.rs`).
    const ALEO_PRIVATE_KEY: &str = "APrivateKey1zkp3dQx4WASWYQVWKkq14v3RoQDfY2kbLssUj7iifi1VUQ6";
    const ALEO_VIEW_KEY: &str = "AViewKey1cxguxtKkjYnT9XDza9yTvVMxt6Ckb1Pv4ck1hppMzmCB";
    const ALEO_ADDRESS: &str = "aleo184vuwr5u7u0ha5f5k44067dd2uaqewxx6pe5ltha5pv99wvhfqxqv339h4";

    /// Upstream `PrivateKeyCiphertext` literal vector: produced by the JS
    /// binding with secret `"mypassword"`, decrypting to `ENCRYPTED_PRIVATE_KEY`.
    const ENCRYPTED_PRIVATE_KEY: &str =
        "APrivateKey1zkpAYS46Dq4rnt9wdohyWMwdmjmTeMJKPZdp5AhvjXZDsVG";
    const CIPHERTEXT: &str = "ciphertext1qvqg7rgvam3xdcu55pwu6sl8rxwefxaj5gwthk0yzln6jv5fastzup0qn0qftqlqq7jcckyx03fzv9kke0z9puwd7cl7jzyhxfy2f2juplz39dkqs6p24urhxymhv364qm3z8mvyklv5gr52n4fxr2z59jgqytyddj8";

    fn pk(s: &str) -> PrivateKey<CurrentNetwork> {
        PrivateKey::from_str(s).expect("literal private key parses")
    }

    // ── upstream sanity vector: the key derivation chain ───────────────

    #[test]
    fn upstream_sanity_vector_key_chain() {
        let private_key = pk(ALEO_PRIVATE_KEY);
        assert_eq!(private_key.to_string(), ALEO_PRIVATE_KEY);
        let view_key = ViewKey::try_from(&private_key).unwrap();
        assert_eq!(view_key.to_string(), ALEO_VIEW_KEY);
        let address = Address::try_from(&private_key).unwrap();
        assert_eq!(address.to_string(), ALEO_ADDRESS);
        // The view key must derive the same address.
        assert_eq!(view_key.to_address(), address);
    }

    // ── cross-language ciphertext interop (the real gap) ───────────────

    #[test]
    fn decrypts_upstream_js_ciphertext_literal() {
        // 🔴 This ciphertext was produced by the JS SDK's wasm binding. Being
        // able to open it proves the Rust implementation matches the upstream
        // Poseidon/domain-separator scheme byte-for-byte — not just a local
        // encrypt→decrypt round-trip.
        let ciphertext = Ciphertext::<CurrentNetwork>::from_str(CIPHERTEXT).unwrap();
        let recovered = decrypt_private_key(&ciphertext, "mypassword").unwrap();
        assert_eq!(recovered.to_string(), ENCRYPTED_PRIVATE_KEY);

        // A wrong secret must fail.
        assert!(decrypt_private_key(&ciphertext, "badpassword").is_err());
    }

    #[test]
    fn upstream_ciphertext_round_trips_through_string() {
        let ciphertext = Ciphertext::<CurrentNetwork>::from_str(CIPHERTEXT).unwrap();
        assert_eq!(
            ciphertext.to_string(),
            CIPHERTEXT,
            "bech32m string is canonical"
        );
        // The mutated (invalid checksum) vector from the upstream test.
        let bad = "ciphertext1qvqg7rgvam3xdcu55pwu6sl8rxwefxaj5gwthk0yzln6jv5fastzup0qn0qftqlqq7jcckyx03fzv9kke0z9puwd7cl7jzyhxfy2f2juplz39dkqs6p24urhxymhv364qm3z8mvyklv5er52n4fxr2z59jgqytyddj8";
        assert!(Ciphertext::<CurrentNetwork>::from_str(bad).is_err());
    }

    // ── encrypt / decrypt round-trip ───────────────────────────────────

    #[test]
    fn encrypt_decrypt_round_trip() {
        let rng = &mut TestRng::fixed(7);
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let ciphertext = encrypt_private_key(&private_key, "mypassword", rng).unwrap();
        assert_eq!(
            decrypt_private_key(&ciphertext, "mypassword").unwrap(),
            private_key
        );
        assert!(decrypt_private_key(&ciphertext, "wrong_password").is_err());
    }

    #[test]
    fn ciphertext_is_serializable_string() {
        let rng = &mut TestRng::fixed(8);
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let ciphertext = encrypt_private_key(&private_key, "secret", rng).unwrap();
        let text = ciphertext.to_string();
        assert!(
            text.starts_with("ciphertext1"),
            "JS-compatible bech32m prefix: {text}"
        );
        let parsed = Ciphertext::<CurrentNetwork>::from_str(&text).unwrap();
        assert_eq!(decrypt_private_key(&parsed, "secret").unwrap(), private_key);
    }

    #[test]
    fn same_key_twice_yields_different_ciphertexts_both_recoverable() {
        let rng = &mut TestRng::fixed(9);
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let c1 = encrypt_private_key(&private_key, "mypassword", rng).unwrap();
        let c2 = encrypt_private_key(&private_key, "mypassword", rng).unwrap();
        assert_ne!(c1, c2, "fresh nonce each time");
        assert_eq!(decrypt_private_key(&c1, "mypassword").unwrap(), private_key);
        assert_eq!(decrypt_private_key(&c2, "mypassword").unwrap(), private_key);
    }

    #[test]
    fn different_secrets_yield_different_ciphertexts() {
        let rng = &mut TestRng::fixed(10);
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let c1 = encrypt_private_key(&private_key, "mypassword", rng).unwrap();
        let c2 = encrypt_private_key(&private_key, "mypassword2", rng).unwrap();
        assert_ne!(c1, c2);
        assert_eq!(
            decrypt_private_key(&c2, "mypassword2").unwrap(),
            private_key
        );
    }

    #[test]
    fn new_encrypted_returns_key_and_ciphertext() {
        let rng = &mut TestRng::fixed(11);
        let (private_key, ciphertext) = new_encrypted::<CurrentNetwork, _>("pw", rng).unwrap();
        assert_eq!(decrypt_private_key(&ciphertext, "pw").unwrap(), private_key);
    }

    // ── from_seed_unchecked ────────────────────────────────────────────

    #[test]
    fn from_seed_unchecked_is_deterministic_and_rejects_bad_length() {
        let seed = [7u8; 32];
        let a = from_seed_unchecked::<CurrentNetwork>(&seed).unwrap();
        let b = from_seed_unchecked::<CurrentNetwork>(&seed).unwrap();
        assert_eq!(a, b);
        // 🔴 JS panics here (try_into().unwrap()); Rust returns Err.
        assert!(from_seed_unchecked::<CurrentNetwork>(&[0u8; 31]).is_err());
        assert!(from_seed_unchecked::<CurrentNetwork>(&[0u8; 33]).is_err());
        // Every 32-byte value is accepted, even non-canonical ones.
        assert!(from_seed_unchecked::<CurrentNetwork>(&[0xffu8; 32]).is_ok());
    }

    // ── malformed-plaintext validation branches ───────────────────────

    /// Encrypts an arbitrary struct with the *same* domain-separated secret,
    /// so symmetric decryption succeeds and `decrypt_private_key` reaches its
    /// member/seed validation branches instead of failing at the first step.
    fn ciphertext_for(literal: &str, secret: &str) -> Ciphertext<CurrentNetwork> {
        let plaintext = Plaintext::<CurrentNetwork>::from_str(literal).unwrap();
        let secret_field = Field::<CurrentNetwork>::new_domain_separator(secret);
        plaintext.encrypt_symmetric(secret_field).unwrap()
    }

    #[test]
    fn decrypt_rejects_structs_with_missing_or_mistyped_members() {
        // `key` resolves, `nonce` does not.
        let missing = ciphertext_for("{ key: 1field }", "pw");
        let err = decrypt_private_key(&missing, "pw").unwrap_err();
        assert!(
            err.to_string().contains("Missing or invalid 'nonce' member"),
            "{err}"
        );

        // `key` is present but is not a Field literal.
        let mistyped = ciphertext_for("{ key: 1u8, nonce: 1field }", "pw");
        let err = decrypt_private_key(&mistyped, "pw").unwrap_err();
        assert!(
            err.to_string().contains("Expected 'key' to be a field literal"),
            "{err}"
        );
    }

    #[test]
    fn decrypt_rejects_a_non_struct_plaintext() {
        // `find` on a literal fails before the match arm is reached.
        let ciphertext = ciphertext_for("1field", "pw");
        let err = decrypt_private_key(&ciphertext, "pw").unwrap_err();
        assert!(
            err.to_string().contains("Missing or invalid 'key' member"),
            "{err}"
        );
    }

    // ── page methods that are native to snarkVM ────────────────────────

    #[test]
    fn native_bytes_round_trip_and_signature() {
        let rng = &mut TestRng::fixed(12);
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

        // toBytesLe / fromBytesLe (the docs page omits these).
        let bytes = private_key.to_bytes_le().unwrap();
        assert_eq!(
            PrivateKey::<CurrentNetwork>::from_bytes_le(&bytes).unwrap(),
            private_key
        );

        // sign(bytes) → verify with the address.
        let message: [u8; 32] = [42u8; 32];
        let signature = Signature::sign_bytes(&private_key, &message, rng).unwrap();
        let address = Address::try_from(&private_key).unwrap();
        assert!(signature.verify_bytes(&address, &message));
    }
}
