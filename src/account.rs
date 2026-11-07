//! # Aleo Account — key management for Aleo blockchain accounts.
//!
//! Wraps snarkVM account primitives with a safe, ergonomic API.
//! Key chain: `PrivateKey → ViewKey → ComputeKey → Address`.
//!
//! ## JS SDK Feature Mapping
//!
//! | JS SDK (Provable) | Rust SDK | Description |
//! |-------------------|----------|-------------|
//! | `new Account()` | `AleoAccount::new_random(rng)` | Random account generation |
//! | `new Account({seed})` | `AleoAccount::from_seed(&[u8; 32])` | Deterministic recovery from a seed |
//! | `new Account({privateKey})` | `AleoAccount::from_private_key_str(s)` | Recover from key string |
//! | `PrivateKey.newEncrypted(password)` | `AleoAccount::new_encrypted(password)` | Random + encrypted ciphertext |
//! | `privateKey.toCiphertext(password)` | `account.encrypt_private_key(password)` | Encrypt existing private key |
//! | `Account.fromCiphertext(ct, pw)` | `AleoAccount::from_ciphertext(ct, pw)` | Decrypt and recover |
//! | `Account.isValidAddress(s)` | `AleoAccount::is_valid_address(s)` | Address format validation |
//! | `account.decryptRecord(ct)` | `account.decrypt_record(ct)` | Decrypt one record ciphertext |
//! | `account.decryptRecords(cts)` | `account.decrypt_records(cts)` | Decrypt many, fail-fast |
//! | `account.ownsRecordCiphertext(ct)` | `account.owns_record_ciphertext(ct)` | Ownership check without decrypting |
//! | `account.generateRecordViewKey(ct)` | `account.generate_record_view_key(ct)` | Per-record key, shared without the view key |
//! | `account.generateTransitionViewKey(tpk)` | `account.generate_transition_view_key(tpk)` | Per-transition key for private inputs |
//! | `account.sign(msg)` | `account.sign(msg, rng)` | Sign raw bytes |
//! | `account.verify(msg, sig)` | `account.verify(msg, &sig)` | Verify a signature |
//! | `account.toString()` | `account.address_str()` / `Display` | Address as a string |
//! | `account.destroy()` | `account.destroy()` | Best-effort key overwrite |
//!
//! ## Key Derivation Chain
//!
//! ```text
//! PrivateKey ──→ ViewKey
//!      │
//!      └──→ ComputeKey ──→ Address
//! ```
//!
//! ## Usage
//!
//! ```no_run
//! use aleo_rust_sdk::AleoAccount;
//! use snarkvm::prelude::TestRng;
//!
//! let mut rng = TestRng::default();
//!
//! // Generate a random account
//! let account = AleoAccount::new_random(&mut rng).unwrap();
//! println!("Address: {}", account.address_str());
//!
//! // Recover from a private key string
//! let recovered = AleoAccount::from_private_key_str("APrivateKey1...").unwrap();
//! assert_eq!(recovered.address_str(), "aleo1...");
//!
//! // Encrypt and decrypt
//! let (_, ciphertext) = AleoAccount::new_encrypted("mypassword", &mut rng).unwrap();
//! let decrypted = AleoAccount::from_ciphertext(&ciphertext, "mypassword").unwrap();
//! assert_eq!(account.address_str(), decrypted.address_str());
//! ```

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{Context, Result};
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;
use snarkvm::console::program::{Ciphertext, Plaintext, Record};
use snarkvm::fields::PrimeField;
use snarkvm::prelude::{
    Address, ComputeKey, CryptoRng, Environment, Field, Group, PrivateKey, Rng, Signature, TestRng,
    TestnetV0, ViewKey,
};
use std::fmt;
use std::str::FromStr;
use zeroize::Zeroize;

/// Number of PBKDF2 iterations for key derivation.
const PBKDF2_ITERATIONS: u32 = 100_000;
/// Required seed length, in bytes. An Aleo account seed is a field element, and
/// 32 bytes is that element's wire width — the JS binding hard-requires it too.
const SEED_LEN: usize = 32;
/// Salt length in bytes.
const SALT_LEN: usize = 16;
/// AES-GCM nonce length.
const NONCE_LEN: usize = 12;
/// AES-256 key length.
const KEY_LEN: usize = 32;
/// Ciphertext tag: aleo-enc-v1:hex(salt || nonce || ciphertext)
const CIPHERTEXT_PREFIX: &str = "aleo-enc-v1:";

/// A decrypted Aleo record — the Rust counterpart of the JS SDK's
/// `RecordPlaintext`.
pub type RecordPlaintext = Record<TestnetV0, Plaintext<TestnetV0>>;

/// An encrypted record as it appears on chain.
type RecordCiphertext = Record<TestnetV0, Ciphertext<TestnetV0>>;

/// Reduce 32 little-endian bytes into a field element, the way the JS binding
/// does for `new Account({seed})`.
///
/// `snarkvm_console_types::Field` is a newtype over the environment's base field,
/// and the mod-order reduction lives on the inner type, so the call goes through
/// `<TestnetV0 as Environment>::Field` rather than the wrapper.
fn field_from_seed_le(seed: &[u8; SEED_LEN]) -> Field<TestnetV0> {
    Field::new(<TestnetV0 as Environment>::Field::from_bytes_le_mod_order(
        seed,
    ))
}

/// An Aleo account holding the full key chain.
#[derive(Clone, Debug)]
pub struct AleoAccount {
    pub private_key: PrivateKey<TestnetV0>,
    pub view_key: ViewKey<TestnetV0>,
    pub compute_key: ComputeKey<TestnetV0>,
    pub address: Address<TestnetV0>,
}

impl AleoAccount {
    /// Derive the full key chain from a private key.
    fn from_private_key(private_key: PrivateKey<TestnetV0>) -> Result<Self> {
        let view_key = ViewKey::try_from(&private_key)
            .map_err(|e| anyhow::anyhow!("View key derivation failed: {e}"))?;
        let compute_key = ComputeKey::try_from(&private_key)
            .map_err(|e| anyhow::anyhow!("Compute key derivation failed: {e}"))?;
        let address = Address::try_from(&compute_key)
            .map_err(|e| anyhow::anyhow!("Address derivation failed: {e}"))?;
        Ok(Self {
            private_key,
            view_key,
            compute_key,
            address,
        })
    }

    /// Create an account from a private key string (bech32).
    pub fn from_private_key_str(key_str: &str) -> Result<Self> {
        let private_key = PrivateKey::from_str(key_str)
            .map_err(|e| anyhow::anyhow!("Invalid private key: {e}"))?;
        Self::from_private_key(private_key)
    }

    /// Generate a new random account.
    pub fn new_random(rng: &mut TestRng) -> Result<Self> {
        let private_key = PrivateKey::new(rng)?;
        Self::from_private_key(private_key)
    }

    /// Recover an account deterministically from a 32-byte seed.
    ///
    /// Equivalent to JS SDK `new Account({seed})`, which calls
    /// `PrivateKey.from_seed_unchecked(seed)`.
    ///
    /// The seed is read as a little-endian field element reduced modulo the
    /// field order, then passed to `PrivateKey::try_from`, which derives the
    /// signing key and signature randomizer with domain separators. The JS
    /// binding additionally round-trips the field through its byte encoding
    /// before that call; the round-trip is a no-op for a canonical element, so
    /// the resulting keys are identical.
    ///
    /// # Errors
    ///
    /// Returns an error if `seed` is not exactly 32 bytes. The JS
    /// binding `unwrap()`s its `try_into` and panics instead; panicking on
    /// caller-supplied data is not something a library should do, so this
    /// returns `Err`.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed: [u8; SEED_LEN] = seed.try_into().map_err(|_| {
            anyhow::anyhow!("Seed must be exactly {SEED_LEN} bytes, got {}", seed.len())
        })?;
        let private_key = PrivateKey::try_from(field_from_seed_le(&seed))
            .map_err(|e| anyhow::anyhow!("Private key derivation from seed failed: {e}"))?;
        Self::from_private_key(private_key)
    }

    // ── JS SDK: Encrypted private key ──────────────────────────────────

    /// Generate a new random account and encrypt its private key with a password.
    ///
    /// Returns `(account, ciphertext)` where ciphertext is a portable string
    /// that can be stored and later recovered with [`AleoAccount::from_ciphertext`].
    ///
    /// Equivalent to JS SDK `PrivateKey.newEncrypted(password)`.
    pub fn new_encrypted(password: &str, rng: &mut TestRng) -> Result<(Self, String)> {
        let account = Self::new_random(rng)?;
        let ciphertext = encrypt_private_key_str(&account.private_key_str(), password)?;
        Ok((account, ciphertext))
    }

    /// Encrypt this account's private key with a password.
    ///
    /// Returns a portable ciphertext string.
    ///
    /// Equivalent to JS SDK `privateKey.toCiphertext(password)`.
    pub fn encrypt_private_key(&self, password: &str) -> Result<String> {
        encrypt_private_key_str(&self.private_key_str(), password)
    }

    /// Decrypt a ciphertext and recover the full account.
    ///
    /// Equivalent to JS SDK `Account.fromCiphertext(ciphertext, password)`.
    pub fn from_ciphertext(ciphertext: &str, password: &str) -> Result<Self> {
        let pk_str = decrypt_private_key_str(ciphertext, password)?;
        Self::from_private_key_str(&pk_str)
    }

    // ── JS SDK: Address validation ──────────────────────────────────────

    /// Check whether a string is a valid Aleo address (bech32m format).
    ///
    /// Equivalent to JS SDK `Account.isValidAddress(s)`.
    ///
    /// Returns `true` if the string is syntactically a valid `aleo1...` address.
    pub fn is_valid_address(address: &str) -> bool {
        // Aleo addresses start with "aleo1" and are bech32m-encoded
        if !address.starts_with("aleo1") {
            return false;
        }
        if address.len() < 10 || address.len() > 128 {
            return false;
        }
        // Try parsing with snarkVM's Address type
        Address::<TestnetV0>::from_str(address).is_ok()
    }

    // ── JS SDK: Record decryption and per-record keys ───────────────────

    /// Decrypt one record ciphertext into a plaintext record.
    ///
    /// Equivalent to JS SDK `account.decryptRecord(ciphertext)`.
    ///
    /// This delegates to `Record::decrypt`, which derives the record view key
    /// as `(nonce · view_key).x` and then **rejects** the result unless the
    /// recovered owner is this account's address. A ciphertext that decrypts is
    /// therefore owned by this account by construction; there is no separate
    /// ownership check that a later change could drop.
    ///
    /// The error does not distinguish "not yours" from "malformed", because
    /// snarkVM's failure modes are not distinguishable here and both mean "not
    /// a record you can spend".
    pub fn decrypt_record(&self, ciphertext: &str) -> Result<RecordPlaintext> {
        let record = parse_record_ciphertext(ciphertext)?;
        record.decrypt(&self.view_key).map_err(|e| {
            anyhow::anyhow!("Record cannot be decrypted with this account's view key: {e}")
        })
    }

    /// Decrypt many record ciphertexts, stopping at the first failure.
    ///
    /// Equivalent to JS SDK `account.decryptRecords(ciphertexts)`.
    ///
    /// # JS docs vs JS implementation
    ///
    /// The published JSDoc claims "if the account owns no records, the array will
    /// be empty", which reads as "foreign ciphertexts are skipped". The
    /// implementation (`sdk/src/account.ts`) is a plain `map` over
    /// `viewKey.decrypt`, so it **throws** on the first foreign ciphertext. This
    /// follows the implementation, since that is the behaviour callers actually
    /// observe. To *filter* a mixed list, use [`Self::owns_record_ciphertext`]
    /// first, or call [`Self::decrypt_record`] per item and drop the errors.
    pub fn decrypt_records<'a>(
        &self,
        ciphertexts: impl IntoIterator<Item = &'a str>,
    ) -> Result<Vec<RecordPlaintext>> {
        ciphertexts
            .into_iter()
            .enumerate()
            .map(|(index, ciphertext)| {
                self.decrypt_record(ciphertext)
                    .with_context(|| format!("ciphertext #{index} could not be decrypted"))
            })
            .collect()
    }

    /// Return `true` if this account owns the given record ciphertext.
    ///
    /// Equivalent to JS SDK `account.ownsRecordCiphertext(ciphertext)`.
    ///
    /// This is the cheap membership test: it decrypts the record's owner field,
    /// not its data entries. Input that does not parse returns `false` (the JS binding
    /// catches the parse error and returns `false` too) rather than surfacing an
    /// error — a caller filtering a list wants "skip it", not "abort".
    pub fn owns_record_ciphertext(&self, ciphertext: &str) -> bool {
        match parse_record_ciphertext(ciphertext) {
            Ok(record) => record.is_owner(&self.view_key),
            Err(e) => {
                tracing::debug!("Record ciphertext rejected while checking ownership: {e}");
                false
            }
        }
    }

    /// Derive the record view key for a ciphertext owned by this account.
    ///
    /// Equivalent to JS SDK `account.generateRecordViewKey(recordCiphertext)`.
    ///
    /// The record view key is `(nonce · view_key).x` as a field element. It
    /// decrypts exactly one record, so it can be handed to a service (an auditor,
    /// an indexer) without handing over the account-wide view key.
    ///
    /// # Errors
    ///
    /// Returns an error if the ciphertext does not parse, or if it belongs to
    /// another account — matching the JS binding, which throws
    /// `"The record ciphertext does not belong to this account"`. Emitting a
    /// view key for a foreign record would only invite the caller to decrypt with
    /// a key that cannot work.
    pub fn generate_record_view_key(&self, ciphertext: &str) -> Result<Field<TestnetV0>> {
        let record = parse_record_ciphertext(ciphertext)?;
        if !record.is_owner(&self.view_key) {
            anyhow::bail!("The record ciphertext does not belong to this account");
        }
        Ok(record_view_key(&record, &self.view_key))
    }

    /// Derive the transition view key for a transition public key.
    ///
    /// Equivalent to JS SDK `account.generateTransitionViewKey(tpk)`.
    ///
    /// Private transition inputs and outputs are encrypted under
    /// `(tpk · view_key).x`, so this key decrypts one transition without
    /// exposing the account-wide view key.
    ///
    /// Unlike [`Self::generate_record_view_key`] there is no ownership check
    /// here: a transition public key carries no owner field, and the JS binding
    /// does not check either. A wrong `tpk` simply yields a key that decrypts to
    /// garbage.
    pub fn generate_transition_view_key(&self, tpk: &str) -> Result<Field<TestnetV0>> {
        let tpk = Group::<TestnetV0>::from_str(tpk)
            .map_err(|e| anyhow::anyhow!("Invalid transition public key: {e}"))?;
        Ok(transition_view_key(&tpk, &self.view_key))
    }

    // ── JS SDK: Message signing ─────────────────────────────────────────

    /// Sign a raw byte message with this account's private key.
    ///
    /// Equivalent to JS SDK `account.sign(message)`.
    ///
    /// Aleo's Schnorr-style signature scheme is randomized, so an RNG is
    /// required: two signatures over the same message differ and both verify.
    /// The bound is snarkVM's own (`rand 0.10`, re-exported through
    /// `snarkvm::prelude`), so callers must pass an RNG from that same `rand`
    /// version; `TestRng` works in tests.
    pub fn sign<R: Rng + CryptoRng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Signature<TestnetV0>> {
        self.private_key
            .sign_bytes(message, rng)
            .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))
    }

    /// Verify a signature over a raw byte message against this account's address.
    ///
    /// Equivalent to JS SDK `account.verify(message, signature)`.
    ///
    /// This verifies against `self.address`; to check somebody else's signature,
    /// parse their address and call `Signature::verify_bytes` directly.
    pub fn verify(&self, message: &[u8], signature: &Signature<TestnetV0>) -> bool {
        signature.verify_bytes(&self.address, message)
    }

    // ── JS SDK: Secure disposal ─────────────────────────────────────────

    /// Overwrite the sensitive key material in this account.
    ///
    /// Equivalent to JS SDK `account.destroy()`, with one honest difference:
    /// `PrivateKey` is `Copy` and exposes no `Zeroize` path through a shared
    /// reference, so this **cannot** guarantee the old bytes are gone from
    /// memory. It replaces the key with an unrelated one, which makes a
    /// use-after-destroy produce the wrong address instead of silently signing
    /// with the destroyed account.
    ///
    /// The replacement is seeded from 32 bytes of `OsRng` entropy rather than
    /// from `TestRng`. `TestRng::default()` would work today (it seeds itself
    /// from OS entropy), but it is a test utility whose seeding policy is not a
    /// stability guarantee — `TestRng::fixed` exists precisely to make it
    /// reproducible. Production key material should not depend on that.
    ///
    /// If you need real erasure, do not keep long-lived `AleoAccount` values:
    /// decrypt from a ciphertext right before use (see [`Self::from_ciphertext`])
    /// and drop the value afterwards.
    pub fn destroy(&mut self) {
        use rand::RngCore;

        let mut seed = [0u8; SEED_LEN];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let field = field_from_seed_le(&seed);
        seed.zeroize();

        let Ok(fresh) = PrivateKey::try_from(field) else {
            return;
        };
        // Overwrite the whole chain, not just the private key: a stale
        // `view_key`/`address` would still identify the destroyed account.
        if let Ok(vk) = ViewKey::try_from(&fresh) {
            self.view_key = vk;
        }
        if let Ok(ck) = ComputeKey::try_from(&fresh) {
            self.compute_key = ck;
        }
        if let Ok(addr) = Address::try_from(&self.compute_key) {
            self.address = addr;
        }
        self.private_key = fresh;
    }

    // ── Accessors ──────────────────────────────────────────────────────

    /// Return the address as a bech32 string.
    pub fn address_str(&self) -> String {
        self.address.to_string()
    }

    /// Return the private key as a bech32 string.
    pub fn private_key_str(&self) -> String {
        self.private_key.to_string()
    }

    /// Return the view key as a bech32 string.
    ///
    /// The view key decrypts every record owned by this account, so treat it as a
    /// secret: hand out [`Self::generate_record_view_key`] values instead when
    /// only one record needs to be readable.
    pub fn view_key_str(&self) -> String {
        self.view_key.to_string()
    }
}

impl fmt::Display for AleoAccount {
    /// Formats the account as its address, matching JS SDK `account.toString()`.
    ///
    /// The private key is deliberately unreachable through `Display`, which is
    /// what makes it safe to interpolate an account into a log line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

impl FromStr for AleoAccount {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::from_private_key_str(s)
    }
}

// ── Record helpers ────────────────────────────────────────────────────

/// Parse a record ciphertext string, with context instead of snarkVM's terse
/// parse error.
fn parse_record_ciphertext(ciphertext: &str) -> Result<RecordCiphertext> {
    RecordCiphertext::from_str(ciphertext)
        .map_err(|e| anyhow::anyhow!("Invalid record ciphertext: {e}"))
}

/// The record view key: `(nonce · view_key).x`.
///
/// Kept as a free function so the derivation lives in exactly one place. The same
/// formula is an invariant snarkVM relies on (`Record::decrypt` and
/// `Record::is_owner` both recompute it), and two copies of it in this crate
/// could drift.
fn record_view_key(record: &RecordCiphertext, view_key: &ViewKey<TestnetV0>) -> Field<TestnetV0> {
    (*record.nonce() * **view_key).to_x_coordinate()
}

/// The transition view key: `(tpk · view_key).x`.
fn transition_view_key(tpk: &Group<TestnetV0>, view_key: &ViewKey<TestnetV0>) -> Field<TestnetV0> {
    (*tpk * **view_key).to_x_coordinate()
}

// ── Encryption helpers ────────────────────────────────────────────────

/// Derive an AES-256 key from a password using PBKDF2-HMAC-SHA256.
fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    pbkdf2_hmac_array::<Sha256, KEY_LEN>(password.as_bytes(), salt, PBKDF2_ITERATIONS)
}

/// Encrypt a private key string with a password.
///
/// Format: `aleo-enc-v1:` + hex(salt[16] || nonce[12] || ciphertext)
fn encrypt_private_key_str(pk_str: &str, password: &str) -> Result<String> {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;

    // Generate random salt
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);

    // Derive key
    let key = derive_key(password, &salt);

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow::anyhow!("AES-GCM init failed: {e}"))?;
    let ciphertext = cipher
        .encrypt(nonce, pk_str.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

    // Format: salt || nonce || ciphertext
    let mut combined = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&salt);
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    // Zeroize sensitive intermediates
    let mut key_mut = key;
    key_mut.zeroize();

    Ok(format!("{}{}", CIPHERTEXT_PREFIX, hex::encode(&combined)))
}

/// Decrypt a ciphertext string back to a private key string.
fn decrypt_private_key_str(ciphertext: &str, password: &str) -> Result<String> {
    // Strip prefix
    let hex_data = ciphertext.strip_prefix(CIPHERTEXT_PREFIX).ok_or_else(|| {
        anyhow::anyhow!("Invalid ciphertext prefix; expected '{CIPHERTEXT_PREFIX}'")
    })?;

    let combined =
        hex::decode(hex_data).map_err(|e| anyhow::anyhow!("Invalid ciphertext hex: {e}"))?;

    if combined.len() < SALT_LEN + NONCE_LEN {
        anyhow::bail!("Ciphertext too short ({} bytes)", combined.len());
    }

    let salt = &combined[..SALT_LEN];
    let nonce = Nonce::from_slice(&combined[SALT_LEN..SALT_LEN + NONCE_LEN]);
    let encrypted = &combined[SALT_LEN + NONCE_LEN..];

    // Derive key
    let key = derive_key(password, salt);

    // Decrypt
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow::anyhow!("AES-GCM init failed: {e}"))?;
    let plaintext = cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| anyhow::anyhow!("Decryption failed (wrong password or corrupted data)"))?;

    let mut key_mut = key;
    key_mut.zeroize();

    String::from_utf8(plaintext)
        .map_err(|e| anyhow::anyhow!("Decrypted data is not valid UTF-8: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexmap::IndexMap;
    use snarkvm::console::program::{Entry, Identifier, Literal, Owner};
    use snarkvm::prelude::{Network, Scalar, U8};
    use snarkvm::utilities::rand::Uniform;

    /// Build a genuine encrypted record for `account` holding a private
    /// `microcredits` entry.
    ///
    /// snarkVM requires `nonce == g_scalar_multiply(randomizer)`; that is the
    /// relation [`AleoAccount::generate_record_view_key`] relies on, so the
    /// randomizer is chosen here rather than invented.
    fn encrypted_record(account: &AleoAccount, microcredits: u64, rng: &mut TestRng) -> String {
        let randomizer = Scalar::rand(rng);
        let nonce = TestnetV0::g_scalar_multiply(&randomizer);
        let owner = Owner::Private(Plaintext::from(Literal::Address(account.address)));
        let mut data = IndexMap::new();
        data.insert(
            Identifier::from_str("microcredits").unwrap(),
            Entry::Private(Plaintext::from_str(&format!("{microcredits}u64")).unwrap()),
        );
        let plaintext = Record::<TestnetV0, Plaintext<TestnetV0>>::from_plaintext(
            owner,
            data,
            nonce,
            U8::new(0),
        )
        .unwrap();
        plaintext.encrypt(randomizer).unwrap().to_string()
    }

    #[test]
    fn test_account_roundtrip() {
        let mut rng = TestRng::default();
        let account = AleoAccount::new_random(&mut rng).unwrap();
        let pk_str = account.private_key_str();
        let recovered = AleoAccount::from_private_key_str(&pk_str).unwrap();
        assert_eq!(account.address, recovered.address);
    }

    #[test]
    fn test_account_chain_consistent() {
        let mut rng = TestRng::default();
        let account = AleoAccount::new_random(&mut rng).unwrap();
        assert!(account.address_str().starts_with("aleo1"));
    }

    #[test]
    fn test_new_encrypted_roundtrip() {
        let mut rng = TestRng::default();
        let password = "test-password-123";
        let (original, ciphertext) = AleoAccount::new_encrypted(password, &mut rng).unwrap();

        // Decrypt and verify
        let recovered = AleoAccount::from_ciphertext(&ciphertext, password).unwrap();
        assert_eq!(original.address, recovered.address);
        assert_eq!(original.private_key_str(), recovered.private_key_str());
    }

    #[test]
    fn test_encrypt_existing_key() {
        let mut rng = TestRng::default();
        let account = AleoAccount::new_random(&mut rng).unwrap();
        let password = "another-password";

        let ciphertext = account.encrypt_private_key(password).unwrap();
        let recovered = AleoAccount::from_ciphertext(&ciphertext, password).unwrap();
        assert_eq!(account.address, recovered.address);
    }

    #[test]
    fn test_encrypt_wrong_password_fails() {
        let mut rng = TestRng::default();
        let (_, ciphertext) = AleoAccount::new_encrypted("right-password", &mut rng).unwrap();
        let result = AleoAccount::from_ciphertext(&ciphertext, "wrong-password");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_valid_address() {
        let mut rng = TestRng::default();
        let account = AleoAccount::new_random(&mut rng).unwrap();
        let addr = account.address_str();

        assert!(AleoAccount::is_valid_address(&addr));
        assert!(!AleoAccount::is_valid_address("not_an_address"));
        assert!(!AleoAccount::is_valid_address("aleo1"));
        assert!(!AleoAccount::is_valid_address(""));
    }

    #[test]
    fn test_destroy_overwrites_keys() {
        let mut rng = TestRng::default();
        let mut account = AleoAccount::new_random(&mut rng).unwrap();
        let original_pk = account.private_key_str();

        account.destroy();

        // After destroy, the private key should be different
        let destroyed_pk = account.private_key_str();
        assert_ne!(
            original_pk, destroyed_pk,
            "destroy() did not overwrite private key"
        );
    }

    #[test]
    fn test_ciphertext_format() {
        let mut rng = TestRng::default();
        let password = "format-test";
        let (_, ciphertext) = AleoAccount::new_encrypted(password, &mut rng).unwrap();

        // Check prefix
        assert!(ciphertext.starts_with(CIPHERTEXT_PREFIX));

        // Check hex body has valid length (salt + nonce + at least some encrypted data)
        let hex_body = &ciphertext[CIPHERTEXT_PREFIX.len()..];
        let decoded = hex::decode(hex_body).unwrap();
        assert!(decoded.len() > SALT_LEN + NONCE_LEN);
    }

    #[test]
    fn test_encrypted_ciphertext_different_each_time() {
        let mut rng = TestRng::default();
        let password = "same-password";
        let (_, c1) = AleoAccount::new_encrypted(password, &mut rng).unwrap();

        let mut rng2 = TestRng::default();
        let (_, c2) = AleoAccount::new_encrypted(password, &mut rng2).unwrap();

        // Different accounts → different ciphertexts
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_from_ciphertext_invalid_format() {
        let result = AleoAccount::from_ciphertext("not-a-valid-ciphertext", "password");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_valid_address_known_good() {
        let good = "aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px";
        assert!(AleoAccount::is_valid_address(good));
    }

    // ── Seed recovery (JS: new Account({seed})) ─────────────────────────

    #[test]
    fn test_from_seed_is_deterministic() {
        // The exact 32-byte array the JS SDK docs feed to `new Account({seed})`.
        let seed = [
            94u8, 91, 52, 251, 240, 230, 226, 35, 117, 253, 224, 210, 175, 13, 205, 120, 155, 214,
            7, 169, 66, 62, 206, 50, 188, 40, 29, 122, 40, 250, 54, 18,
        ];
        let first = AleoAccount::from_seed(&seed).unwrap();
        let second = AleoAccount::from_seed(&seed).unwrap();
        assert_eq!(first.private_key_str(), second.private_key_str());
        assert_eq!(first.address, second.address);

        // The same seed must survive a round-trip through the private key string,
        // otherwise "recover from seed" and "recover from key" disagree.
        let reloaded = AleoAccount::from_private_key_str(&first.private_key_str()).unwrap();
        assert_eq!(reloaded.address, first.address);

        // A different seed must not collide.
        let mut other_seed = seed;
        other_seed[0] ^= 0xFF;
        let other = AleoAccount::from_seed(&other_seed).unwrap();
        assert_ne!(other.address, first.address);
    }

    #[test]
    fn test_from_seed_requires_exactly_32_bytes() {
        // JS `PrivateKey.from_seed_unchecked` unwraps the `try_into`, i.e. it
        // panics. We return an error instead — but the length rule is the same.
        assert!(AleoAccount::from_seed(&[0u8; 31]).is_err());
        assert!(AleoAccount::from_seed(&[0u8; 33]).is_err());
        assert!(AleoAccount::from_seed(&[]).is_err());
        assert!(AleoAccount::from_seed(&[0u8; 32]).is_ok());
    }

    // ── Record decryption and per-record view keys ──────────────────────

    #[test]
    fn test_record_view_key_decrypts_to_the_same_plaintext() {
        let mut rng = TestRng::default();
        let account = AleoAccount::new_random(&mut rng).unwrap();
        let ciphertext = encrypted_record(&account, 2_000_000, &mut rng);

        // Path A: snarkVM's own checked decryption.
        let via_decrypt = account.decrypt_record(&ciphertext).unwrap();

        // Path B: our derived record view key + symmetric decryption. If the
        // derivation were wrong (swapped operands, y instead of x coordinate),
        // this would not reproduce path A — the two paths share no code.
        let record_view_key = account.generate_record_view_key(&ciphertext).unwrap();
        let encrypted = RecordCiphertext::from_str(&ciphertext).unwrap();
        let via_view_key = encrypted.decrypt_symmetric_unchecked(&record_view_key).unwrap();

        assert_eq!(via_decrypt, via_view_key);
        // And the amount really is the one we encrypted, so both paths cannot
        // agree on garbage.
        let entry = via_decrypt.data().get(&Identifier::from_str("microcredits").unwrap());
        assert_eq!(entry.unwrap().to_string(), "2000000u64.private");
    }

    #[test]
    fn test_records_belonging_to_someone_else_are_rejected() {
        let mut rng = TestRng::default();
        let owner = AleoAccount::new_random(&mut rng).unwrap();
        let stranger = AleoAccount::new_random(&mut rng).unwrap();
        let ciphertext = encrypted_record(&owner, 1_000_000, &mut rng);

        assert!(owner.owns_record_ciphertext(&ciphertext));
        assert!(!stranger.owns_record_ciphertext(&ciphertext));

        let err = stranger.decrypt_record(&ciphertext).unwrap_err().to_string();
        assert!(
            err.contains("cannot be decrypted"),
            "unexpected error: {err}"
        );

        let err = stranger.generate_record_view_key(&ciphertext).unwrap_err().to_string();
        assert!(
            err.contains("does not belong to this account"),
            "unexpected error: {err}"
        );

        // Malformed input is "not ours", not an abort — a caller filtering a
        // list of ciphertexts must not have to pre-validate them.
        assert!(!owner.owns_record_ciphertext("not a ciphertext"));
        assert!(owner.decrypt_record("not a ciphertext").is_err());
        assert!(owner.generate_record_view_key("not a ciphertext").is_err());
    }

    #[test]
    fn test_decrypt_records_fails_fast_on_a_foreign_ciphertext() {
        let mut rng = TestRng::default();
        let account = AleoAccount::new_random(&mut rng).unwrap();
        let stranger = AleoAccount::new_random(&mut rng).unwrap();

        let mine_a = encrypted_record(&account, 100, &mut rng);
        let mine_b = encrypted_record(&account, 200, &mut rng);
        let theirs = encrypted_record(&stranger, 300, &mut rng);

        // All ours: order preserved, every record decrypts.
        let all_mine = account.decrypt_records([mine_a.as_str(), mine_b.as_str()]).unwrap();
        assert_eq!(all_mine.len(), 2);
        let amounts: Vec<String> = all_mine
            .iter()
            .map(|r| {
                r.data()
                    .get(&Identifier::from_str("microcredits").unwrap())
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(amounts, ["100u64.private", "200u64.private"]);

        // One foreign record in the middle: the error names its position, so a
        // caller can tell "the whole list is bad" from "item 1 is bad".
        let err = account
            .decrypt_records([mine_a.as_str(), theirs.as_str(), mine_b.as_str()])
            .unwrap_err();
        let chain = format!("{err:#}");
        assert!(chain.contains("#1"), "unexpected error chain: {chain}");
    }

    // ── Transition view keys ────────────────────────────────────────────

    #[test]
    fn test_transition_view_key_agrees_with_address_arithmetic() {
        let mut rng = TestRng::default();
        let account = AleoAccount::new_random(&mut rng).unwrap();
        let stranger = AleoAccount::new_random(&mut rng).unwrap();

        // A real transition public key has the form `tpk = r·G`.
        let randomizer = Scalar::rand(&mut rng);
        let tpk = TestnetV0::g_scalar_multiply(&randomizer);
        let derived = account.generate_transition_view_key(&tpk.to_string()).unwrap();

        // Independent formulation: `tpk · vk == address · r`, because
        // `address == vk·G`. Same point, computed from a different operand.
        let expected = (*account.address * randomizer).to_x_coordinate();
        assert_eq!(derived, expected);

        // A different account derives a different key from the same `tpk`.
        let other = stranger.generate_transition_view_key(&tpk.to_string()).unwrap();
        assert_ne!(derived, other);
    }

    #[test]
    fn test_transition_view_key_rejects_a_non_group() {
        let mut rng = TestRng::default();
        let account = AleoAccount::new_random(&mut rng).unwrap();
        let err = account.generate_transition_view_key("aleo1notagroup").unwrap_err().to_string();
        assert!(err.contains("Invalid transition public key"), "{err}");
    }

    // ── Signing ─────────────────────────────────────────────────────────

    #[test]
    fn test_sign_and_verify() {
        let mut rng = TestRng::default();
        let account = AleoAccount::new_random(&mut rng).unwrap();
        let stranger = AleoAccount::new_random(&mut rng).unwrap();
        let message = b"hello world";

        let signature = account.sign(message, &mut rng).unwrap();
        assert!(account.verify(message, &signature));

        // A signature is bound to the message...
        assert!(!account.verify(b"hello world!", &signature));
        // ...and to the key that produced it.
        assert!(!stranger.verify(message, &signature));

        // Aleo signatures are randomized: two signatures over the same message
        // differ and both verify. Identical signatures would mean `sign` is not
        // consuming the RNG it takes.
        let again = account.sign(message, &mut rng).unwrap();
        assert_ne!(signature.to_string(), again.to_string());
        assert!(account.verify(message, &again));
    }

    // ── Accessors and disposal ──────────────────────────────────────────

    #[test]
    fn test_string_accessors_and_display() {
        let mut rng = TestRng::default();
        let account = AleoAccount::new_random(&mut rng).unwrap();

        assert!(account.view_key_str().starts_with("AViewKey1"));
        // `Display` is the address, never the private key — this is what makes it
        // safe to interpolate an account into a log line.
        assert_eq!(account.to_string(), account.address_str());
        assert!(!account.to_string().contains(&account.private_key_str()));

        // The bech32 view key must parse back to the same address.
        let from_vk = ViewKey::<TestnetV0>::from_str(&account.view_key_str()).unwrap();
        assert_eq!(from_vk.to_address(), account.address);
    }

    #[test]
    fn test_destroy_replaces_the_whole_key_chain() {
        let mut rng = TestRng::default();
        let mut account = AleoAccount::new_random(&mut rng).unwrap();
        let before = (
            account.private_key_str(),
            account.view_key_str(),
            account.address_str(),
        );

        account.destroy();

        let after = (
            account.private_key_str(),
            account.view_key_str(),
            account.address_str(),
        );
        // Every field must move together: a stale view key or address would still
        // point at the destroyed account.
        assert_ne!(before.0, after.0);
        assert_ne!(before.1, after.1);
        assert_ne!(before.2, after.2);

        // The replacement chain must be internally consistent.
        let rederived = AleoAccount::from_private_key_str(&account.private_key_str()).unwrap();
        assert_eq!(rederived.address, account.address);
        assert_eq!(rederived.view_key, account.view_key);
    }

    #[test]
    fn test_destroy_yields_distinct_keys() {
        // `destroy` must never install a *fixed* replacement key: a zeroed or
        // hardcoded seed would leave every destroyed account sharing one key.
        let mut rng = TestRng::default();
        let mut a = AleoAccount::new_random(&mut rng).unwrap();
        let mut b = AleoAccount::new_random(&mut rng).unwrap();
        a.destroy();
        b.destroy();
        assert_ne!(a.private_key_str(), b.private_key_str());
    }
}
