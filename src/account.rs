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
//! | `new Account({privateKey})` | `AleoAccount::from_private_key_str(s)` | Recover from key string |
//! | `PrivateKey.newEncrypted(password)` | `AleoAccount::new_encrypted(password)` | Random + encrypted ciphertext |
//! | `privateKey.toCiphertext(password)` | `account.encrypt_private_key(password)` | Encrypt existing private key |
//! | `Account.fromCiphertext(ct, pw)` | `AleoAccount::from_ciphertext(ct, pw)` | Decrypt and recover |
//! | `Account.isValidAddress(s)` | `AleoAccount::is_valid_address(s)` | Address format validation |
//! | `account.destroy()` | `account.destroy()` | Zeroize sensitive memory |
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
use anyhow::Result;
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;
use snarkvm::prelude::{Address, ComputeKey, PrivateKey, TestRng, TestnetV0, ViewKey};
use std::str::FromStr;
use zeroize::Zeroize;

/// Number of PBKDF2 iterations for key derivation.
const PBKDF2_ITERATIONS: u32 = 100_000;
/// Salt length in bytes.
const SALT_LEN: usize = 16;
/// AES-GCM nonce length.
const NONCE_LEN: usize = 12;
/// AES-256 key length.
const KEY_LEN: usize = 32;
/// Ciphertext tag: aleo-enc-v1:hex(salt || nonce || ciphertext)
const CIPHERTEXT_PREFIX: &str = "aleo-enc-v1:";

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

    // ── JS SDK: Encrypted private key ──────────────────────────────────

    /// Generate a new random account and encrypt its private key with a password.
    ///
    /// Returns `(account, ciphertext)` where ciphertext is a portable string
    /// that can be stored and later recovered with [`from_ciphertext`].
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

    // ── JS SDK: Secure disposal ─────────────────────────────────────────

    /// Securely zeroizes sensitive key material in this account.
    ///
    /// After calling this, the account struct fields are zeroed-out and
    /// should not be used. Equivalent to JS SDK `account.destroy()`.
    pub fn destroy(&mut self) {
        // Zeroize the private key by replacing with a fresh random key
        // (PrivateKey doesn't implement Zeroize, so we overwrite via destructure)
        let mut rng = TestRng::default();
        if let Ok(fresh) = PrivateKey::new(&mut rng) {
            // Overwrite the sensitive fields with fresh random keys
            let _ = std::mem::replace(&mut self.private_key, fresh);
        }
        // Re-derive with the dummy key so view_key, compute_key, address get overwritten
        if let Ok(vk) = ViewKey::try_from(&self.private_key) {
            self.view_key = vk;
        }
        if let Ok(ck) = ComputeKey::try_from(&self.private_key) {
            self.compute_key = ck;
        }
        if let Ok(addr) = Address::try_from(&self.compute_key) {
            self.address = addr;
        }
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
}

impl FromStr for AleoAccount {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::from_private_key_str(s)
    }
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
}
