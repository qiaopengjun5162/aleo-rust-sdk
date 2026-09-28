/// Aleo Account — key management for Aleo blockchain accounts.
///
/// Wraps snarkVM account primitives with a safe, ergonomic API.
/// Key chain: `PrivateKey → ViewKey → ComputeKey → Address`.

use anyhow::Result;
use snarkvm::prelude::{
    Address, ComputeKey, PrivateKey, TestRng, TestnetV0, ViewKey,
};
use std::str::FromStr;

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
    fn from_private_key(private_key: PrivateKey<TestnetV0>) -> Self {
        let view_key = ViewKey::try_from(&private_key).expect("view key derivation");
        let compute_key = ComputeKey::try_from(&private_key).expect("compute key derivation");
        let address = Address::try_from(&compute_key).expect("address derivation");
        Self { private_key, view_key, compute_key, address }
    }

    /// Create an account from a private key string (bech32).
    pub fn from_private_key_str(key_str: &str) -> Result<Self> {
        let private_key = PrivateKey::from_str(key_str)
            .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
        Ok(Self::from_private_key(private_key))
    }

    /// Generate a new random account.
    pub fn new_random(rng: &mut TestRng) -> Result<Self> {
        let private_key = PrivateKey::new(rng)?;
        Ok(Self::from_private_key(private_key))
    }

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
}
