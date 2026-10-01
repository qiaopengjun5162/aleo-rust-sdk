use aleo_rust_sdk::AleoAccount;
use std::str::FromStr as _;

/// Cover FromStr impl (line 56-58) — roundtrip from generated key
#[test]
fn test_account_from_str_trait() {
    use snarkvm::prelude::TestRng;
    let mut rng = TestRng::default();
    let orig = AleoAccount::new_random(&mut rng).unwrap();
    let pk_str = orig.private_key_str();
    let acc = AleoAccount::from_str(&pk_str).unwrap();
    assert_eq!(acc.address_str(), orig.address_str());
}

/// Cover from_private_key_str error path
#[test]
fn test_account_from_private_key_str_invalid() {
    let r = AleoAccount::from_private_key_str("garbage");
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("Invalid private"));
}

/// Use address_str and private_key_str
#[test]
fn test_account_methods() {
    let mut rng = snarkvm::prelude::TestRng::default();
    let acc = AleoAccount::new_random(&mut rng).unwrap();
    assert!(!acc.address_str().is_empty());
    assert!(!acc.private_key_str().is_empty());
}
