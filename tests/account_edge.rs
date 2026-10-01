use aleo_rust_sdk::AleoAccount;

/// Coverage: invalid private key error path — uses private key string
#[test]
fn test_account_from_invalid_private_key() {
    let result = AleoAccount::from_private_key_str("not_a_valid_key");
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("Invalid private") || err.contains("invalid"));
}

/// Coverage: zero-length private key
#[test]
fn test_account_from_empty_private_key() {
    let result = AleoAccount::from_private_key_str("");
    assert!(result.is_err());
}

/// Coverage: account from valid private key string roundtrip
#[test]
fn test_account_from_valid_private_key() {
    use snarkvm::prelude::TestRng;
    let mut rng = TestRng::default();
    let orig = AleoAccount::new_random(&mut rng).unwrap();
    let pk_str = orig.private_key_str();
    let result = AleoAccount::from_private_key_str(&pk_str);
    assert!(result.is_ok());
    let acc = result.unwrap();
    assert_eq!(acc.private_key_str(), pk_str);
}
