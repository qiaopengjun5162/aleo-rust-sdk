//! Circle USDCx shielded-mint hook data.
//!
//! Mirrors the JS SDK's `generateHookData`
//! (`sdk/src/integrations/circle/hook-data.ts`). A Circle USDCx shielded mint
//! carries a 65-byte hook-data blob:
//!
//! | Bytes  | Contents                                                        |
//! |--------|-----------------------------------------------------------------|
//! | `0`    | Version tag, always [`HOOK_DATA_VERSION`] (`2`).                |
//! | `1..33`| BHP256 commitment over the recipient address's plaintext bits,  |
//! |        | with the secret nonce as randomizer (32 bytes, little-endian).  |
//! | `33..65`| Zero padding.                                                  |
//!
//! The commitment uses the **typed plaintext bits** of the address, not the raw
//! field bits: JS passes `Plaintext.fromString(address).toBitsLe()` to
//! `BHP256.commit`, and [`Plaintext::to_bits_le`] has the same semantics here
//! (literal variant tag plus the literal's little-endian bits), so the two
//! produce the same commitment for the same address.
//!
//! # Example
//!
//! ```
//! use aleo_rust_sdk::circle::{generate_hook_data, HOOK_DATA_LEN};
//! use snarkvm::prelude::TestnetV0;
//!
//! let hook_data = generate_hook_data::<TestnetV0>(
//!     "aleo1r5fwayr4vhaz2mgyuqg7qer3apunn2zefe7m9cle94rar0dwcgyq6hg9ze",
//!     "0scalar",
//! )
//! .unwrap();
//! assert_eq!(hook_data.len(), HOOK_DATA_LEN);
//! assert_eq!(hook_data[0], 2);
//! ```

use snarkvm::prelude::{FromStr, Network, Plaintext, Result, Scalar, ToBits, ToBytes};

/// Total length of the hook data blob, in bytes.
///
/// The JS SDK allocates `new Uint8Array(65)` and only fills the first 33 bytes.
pub const HOOK_DATA_LEN: usize = 65;

/// Version tag stored in byte 0. The JS SDK hardcodes `hookData[0] = 2`.
pub const HOOK_DATA_VERSION: u8 = 2;

/// Length of the BHP256 commitment, in bytes.
pub const HOOK_DATA_COMMITMENT_LEN: usize = 32;

/// Offset where the commitment starts: right after the version tag.
pub const HOOK_DATA_COMMITMENT_OFFSET: usize = 1;

/// Recipient address hardcoded in the JS SDK's `constants.ts` for its own test.
pub const HOOK_DATA_RECIPIENT: &str =
    "aleo1r5fwayr4vhaz2mgyuqg7qer3apunn2zefe7m9cle94rar0dwcgyq6hg9ze";

/// Secret nonce hardcoded in the JS SDK's `constants.ts` (`Scalar` zero).
pub const SECRET_NONCE: &str = "0scalar";

/// Builds the 65-byte hook data for a Circle USDCx shielded mint.
///
/// This is the Rust equivalent of the JS `generateHookData(recipient, secretNonce)`.
///
/// # Arguments
/// * `recipient` - The recipient's bech32m-encoded Aleo address.
/// * `secret_nonce` - The nonce scalar, in snarkVM's `"<decimal>scalar"` form.
///
/// # Returns
/// A fixed 65-byte array: version tag, 32-byte BHP256 commitment, zero padding.
///
/// # Errors
/// Returns an error if either string fails to parse, or if the commitment
/// cannot be produced (for example when the plaintext bits exceed BHP256's
/// 256-bit input limit).
pub fn generate_hook_data<N: Network>(
    recipient: &str,
    secret_nonce: &str,
) -> Result<[u8; HOOK_DATA_LEN]> {
    let recipient = Plaintext::<N>::from_str(recipient)?;
    let randomizer = Scalar::<N>::from_str(secret_nonce)?;

    let commitment = N::commit_bhp256(&recipient.to_bits_le(), &randomizer)?;
    let commitment_bytes = commitment.to_bytes_le()?;

    // BHP256 commitments are always 32 bytes; fail loudly rather than silently
    // shifting the zero padding if that ever changes.
    if commitment_bytes.len() != HOOK_DATA_COMMITMENT_LEN {
        return Err(anyhow::anyhow!(
            "expected a {HOOK_DATA_COMMITMENT_LEN}-byte BHP256 commitment, got {}",
            commitment_bytes.len()
        ));
    }

    let mut hook_data = [0u8; HOOK_DATA_LEN];
    hook_data[0] = HOOK_DATA_VERSION;
    hook_data[HOOK_DATA_COMMITMENT_OFFSET..HOOK_DATA_COMMITMENT_OFFSET + HOOK_DATA_COMMITMENT_LEN]
        .copy_from_slice(&commitment_bytes);
    Ok(hook_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::{Address, TestnetV0, ToField, Zero};

    type N = TestnetV0;

    /// The JS test only checks the length and the version byte; pin those plus
    /// the zero padding, which the JS code gets implicitly from `Uint8Array`.
    #[test]
    fn hook_data_matches_js_shape() {
        let hook_data = generate_hook_data::<N>(HOOK_DATA_RECIPIENT, SECRET_NONCE).unwrap();

        assert_eq!(hook_data.len(), HOOK_DATA_LEN);
        assert_eq!(hook_data[0], HOOK_DATA_VERSION);
        assert_eq!(hook_data[0], 2);
        assert!(
            hook_data[HOOK_DATA_COMMITMENT_OFFSET + HOOK_DATA_COMMITMENT_LEN..]
                .iter()
                .all(|byte| *byte == 0),
            "bytes 33..65 must stay zero"
        );
    }

    /// Snapshot of the commitment for the JS SDK's constant recipient/nonce.
    ///
    /// The upstream test does not pin the commitment, so this value was produced
    /// by this implementation and is here to catch an accidental recipe change.
    #[test]
    fn hook_data_commitment_is_pinned() {
        let hook_data = generate_hook_data::<N>(HOOK_DATA_RECIPIENT, SECRET_NONCE).unwrap();
        let commitment = &hook_data
            [HOOK_DATA_COMMITMENT_OFFSET..HOOK_DATA_COMMITMENT_OFFSET + HOOK_DATA_COMMITMENT_LEN];

        assert_eq!(
            hex_encode(commitment),
            "4d2789e2802bdf53eece01292ffcc9db2cfff37400c15418567ef2e351a5a60a"
        );
    }

    /// `"0scalar"` really is the zero scalar, so the JS constant is not a typo.
    #[test]
    fn secret_nonce_is_zero_scalar() {
        let parsed = Scalar::<N>::from_str(SECRET_NONCE).unwrap();
        assert_eq!(parsed, Scalar::<N>::zero());
    }

    /// Changing the nonce or the recipient must change the commitment. Without
    /// this, a broken implementation that ignored its arguments would still
    /// pass the shape test.
    #[test]
    fn commitment_depends_on_both_inputs() {
        let base = generate_hook_data::<N>(HOOK_DATA_RECIPIENT, SECRET_NONCE).unwrap();

        let other_nonce = generate_hook_data::<N>(HOOK_DATA_RECIPIENT, "1scalar").unwrap();
        assert_ne!(
            base[HOOK_DATA_COMMITMENT_OFFSET
                ..HOOK_DATA_COMMITMENT_OFFSET + HOOK_DATA_COMMITMENT_LEN],
            other_nonce[HOOK_DATA_COMMITMENT_OFFSET
                ..HOOK_DATA_COMMITMENT_OFFSET + HOOK_DATA_COMMITMENT_LEN]
        );

        let other_recipient = generate_hook_data::<N>(
            "aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px",
            SECRET_NONCE,
        )
        .unwrap();
        assert_ne!(
            base[HOOK_DATA_COMMITMENT_OFFSET
                ..HOOK_DATA_COMMITMENT_OFFSET + HOOK_DATA_COMMITMENT_LEN],
            other_recipient[HOOK_DATA_COMMITMENT_OFFSET
                ..HOOK_DATA_COMMITMENT_OFFSET + HOOK_DATA_COMMITMENT_LEN]
        );
    }

    /// The commitment covers the address's **typed plaintext bits**, not its raw
    /// field bits. JS feeds `Plaintext.toBitsLe()` to `BHP256.commit`, so a
    /// future refactor that "simplifies" this to `Address::to_field().to_bits_le()`
    /// would produce a different on-chain commitment. This pins the distinction.
    #[test]
    fn commitment_uses_plaintext_bits_not_field_bits() {
        let randomizer = Scalar::<N>::zero();

        let plaintext = Plaintext::<N>::from_str(HOOK_DATA_RECIPIENT).unwrap();
        let from_plaintext = N::commit_bhp256(&plaintext.to_bits_le(), &randomizer).unwrap();

        let address = Address::<N>::from_str(HOOK_DATA_RECIPIENT).unwrap();
        let from_field = N::commit_bhp256(&address.to_field().unwrap().to_bits_le(), &randomizer)
            .expect("a field is well under BHP256's 256-bit limit");

        assert_ne!(from_plaintext, from_field);
    }

    #[test]
    fn rejects_malformed_inputs() {
        assert!(generate_hook_data::<N>("not-an-address", SECRET_NONCE).is_err());
        assert!(generate_hook_data::<N>(HOOK_DATA_RECIPIENT, "not-a-scalar").is_err());
        assert!(generate_hook_data::<N>(HOOK_DATA_RECIPIENT, "0").is_err());
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
