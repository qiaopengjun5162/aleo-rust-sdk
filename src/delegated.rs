//! # Delegated proving — Provable's Delegated Proving Service (DPS).
//!
//! Local proving is the expensive half of an Aleo transaction: a single
//! `credits.aleo/transfer_public` proof costs tens of seconds of CPU on a laptop
//! (see `tests/real_prove.rs`). Delegated proving moves that work to a prover
//! running inside a TEE: the request is encrypted to an ephemeral key the
//! prover just minted, decrypted only inside the enclave, and the resulting
//! [`Transaction`] comes back ready to broadcast.
//!
//! ## Wire protocol
//!
//! The prover speaks three endpoints, all relative to a per-network base such
//! as `https://prover.provable.prove/testnet`:
//!
//! | Endpoint | Method | Purpose |
//! |----------|--------|---------|
//! | `/pubkey` | GET | One-time X25519 public key: `{key_id, public_key}` |
//! | `/prove/authorization` | POST | Encrypted [`ProvingRequest`] → transaction |
//! | `/prove/request` | POST | Signed-request variant (not implemented here) |
//!
//! `key_id` and the ciphertext are single-use: a retry must fetch a fresh
//! `/pubkey` first, which is why [`DelegatedProver`] never retries on its own
//! (silently re-submitting could broadcast the same transaction twice).
//!
//! ## Byte formats (verified against the reference client, not guessed)
//!
//! The plaintext inside the sealed box is **little-endian binary**, not JSON:
//!
//! ```text
//! authorization.write_le() ‖ u8(has_fee_authorization)
//!                         [‖ fee_authorization.write_le()] ‖ u8(broadcast)
//! ```
//!
//! The envelope is libsodium's `crypto_box_seal`:
//!
//! ```text
//! ephemeral_public_key(32) ‖ poly1305_tag(16) ‖ ciphertext
//! nonce = BLAKE2b-192(ephemeral_public_key ‖ recipient_public_key)
//! ```
//!
//! Both are checked by tests: the tag-before-ciphertext ordering and the
//! 24-byte BLAKE2b digest are the two details that silently produce
//! ciphertext the prover cannot open.
//!
//! ## Verification status
//!
//! Offline: the byte layout, the sealed box (against a libsodium-generated
//! known-answer vector), and the HTTP shape (against a mock server).
//! **Live end-to-end needs a Provable credential** — see [`ApiAuth`].
//!
//! ## Example
//!
//! ```no_run
//! use aleo_rust_sdk::delegated::{ApiAuth, DelegatedProver, ProvingRequest};
//!
//! # async fn run(authorization: snarkvm::prelude::Authorization<snarkvm::prelude::TestnetV0>) -> anyhow::Result<()> {
//! // `none` is correct for the unauthenticated edge gateway; use
//! // `ApiAuth::api_key(..)` or `ApiAuth::jwt(..)` when the prover asks for it.
//! let prover = DelegatedProver::new("testnet", ApiAuth::None)?;
//!
//! let request = ProvingRequest::new(authorization, None, false);
//! let response = prover.submit_authorization(&request).await?;
//! println!("proved: {}", response.transaction.id());
//! # Ok(())
//! # }
//! ```

use anyhow::{Context, Result, bail};
use reqwest::header::{CONTENT_TYPE, COOKIE, SET_COOKIE};
use serde::Deserialize;
use snarkvm::ledger::block::Transaction;
use snarkvm::prelude::{Authorization, TestnetV0};
use snarkvm::utilities::{FromBytes, ToBytes};
use std::fmt;
use std::io::Cursor;
use zeroize::Zeroizing;

use crate::hosted::{AuthProvider, REQUEST_TIMEOUT, session_cookie, truncate};

// Re-exported so `delegated::ApiAuth` (and its documented paths) keep working
// now that the envelope is shared with [`crate::scanner`].
pub use crate::hosted::{ApiAuth, EphemeralKey};

/// Default prover host. The per-network path segment is appended by
/// [`DelegatedProver::new`].
const DEFAULT_PROVER_HOST: &str = "https://prover.provable.prove";
/// Origin that mints JWTs for the legacy `api.provable.com` gateway.
const DEFAULT_API_ORIGIN: &str = "https://api.provable.com";

// ── Proving request ──────────────────────────────────────────────────────

/// A proving request in the `Authorization` variant.
///
/// The `Request` variant (a signed `Request` that the prover authorizes
/// server-side) is deliberately not modelled: it only supports
/// single-public-request executions, and this SDK's [`authorize`] path always
/// produces a full `Authorization`.
///
/// [`authorize`]: crate::ExecutionEngine::authorize_and_execute
#[derive(Clone)]
pub struct ProvingRequest {
    /// Authorization for the function call being proved.
    pub authorization: Authorization<TestnetV0>,
    /// Optional authorization of `credits.aleo/fee_public` (or `fee_private`).
    ///
    /// Leave as `None` only when the prover is configured to pay the fee on
    /// your behalf (a "fee master"); otherwise attach one built with
    /// [`ExecutionEngine::authorize_fee_public_authorization`].
    ///
    /// [`ExecutionEngine::authorize_fee_public_authorization`]:
    ///     crate::ExecutionEngine::authorize_fee_public_authorization
    pub fee_authorization: Option<Authorization<TestnetV0>>,
    /// Ask the prover to broadcast the transaction itself.
    ///
    /// When `false` the transaction comes back un-broadcast and the caller
    /// submits it through [`AleoClient`](crate::AleoClient).
    pub broadcast: bool,
}

impl ProvingRequest {
    /// Build a proving request from an authorization.
    pub fn new(
        authorization: Authorization<TestnetV0>,
        fee_authorization: Option<Authorization<TestnetV0>>,
        broadcast: bool,
    ) -> Self {
        Self {
            authorization,
            fee_authorization,
            broadcast,
        }
    }

    /// Serialize to the exact bytes the DPS expects inside the sealed box.
    ///
    /// The returned buffer holds private inputs, so it is zeroized on drop —
    /// the prover is the only party that should ever hold this plaintext.
    pub fn to_bytes_le(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Vec::new();
        self.authorization
            .write_le(&mut out)
            .context("Failed to serialize authorization")?;
        match &self.fee_authorization {
            Some(fee) => {
                true.write_le(&mut out).context("Failed to serialize fee flag")?;
                fee.write_le(&mut out).context("Failed to serialize fee authorization")?;
            }
            None => false.write_le(&mut out).context("Failed to serialize fee flag")?,
        }
        self.broadcast
            .write_le(&mut out)
            .context("Failed to serialize broadcast flag")?;
        Ok(Zeroizing::new(out))
    }

    /// Parse bytes produced by [`ProvingRequest::to_bytes_le`].
    ///
    /// Trailing bytes are rejected: a length mismatch means the reader and the
    /// writer disagree about the layout, and silently ignoring the tail would
    /// hide exactly that bug.
    pub fn from_bytes_le(bytes: &[u8]) -> Result<Self> {
        let mut reader = Cursor::new(bytes);
        let authorization = Authorization::<TestnetV0>::read_le(&mut reader)
            .context("Failed to read authorization")?;
        let has_fee = bool::read_le(&mut reader).context("Failed to read fee flag")?;
        let fee_authorization = if has_fee {
            Some(
                Authorization::<TestnetV0>::read_le(&mut reader)
                    .context("Failed to read fee authorization")?,
            )
        } else {
            None
        };
        let broadcast = bool::read_le(&mut reader).context("Failed to read broadcast flag")?;

        let consumed = reader.position() as usize;
        if consumed != bytes.len() {
            bail!(
                "Trailing bytes after proving request: consumed {consumed} of {}",
                bytes.len()
            );
        }
        Ok(Self {
            authorization,
            fee_authorization,
            broadcast,
        })
    }
}

impl fmt::Debug for ProvingRequest {
    /// Never print the inner authorizations — they carry the private inputs of
    /// the call. Length plus the fee/broadcast flags are enough to debug.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProvingRequest")
            .field("requests", &self.authorization.len())
            .field("has_fee_authorization", &self.fee_authorization.is_some())
            .field("broadcast", &self.broadcast)
            .finish()
    }
}

// ── Sealed box ───────────────────────────────────────────────────────────

/// Encrypt `plaintext` to a base64 X25519 public key using libsodium's
/// sealed-box construction.
///
/// Returns base64 of `ephemeral_pk ‖ tag ‖ ciphertext`. The ephemeral key is
/// generated per call from the OS RNG, so the same request encrypted twice
/// produces different ciphertexts — which is what makes the one-time `key_id`
/// meaningful.
pub fn seal_for_prover(recipient_public_key_b64: &str, plaintext: &[u8]) -> Result<String> {
    crate::hosted::seal_sealed_box(recipient_public_key_b64, plaintext)
}

// ── HTTP client ──────────────────────────────────────────────────────────

/// What the prover reports about the broadcast it performed.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct BroadcastResult {
    /// e.g. `"accepted"`. Kept as a plain string: the prover may add states
    /// and rejecting unknown values would break on their next release.
    #[serde(default)]
    pub status: Option<String>,
}

/// A proved transaction, plus broadcast info when `broadcast` was requested.
#[derive(Clone, Debug, Deserialize)]
pub struct ProvingResponse {
    /// The transaction the prover produced. Broadcast it yourself unless you
    /// set [`ProvingRequest::broadcast`].
    pub transaction: Transaction<TestnetV0>,
    /// Present only when the request asked the prover to broadcast.
    #[serde(default)]
    pub broadcast_result: Option<BroadcastResult>,
}

impl ProvingResponse {
    /// Whether the prover reports it broadcast the transaction.
    ///
    /// `true` here means "the prover says it submitted", **not** "it is
    /// confirmed on chain" — confirmation still requires polling the network.
    pub fn prover_broadcast(&self) -> bool {
        self.broadcast_result.is_some()
    }
}

/// Client for the Delegated Proving Service.
pub struct DelegatedProver {
    http: reqwest::Client,
    /// Per-network prover base, e.g. `https://prover.provable.prove/testnet`.
    prover_base: String,
    /// Credentials for both `/pubkey` and the encrypted POST.
    auth: AuthProvider,
}

impl DelegatedProver {
    /// Build a client for `network` (`"testnet"` or `"mainnet"`) against
    /// Provable's hosted prover.
    pub fn new(network: &str, auth: ApiAuth) -> Result<Self> {
        if network.is_empty() {
            bail!("Network name must not be empty");
        }
        Self::with_endpoints(
            format!("{DEFAULT_PROVER_HOST}/{network}"),
            DEFAULT_API_ORIGIN,
            auth,
        )
    }

    /// Build a client against explicit endpoints.
    ///
    /// `prover_base` must already include the network segment. Useful for a
    /// self-hosted prover and for tests.
    pub fn with_endpoints(
        prover_base: impl Into<String>,
        api_origin: impl Into<String>,
        auth: ApiAuth,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(crate::network::BROWSER_UA)
            .build()
            .context("Failed to build HTTP client")?;
        Ok(Self {
            prover_base: prover_base.into().trim_end_matches('/').to_string(),
            auth: AuthProvider::new(http.clone(), api_origin, auth),
            http,
        })
    }

    /// Fetch a one-time encryption key from the prover.
    ///
    /// The second return value is the `Set-Cookie` value when the prover sent
    /// one; it must be echoed on the follow-up POST so the prover can pair the
    /// two calls.
    pub async fn fetch_pubkey(&self) -> Result<(EphemeralKey, Option<String>)> {
        let headers = self.auth_headers().await?;
        self.fetch_pubkey_with(&headers).await
    }

    /// Fetch a one-time key using an already-resolved header set.
    async fn fetch_pubkey_with(
        &self,
        headers: &[(String, String)],
    ) -> Result<(EphemeralKey, Option<String>)> {
        let mut request = self.http.get(format!("{}/pubkey", self.prover_base));
        for (name, value) in headers {
            request = request.header(name, value);
        }

        let response = request.send().await.context("DPS /pubkey request failed")?;
        let status = response.status();
        let cookie = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .next()
            .and_then(|value| value.to_str().ok())
            .map(session_cookie);

        let body = response.text().await.context("Failed to read /pubkey body")?;
        if !status.is_success() {
            bail!("DPS /pubkey returned {status}: {}", truncate(&body));
        }

        let key: EphemeralKey =
            serde_json::from_str(&body).context("Failed to parse /pubkey response")?;
        Ok((key, cookie))
    }

    /// Encrypt a proving request and submit it to `/prove/authorization`.
    ///
    /// # Errors
    ///
    /// Fails if the prover rejects the request (bad auth, spent `key_id`,
    /// malformed ciphertext) or returns a body that is not a transaction. No
    /// automatic retry: the key is single-use and re-submitting could
    /// double-broadcast.
    pub async fn submit_authorization(&self, request: &ProvingRequest) -> Result<ProvingResponse> {
        // Resolve auth once so a token refresh cannot happen twice in one call.
        let headers = self.auth_headers().await?;
        let (key, cookie) = self.fetch_pubkey_with(&headers).await?;

        let plaintext = request.to_bytes_le()?;
        let ciphertext = seal_for_prover(&key.public_key, &plaintext)?;

        let payload = serde_json::json!({
            "key_id": key.key_id,
            "ciphertext": ciphertext,
        });
        self.post_encrypted(
            "/prove/authorization",
            &headers,
            cookie.as_deref(),
            &payload,
        )
        .await
    }

    /// POST an already-encrypted payload to `path` (relative to the prover base).
    ///
    /// Exposed so callers that manage their own key/encryption (or that target
    /// `/prove/request`) can reuse the transport and auth plumbing.
    pub async fn post_encrypted(
        &self,
        path: &str,
        headers: &[(String, String)],
        cookie: Option<&str>,
        payload: &serde_json::Value,
    ) -> Result<ProvingResponse> {
        let mut request = self
            .http
            .post(format!("{}{}", self.prover_base, path))
            .header(CONTENT_TYPE, "application/json")
            .json(payload);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if let Some(cookie) = cookie {
            request = request.header(COOKIE, cookie);
        }

        let response = request.send().await.context("DPS prove request failed")?;
        let status = response.status();
        let body = response.text().await.context("Failed to read prove response body")?;

        if !status.is_success() {
            bail!("DPS {path} returned {status}: {}", truncate(&body));
        }
        serde_json::from_str(&body).context("Failed to parse prove response")
    }

    /// Resolve the auth headers for one request, minting a JWT when needed.
    pub async fn auth_headers(&self) -> Result<Vec<(String, String)>> {
        self.auth.headers().await
    }
}

impl fmt::Debug for DelegatedProver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DelegatedProver")
            .field("prover_base", &self.prover_base)
            .field("auth", &self.auth)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    /// X25519 key pair used by the vector in [`crate::hosted`]; reused here so
    /// the DPS-facing wrapper is exercised with the same bytes.
    const RECIPIENT_PUBLIC_KEY_B64: &str = "j0DFrbaPJWJK5bIU6nZ6bslNgp09e14a0bpvPiE4KF8=";
    const RECIPIENT_SECRET_SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    #[test]
    fn seal_for_prover_round_trips() {
        let secret = crypto_box::SecretKey::from(RECIPIENT_SECRET_SEED);
        let sealed = seal_for_prover(RECIPIENT_PUBLIC_KEY_B64, b"proving request").unwrap();
        let raw = BASE64.decode(sealed).unwrap();
        // libsodium layout: 32-byte ephemeral key + 16-byte tag + ciphertext.
        assert_eq!(raw.len(), 32 + 16 + b"proving request".len());
        assert_eq!(secret.unseal(&raw).unwrap(), b"proving request");
    }

    #[test]
    fn seal_uses_a_fresh_ephemeral_key_each_time() {
        let a = seal_for_prover(RECIPIENT_PUBLIC_KEY_B64, b"same input").unwrap();
        let b = seal_for_prover(RECIPIENT_PUBLIC_KEY_B64, b"same input").unwrap();
        assert_ne!(a, b, "each call must mint a new ephemeral key");
    }

    #[test]
    fn seal_rejects_wrong_length_public_key() {
        let err = seal_for_prover(&BASE64.encode([0u8; 16]), b"x").unwrap_err().to_string();
        assert!(err.contains("32 bytes"), "unexpected error: {err}");
    }

    #[test]
    fn seal_rejects_non_base64_public_key() {
        assert!(seal_for_prover("not*base64", b"x").is_err());
    }
}
