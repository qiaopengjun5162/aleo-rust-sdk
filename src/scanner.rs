//! # Record scanning — Provable's Record Scanning Service (RSS).
//!
//! Aleo records are ciphertexts on chain: finding yours means trying your view
//! key against every record ever created. [`crate::record::RecordScanner`] does
//! that locally, one `records/all` page at a time — correct, but O(chain).
//!
//! The RSS does the same work inside a TEE: you register a **view key,
//! encrypted to an ephemeral key the service just minted**, it indexes the
//! ledger once, and afterwards you query by a `uuid` it gave you. The view key
//! is only ever decrypted inside the enclave, and the service returns records,
//! not your key.
//!
//! ## Wire protocol
//!
//! All routes are relative to a per-network base such as
//! `https://api.provable.com/scanner/testnet`:
//!
//! | Route | Method | Body | Response |
//! |-------|--------|------|----------|
//! | `/pubkey` | GET | — | `{key_id, public_key}` |
//! | `/register/encrypted` | POST | `{key_id, ciphertext}` | `{uuid, status?}` |
//! | `/records/owned` | POST | `{uuid, unspent?, filter?, responseFilter?}` | array of records |
//! | `/records/encrypted` | POST | `RecordsFilter` | array of encrypted records |
//! | `/records/sns` | POST | `[serial_number, …]` | `{sn: bool}` spent map |
//! | `/records/tags` | POST | `[tag, …]` | `{tag: bool}` spent map |
//! | `/status` | POST | `"<uuid>"` (bare JSON string) | `{synced, percentage}` |
//! | `/revoke` | POST | `"<uuid>"` (bare JSON string) | — |
//!
//! The last three are read-only ledger queries that do **not** need a
//! registered `uuid`: `/records/encrypted` scans the whole ledger for encrypted
//! records matching a filter, while `/records/sns` and `/records/tags` are
//! double-spend probes — they report only whether a serial number or tag has
//! appeared in any on-chain transition input, so they leak nothing about which
//! records are *yours*. A `true` in either map means the record has been spent.
//!
//! Two of those are worth flagging because the published guide disagrees:
//! `/status` and `/revoke` take a **bare JSON string**, not `{"uuid": ...}`.
//! The guide also omits that `/records/owned` may answer either with an array or
//! with `{"data": [...]}`; both are accepted here.
//!
//! ## Parity with the JS `RecordScanner`
//!
//! [`compute_uuid`] reproduces the JS `computeUUID(viewKey)`: a Poseidon4 hash
//! of the `"RecordScannerV0"` domain separator, the view key as a field, and
//! `1field`. It is what the service returns as `uuid` on registration, so it
//! lets a caller derive the identifier offline (e.g. to validate a stored one).
//!
//! The JS `findRecord` / `findCreditsRecord` / `findCreditsRecords` helpers are
//! provided as methods on [`RecordScanService`]. Unlike the JS SDK they take
//! the `uuid` and the [`ViewKey`] explicitly instead of storing them on the
//! client: a view key is too sensitive to keep alive for the lifetime of an
//! HTTP client, and local decryption ([`OwnedRecord::decrypt`]) means the
//! service never has to return a plaintext we would then have to distrust.
//!
//! Note the two credits helpers filter **differently**: `find_credits_record`
//! takes the first record with *at least* the requested amount, while
//! `find_credits_records` keeps records whose amount *exactly equals* one of
//! the supplied amounts. That asymmetry is in the JS SDK too.
//!
//! ## Registration plaintext
//!
//! The sealed box contains little-endian binary, not JSON:
//!
//! ```text
//! view_key.write_le() ‖ u32(start_block).to_le_bytes()
//! ```
//!
//! The intermediate buffer is zeroized after encryption, matching the reference
//! client: a view key left in a heap allocation is the same secret as one left
//! in a string.
//!
//! ## Trust boundary
//!
//! The service tells you *which* records it thinks are yours, and it could be
//! wrong or malicious. [`OwnedRecord::decrypt`] therefore decrypts the returned
//! `record_ciphertext` locally with your view key and ignores any
//! `record_plaintext` the response carries: a plaintext you did not compute is
//! a claim, not a fact. Records that fail local decryption are rejected, so a
//! forged response cannot smuggle in a spendable-looking record.
//!
//! ## Example
//!
//! ```no_run
//! use aleo_rust_sdk::hosted::ApiAuth;
//! use aleo_rust_sdk::scanner::RecordScanService;
//! use snarkvm::prelude::ViewKey;
//! use std::str::FromStr;
//!
//! # async fn run() -> anyhow::Result<()> {
//! let service = RecordScanService::new("testnet", ApiAuth::None)?;
//! let view_key = ViewKey::from_str("AViewKey1...")?;
//!
//! let registration = service.register(&view_key, 0).await?;
//! let owned = service.records_owned(&registration.uuid, Default::default()).await?;
//! for record in &owned {
//!     let decrypted = record.decrypt(&view_key)?;
//!     println!("{} microcredits", decrypted.microcredits);
//! }
//! # Ok(())
//! # }
//! ```

use anyhow::{Context, Result, bail};
use reqwest::header::{CONTENT_TYPE, COOKIE, SET_COOKIE};
use serde::{Deserialize, Serialize};
use snarkvm::prelude::{Field, Network, One, TestnetV0, ToField, ViewKey};
use snarkvm::utilities::ToBytes;
use std::collections::HashMap;
use std::fmt;
use zeroize::Zeroizing;

use crate::hosted::{ApiAuth, AuthProvider, EphemeralKey, session_cookie, truncate};
use crate::record::{AleoRecord, RecordScanner};

// The endpoint constants live in `options` so that this module and
// [`crate::delegated`] cannot drift apart: both used to declare their own copy
// of the JWT origin.
use crate::options::PROVABLE_SCANNER_BASE;

// ── Registration ─────────────────────────────────────────────────────────

/// What the scanner returns once a view key is registered.
#[derive(Clone, Debug, Deserialize)]
pub struct Registration {
    /// Identifier to quote on every later query.
    ///
    /// Despite the field name this is a Aleo `field` literal (e.g.
    /// `"529124…2391field"`), not a RFC 4122 UUID.
    pub uuid: String,
    /// Scanner-side job handle, when the service reports one.
    #[serde(default)]
    pub job_id: Option<String>,
    /// Job state, e.g. `"pending"`. Absent on some deployments.
    #[serde(default)]
    pub status: Option<String>,
}

/// Encrypt a view key (plus the block to start scanning from) for the scanner.
///
/// The plaintext is `view_key.write_le() ‖ u32(start_block)` in little-endian,
/// sealed to `recipient_public_key_b64` with libsodium's `crypto_box_seal`.
///
/// The two buffers that hold the view key are zeroized before returning, so a
/// core dump or a swapped-out page cannot leak the key after the call.
pub fn seal_registration(
    recipient_public_key_b64: &str,
    view_key: &ViewKey<TestnetV0>,
    start_block: u32,
) -> Result<String> {
    let view_key_bytes =
        Zeroizing::new(view_key.to_bytes_le().context("Failed to encode view key")?);

    let mut plaintext = Zeroizing::new(Vec::with_capacity(view_key_bytes.len() + 4));
    plaintext.extend_from_slice(&view_key_bytes);
    plaintext.extend_from_slice(&start_block.to_le_bytes());

    crate::hosted::seal_sealed_box(recipient_public_key_b64, &plaintext)
}

// ── UUID ─────────────────────────────────────────────────────────────────

/// Domain separator the JS SDK hashes into a scanner UUID (`RECORD_DOMAIN`).
const RECORD_SCANNER_DOMAIN: &str = "RecordScannerV0";

/// Derive the record-scanner `uuid` for `view_key` (JS `computeUUID`).
///
/// The JS SDK computes `Poseidon4.hash([Field.newDomainSeparator(
/// "RecordScannerV0"), viewKey.toField(), Field.one()])`. snarkVM exposes the
/// same three primitives as [`Field::new_domain_separator`], [`ToField::to_field`]
/// and [`Network::hash_psd4`], so this produces the same `field` literal that
/// the service returns as `uuid` on registration — without a round trip.
///
/// # Errors
///
/// Fails if the view key cannot be represented as a field element or the hash
/// itself fails.
pub fn compute_uuid(view_key: &ViewKey<TestnetV0>) -> Result<Field<TestnetV0>> {
    let domain = Field::<TestnetV0>::new_domain_separator(RECORD_SCANNER_DOMAIN);
    let view_key_field = view_key
        .to_field()
        .map_err(|error| anyhow::anyhow!("Failed to convert view key to a field: {error}"))?;
    TestnetV0::hash_psd4(&[domain, view_key_field, Field::one()])
        .map_err(|error| anyhow::anyhow!("Failed to compute record scanner UUID: {error}"))
}

// ── Encrypted-record scan filter ─────────────────────────────────────────

/// Which fields `/records/encrypted` should include in each returned record.
///
/// Every field is opt-in: a `Some(true)` includes that column, anything else
/// omits it. Mirrors the JS `RecordsResponseFilter`.
#[derive(Clone, Debug, Default, Serialize)]
pub struct RecordsResponseFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_timestamp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_ciphertext: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_ciphertext: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_name: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_index: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_name: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_name: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition_id: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_index: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition_index: Option<bool>,
}

/// Server-side filter for `/records/encrypted` (JS `RecordsFilter`).
///
/// Unlike [`OwnedFilter`] this is a ledger-wide scan, not a per-`uuid` query, so
/// it carries no `uuid`. Only the set fields are sent: unset ones are omitted
/// from the request rather than serialized as `null`, matching the JS SDK.
#[derive(Clone, Debug, Default, Serialize)]
pub struct EncryptedRecordsFilter {
    /// Restrict to records whose commitment is in this list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitments: Option<Vec<String>>,
    /// Which columns to include in each returned record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<RecordsResponseFilter>,
    /// Lowest block height to scan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<u32>,
    /// Highest block height to scan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<u32>,
    /// Restrict to these programs, e.g. `["credits.aleo"]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub programs: Option<Vec<String>>,
    /// Restrict to records with these names, e.g. `["credits"]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub records: Option<Vec<String>>,
    /// Restrict to records produced by these functions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub functions: Option<Vec<String>>,
    /// Page size for paginated scans.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results_per_page: Option<u32>,
    /// Page offset for paginated scans.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
}

// ── Queries ──────────────────────────────────────────────────────────────

/// Which fields `/records/owned` should include in each returned record.
///
/// Mirrors the JS `OwnedRecordsResponseFilter`: every column is opt-in, and
/// only `Some(true)` fields are requested. The field set deliberately differs
/// from [`RecordsResponseFilter`] — the encrypted-ledger scan exposes
/// `checksum` / `nonce` / `sender_ciphertext` but no `tag` / `sender` / `spent`.
#[derive(Clone, Debug, Default, Serialize)]
pub struct OwnedRecordsResponseFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_ciphertext: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_timestamp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_index: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_name: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_name: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_name: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition_id: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_index: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition_index: Option<bool>,
}

/// Filter applied server-side by `/records/owned`.
///
/// `unspent` is the only filter that changes *correctness* (spending a spent
/// record fails on chain), so it is the one the builders make obvious.
///
/// Only the fields that are set are sent; unset ones are omitted from the
/// request rather than serialized as `null`.
#[derive(Clone, Debug, Default)]
pub struct OwnedFilter {
    /// Ask the scanner to omit spent records.
    pub unspent: Option<bool>,
    /// Restrict to one program, e.g. `"credits.aleo"`.
    pub program: Option<String>,
    /// Restrict to one record name, e.g. `"credits"`.
    pub record: Option<String>,
    /// Lowest block height to scan (JS `filter.start`).
    pub start: Option<u32>,
    /// Which columns the response should include (JS `responseFilter`).
    pub response_filter: Option<OwnedRecordsResponseFilter>,
}

impl OwnedFilter {
    /// Only records the scanner has not seen spent.
    pub fn unspent() -> Self {
        Self {
            unspent: Some(true),
            ..Default::default()
        }
    }

    /// Restrict to `program`, e.g. `"credits.aleo"`.
    pub fn program(mut self, program: impl Into<String>) -> Self {
        self.program = Some(program.into());
        self
    }

    /// Restrict to records named `record`, e.g. `"credits"`.
    pub fn record_name(mut self, record: impl Into<String>) -> Self {
        self.record = Some(record.into());
        self
    }

    /// Start scanning at `start` (JS `filter.start`).
    pub fn start(mut self, start: u32) -> Self {
        self.start = Some(start);
        self
    }

    /// Ask for only the columns enabled in `response_filter` (JS
    /// `responseFilter`).
    pub fn response_filter(mut self, response_filter: OwnedRecordsResponseFilter) -> Self {
        self.response_filter = Some(response_filter);
        self
    }
}

/// The `/records/owned` request body.
///
/// Built once here rather than assembled inline so the unit test and the live
/// call cannot disagree: a filter that is silently dropped client-side looks
/// exactly like a filter the server ignored.
fn owned_payload(uuid: &str, filter: &OwnedFilter) -> serde_json::Value {
    let mut payload = serde_json::json!({ "uuid": uuid });

    if let Some(unspent) = filter.unspent {
        payload["unspent"] = serde_json::Value::Bool(unspent);
    }

    // `filter` is omitted entirely when nothing is set, rather than sent as an
    // empty object: an empty filter is not obviously a no-op to the service.
    if filter.program.is_some() || filter.record.is_some() || filter.start.is_some() {
        let mut inner = serde_json::Map::new();
        if let Some(program) = &filter.program {
            inner.insert("program".into(), program.clone().into());
        }
        if let Some(record) = &filter.record {
            inner.insert("record".into(), record.clone().into());
        }
        if let Some(start) = filter.start {
            inner.insert("start".into(), start.into());
        }
        payload["filter"] = serde_json::Value::Object(inner);
    }

    // The JS SDK sends this as camelCase `responseFilter`; deriving Serialize
    // on OwnedFilter would produce `response_filter`, so insert it explicitly.
    // Only Option<bool> fields are involved, so serialization cannot fail.
    if let Some(response_filter) = &filter.response_filter {
        payload["responseFilter"] = serde_json::to_value(response_filter)
            .expect("OwnedRecordsResponseFilter is always serializable");
    }

    payload
}

/// A record the scanner attributes to a registered view key.
///
/// Every field is optional because the service's JSON is not guaranteed to carry
/// all of them; [`OwnedRecord::decrypt`] needs only `record_ciphertext`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct OwnedRecord {
    /// Height of the block that created the record.
    #[serde(default)]
    pub block_height: Option<u32>,
    /// Unix timestamp of that block.
    #[serde(default)]
    pub block_timestamp: Option<i64>,
    /// Record commitment.
    #[serde(default)]
    pub commitment: Option<String>,
    /// Function that produced the record.
    #[serde(default)]
    pub function_name: Option<String>,
    /// Index of the output within that function call.
    #[serde(default)]
    pub output_index: Option<u32>,
    /// Owner, as the scanner reports it (may be a ciphertext).
    #[serde(default)]
    pub owner: Option<String>,
    /// Program that created the record, e.g. `"credits.aleo"`.
    #[serde(default)]
    pub program_name: Option<String>,
    /// Encrypted record — the only field [`OwnedRecord::decrypt`] trusts.
    #[serde(default)]
    pub record_ciphertext: Option<String>,
    /// Plaintext, when the service chose to include it. Never trusted; see the
    /// module docs on the trust boundary.
    #[serde(default)]
    pub record_plaintext: Option<String>,
    /// Record name, e.g. `"credits"`.
    #[serde(default)]
    pub record_name: Option<String>,
    /// Sender, when the program records one.
    #[serde(default)]
    pub sender: Option<String>,
    /// Whether the scanner has seen this record spent.
    ///
    /// `None` means **unknown**, not "unspent". Treating unknown as unspent is
    /// how a caller ends up building a transaction around a record that is
    /// already gone, so the field stays three-valued rather than defaulting.
    #[serde(default)]
    pub spent: Option<bool>,
    /// Record tag.
    #[serde(default)]
    pub tag: Option<String>,
    /// Transaction that created the record.
    #[serde(default)]
    pub transaction_id: Option<String>,
    /// Transition that created the record.
    #[serde(default)]
    pub transition_id: Option<String>,
    /// Index of the transaction within its block.
    #[serde(default)]
    pub transaction_index: Option<u32>,
    /// Index of the transition within its transaction.
    #[serde(default)]
    pub transition_index: Option<u32>,
}

impl OwnedRecord {
    /// Decrypt this record locally with `view_key`.
    ///
    /// Returns an [`AleoRecord`] whose `program_id` comes from `program_name`
    /// when present.
    ///
    /// `AleoRecord::spent` is a `bool`, so an unreported spend status becomes
    /// `false` here. That is **not** evidence the record is unspent: to be sure,
    /// ask the scanner for unspent records only ([`OwnedFilter::unspent`]) and
    /// treat [`OwnedRecord::spent`] as the authoritative three-valued answer.
    ///
    /// # Errors
    ///
    /// Fails when the response carried no ciphertext, when the ciphertext does
    /// not parse, or when it does not belong to `view_key`. A record that fails
    /// here should be dropped rather than retried: it is either not yours or
    /// forged.
    pub fn decrypt(&self, view_key: &ViewKey<TestnetV0>) -> Result<AleoRecord> {
        let ciphertext = self
            .record_ciphertext
            .as_deref()
            .context("OwnedRecord carried no record_ciphertext")?;

        let (microcredits, data) = RecordScanner::decrypt_record_parts(ciphertext, view_key)
            .with_context(|| {
                format!(
                    "Record from {} could not be decrypted with this view key",
                    self.program_name.as_deref().unwrap_or("<unknown program>")
                )
            })?;

        Ok(AleoRecord {
            program_id: self.program_name.clone().unwrap_or_default(),
            owner: view_key.to_address(),
            microcredits,
            data,
            ciphertext: ciphertext.to_string(),
            spent: self.spent.unwrap_or(false),
        })
    }
}

/// An encrypted record as returned by `/records/encrypted`.
///
/// Unlike [`OwnedRecord`] this carries the ledger ciphertext and metadata but no
/// decryption: the caller decrypts locally (the same trust boundary as
/// [`OwnedRecord::decrypt`]) rather than trusting a plaintext the service
/// attached. `commitment` is the only mandatory field; the rest mirror the JS
/// `EncryptedRecord` type.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct EncryptedRecord {
    /// Record commitment.
    pub commitment: String,
    /// Checksum of the record.
    #[serde(default)]
    pub checksum: Option<String>,
    /// Height of the block that created the record.
    #[serde(default)]
    pub block_height: Option<u32>,
    /// Unix timestamp of that block.
    #[serde(default)]
    pub block_timestamp: Option<i64>,
    /// Program that created the record, e.g. `"credits.aleo"`.
    #[serde(default)]
    pub program_name: Option<String>,
    /// Function that produced the record.
    #[serde(default)]
    pub function_name: Option<String>,
    /// Index of the output within that function call.
    #[serde(default)]
    pub output_index: Option<u32>,
    /// Owner ciphertext.
    #[serde(default)]
    pub owner: Option<String>,
    /// Record ciphertext — the field to decrypt locally.
    #[serde(default)]
    pub record_ciphertext: Option<String>,
    /// Record name, e.g. `"credits"`.
    #[serde(default)]
    pub record_name: Option<String>,
    /// Record nonce.
    #[serde(default)]
    pub record_nonce: Option<String>,
    /// Sender ciphertext.
    #[serde(default)]
    pub sender_ciphertext: Option<String>,
    /// Transaction that created the record.
    #[serde(default)]
    pub transaction_id: Option<String>,
    /// Transition that created the record.
    #[serde(default)]
    pub transition_id: Option<String>,
    /// Index of the transaction within its block.
    #[serde(default)]
    pub transaction_index: Option<u32>,
    /// Index of the transition within its transaction.
    #[serde(default)]
    pub transition_index: Option<u32>,
}

/// Scan progress for a registered view key.
#[derive(Clone, Debug, Deserialize)]
pub struct ScanStatus {
    /// Whether the initial scan has caught up with the chain tip.
    pub synced: bool,
    /// Completion percentage as reported by the service (0–100).
    #[serde(default)]
    pub percentage: f64,
}

// ── Errors ───────────────────────────────────────────────────────────────

/// Marker: the scanner no longer recognises the `uuid` (HTTP 422).
///
/// The prescribed recovery is to register again and retry once. This is a
/// distinct type rather than a string match so callers can branch on it:
///
/// ```no_run
/// # use anyhow::Error;
/// # fn handle(err: &Error) -> bool {
/// err.downcast_ref::<aleo_rust_sdk::scanner::StaleRegistration>().is_some()
/// # }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct StaleRegistration;

impl fmt::Display for StaleRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "record scanner rejected the uuid (HTTP 422); register the view key again"
        )
    }
}

impl std::error::Error for StaleRegistration {}

// ── Client ───────────────────────────────────────────────────────────────

/// Client for the Record Scanning Service.
pub struct RecordScanService {
    http: reqwest::Client,
    /// Per-network scanner base, e.g. `https://api.provable.com/scanner/testnet`.
    scanner_base: String,
    auth: AuthProvider,
}

impl RecordScanService {
    /// Build a client for `network` (`"testnet"` or `"mainnet"`) against
    /// Provable's hosted scanner.
    pub fn new(network: &str, auth: ApiAuth) -> Result<Self> {
        if network.is_empty() {
            bail!("Network name must not be empty");
        }
        Self::with_endpoints(
            format!("{PROVABLE_SCANNER_BASE}/{network}"),
            crate::options::PROVABLE_API_ORIGIN,
            auth,
        )
    }

    /// Build a client against explicit endpoints.
    ///
    /// `scanner_base` must already include the network segment. Useful for a
    /// self-hosted scanner and for tests.
    pub fn with_endpoints(
        scanner_base: impl Into<String>,
        api_origin: impl Into<String>,
        auth: ApiAuth,
    ) -> Result<Self> {
        Self::with_endpoints_and_http(scanner_base, api_origin, auth, None)
    }

    /// Build a client against explicit endpoints, optionally reusing an
    /// already-built HTTP client.
    ///
    /// `http: None` builds one with the TEE timeout and browser User-Agent;
    /// `Some` uses the supplied client verbatim, which is how
    /// [`AleoNetworkOptions`](crate::AleoNetworkOptions) gives proving and
    /// scanning one shared connection pool.
    pub fn with_endpoints_and_http(
        scanner_base: impl Into<String>,
        api_origin: impl Into<String>,
        auth: ApiAuth,
        http: Option<reqwest::Client>,
    ) -> Result<Self> {
        let http = match http {
            Some(http) => http,
            None => crate::hosted::hosted_http_client()?,
        };
        Ok(Self {
            scanner_base: scanner_base.into().trim_end_matches('/').to_string(),
            auth: AuthProvider::new(http.clone(), api_origin, auth),
            http,
        })
    }

    /// The base URL requests are sent to.
    pub fn scanner_base(&self) -> &str {
        &self.scanner_base
    }

    /// Register `view_key` and return the `uuid` to query with.
    ///
    /// `start_block` bounds how far back the scanner looks; `0` means genesis.
    /// A later `start_block` registers faster but misses older records.
    pub async fn register(
        &self,
        view_key: &ViewKey<TestnetV0>,
        start_block: u32,
    ) -> Result<Registration> {
        // Resolve auth once: the mint/publish pair must share one token.
        let headers = self.auth.headers().await?;
        let (key, cookie) = self.fetch_pubkey_with(&headers).await?;

        let ciphertext = seal_registration(&key.public_key, view_key, start_block)?;
        let payload = serde_json::json!({
            "key_id": key.key_id,
            "ciphertext": ciphertext,
        });

        let body = self
            .post_json(
                "/register/encrypted",
                &headers,
                cookie.as_deref(),
                &payload,
                &[],
            )
            .await?;
        serde_json::from_str(&body).context("Failed to parse /register/encrypted response")
    }

    /// Fetch the records the scanner attributes to `uuid`.
    ///
    /// # Errors
    ///
    /// A 422 means the `uuid` is no longer valid (the service dropped the
    /// registration, or it expired): the error downcasts to
    /// [`StaleRegistration`]. Re-register and retry once — do not retry blindly,
    /// since a stale uuid stays stale.
    pub async fn records_owned(&self, uuid: &str, filter: OwnedFilter) -> Result<Vec<OwnedRecord>> {
        let headers = self.auth.headers().await?;
        let payload = owned_payload(uuid, &filter);

        let body = self.post_json("/records/owned", &headers, None, &payload, &[422]).await?;
        parse_owned_records(&body)
    }

    /// Return the first record matching `filter` (JS `findRecord`).
    ///
    /// # Errors
    ///
    /// Propagates [`RecordScanService::records_owned`] errors, and fails with
    /// `Record not found` when the scanner returned an empty list.
    pub async fn find_record(&self, uuid: &str, filter: OwnedFilter) -> Result<OwnedRecord> {
        let records = self.records_owned(uuid, filter).await?;
        records.into_iter().next().context("Record not found")
    }

    /// Return the first `credits.aleo` record holding *at least* `microcredits`
    /// (JS `findCreditsRecord`).
    ///
    /// `view_key` is used only locally: ciphertexts are decrypted in-process,
    /// so a `record_plaintext` supplied by the service is never trusted.
    /// Records that fail to decrypt are skipped, exactly as the JS SDK skips
    /// records without a usable plaintext.
    ///
    /// # Errors
    ///
    /// Propagates the `/records/owned` errors; fails when no record holds the
    /// requested amount.
    pub async fn find_credits_record(
        &self,
        uuid: &str,
        microcredits: u64,
        view_key: &ViewKey<TestnetV0>,
        filter: OwnedFilter,
    ) -> Result<OwnedRecord> {
        let records = self.credits_records(uuid, view_key, filter).await?;
        records
            .into_iter()
            .find(|(_, amount)| *amount >= microcredits)
            .map(|(record, _)| record)
            .with_context(|| {
                format!("No credits.aleo record with at least {microcredits} microcredits")
            })
    }

    /// Return records whose amount *exactly equals* one of
    /// `microcredit_amounts` (JS `findCreditsRecords`).
    ///
    /// Unlike [`RecordScanService::find_credits_record`] this is an exact
    /// membership test, and an empty result is not an error.
    ///
    /// # Errors
    ///
    /// Propagates the `/records/owned` errors.
    pub async fn find_credits_records(
        &self,
        uuid: &str,
        microcredit_amounts: &[u64],
        view_key: &ViewKey<TestnetV0>,
        filter: OwnedFilter,
    ) -> Result<Vec<OwnedRecord>> {
        let records = self.credits_records(uuid, view_key, filter).await?;
        Ok(records
            .into_iter()
            .filter(|(_, amount)| microcredit_amounts.contains(amount))
            .map(|(record, _)| record)
            .collect())
    }

    /// Fetch `credits.aleo` records and decrypt their amounts locally.
    async fn credits_records(
        &self,
        uuid: &str,
        view_key: &ViewKey<TestnetV0>,
        filter: OwnedFilter,
    ) -> Result<Vec<(OwnedRecord, u64)>> {
        let mut filter = filter;
        // Both JS helpers hard-code credits.aleo/credits and default `unspent`
        // to true. Keep the caller's other fields (start, responseFilter).
        filter.program = Some("credits.aleo".to_string());
        filter.record = Some("credits".to_string());
        if filter.unspent.is_none() {
            filter.unspent = Some(true);
        }

        let records = self.records_owned(uuid, filter).await?;
        Ok(records
            .into_iter()
            .filter_map(|record| {
                let amount = record.decrypt(view_key).ok()?.microcredits;
                Some((record, amount))
            })
            .collect())
    }

    /// Ask how far the scan for `uuid` has progressed.
    pub async fn status(&self, uuid: &str) -> Result<ScanStatus> {
        let headers = self.auth.headers().await?;
        // Bare JSON string, *not* `{"uuid": ...}` — the guide is wrong here.
        let payload = serde_json::Value::String(uuid.to_string());
        let body = self.post_json("/status", &headers, None, &payload, &[422]).await?;
        serde_json::from_str(&body).context("Failed to parse /status response")
    }

    /// Drop the registration for `uuid`, so the scanner stops indexing.
    ///
    /// Worth calling when an account is retired: the scanner discards the
    /// decrypted view key on revocation.
    pub async fn revoke(&self, uuid: &str) -> Result<()> {
        let headers = self.auth.headers().await?;
        let payload = serde_json::Value::String(uuid.to_string());
        self.post_json("/revoke", &headers, None, &payload, &[422]).await?;
        Ok(())
    }

    /// Probe whether serial numbers have been spent.
    ///
    /// Posts the list to `/records/sns` and returns a map of each serial number
    /// to a `bool`. A `true` value means that serial number has appeared in an
    /// on-chain transition input, i.e. the record has been spent. This is a
    /// ledger-wide read that needs no registered `uuid` and leaks nothing about
    /// which records are yours.
    ///
    /// # Errors
    ///
    /// Fails on transport error, a non-2xx status, or a response body that is
    /// not a JSON object mapping strings to booleans.
    pub async fn serial_numbers(&self, serial_numbers: &[String]) -> Result<HashMap<String, bool>> {
        let headers = self.auth.headers().await?;
        let payload = serde_json::to_value(serial_numbers)
            .context("Failed to serialize serial number list")?;
        let body = self.post_json("/records/sns", &headers, None, &payload, &[]).await?;
        parse_string_bool_map(&body, "/records/sns")
    }

    /// Probe whether record tags have been spent.
    ///
    /// Posts the list to `/records/tags` and returns a map of each tag to a
    /// `bool`. A `true` value means a record carrying that tag has appeared in
    /// an on-chain transition input, i.e. has been spent. Like
    /// [`RecordScanService::serial_numbers`] this is a public, `uuid`-free read.
    ///
    /// # Errors
    ///
    /// Fails on transport error, a non-2xx status, or a response body that is
    /// not a JSON object mapping strings to booleans.
    pub async fn tags(&self, tags: &[String]) -> Result<HashMap<String, bool>> {
        let headers = self.auth.headers().await?;
        let payload = serde_json::to_value(tags).context("Failed to serialize tag list")?;
        let body = self.post_json("/records/tags", &headers, None, &payload, &[]).await?;
        parse_string_bool_map(&body, "/records/tags")
    }

    /// Scan the ledger for encrypted records matching `filter`.
    ///
    /// Unlike [`RecordScanService::records_owned`] this is a server-side scan of
    /// the whole ledger (no `uuid`), returning ciphertexts plus the metadata the
    /// filter requested. Decrypt locally with a [`ViewKey`] as needed; never
    /// trust a `record_plaintext` the service might attach.
    ///
    /// # Errors
    ///
    /// Fails on transport error, a non-2xx status, or a response body that is
    /// neither a JSON array of records nor `{"data": [...]}`.
    pub async fn encrypted(&self, filter: &EncryptedRecordsFilter) -> Result<Vec<EncryptedRecord>> {
        let headers = self.auth.headers().await?;
        let payload =
            serde_json::to_value(filter).context("Failed to serialize encrypted records filter")?;
        let body = self.post_json("/records/encrypted", &headers, None, &payload, &[]).await?;
        parse_encrypted_records(&body)
    }

    /// Fetch a one-time encryption key.
    ///
    /// The second return value is the `Set-Cookie` value when the scanner sent
    /// one; it must be echoed on the follow-up POST so the scanner can pair the
    /// two calls.
    pub async fn fetch_pubkey(&self) -> Result<(EphemeralKey, Option<String>)> {
        let headers = self.auth.headers().await?;
        self.fetch_pubkey_with(&headers).await
    }

    async fn fetch_pubkey_with(
        &self,
        headers: &[(String, String)],
    ) -> Result<(EphemeralKey, Option<String>)> {
        let mut request = self.http.get(format!("{}/pubkey", self.scanner_base));
        for (name, value) in headers {
            request = request.header(name, value);
        }

        let response = request.send().await.context("RSS /pubkey request failed")?;
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
            bail!("RSS /pubkey returned {status}: {}", truncate(&body));
        }

        let key: EphemeralKey =
            serde_json::from_str(&body).context("Failed to parse /pubkey response")?;
        Ok((key, cookie))
    }

    /// POST `payload` as JSON and return the response body.
    ///
    /// `stale_statuses` lists the status codes that should be reported as
    /// [`StaleRegistration`] rather than a generic transport error.
    async fn post_json(
        &self,
        path: &str,
        headers: &[(String, String)],
        cookie: Option<&str>,
        payload: &serde_json::Value,
        stale_statuses: &[u16],
    ) -> Result<String> {
        let mut request = self
            .http
            .post(format!("{}{}", self.scanner_base, path))
            .header(CONTENT_TYPE, "application/json")
            .json(payload);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if let Some(cookie) = cookie {
            request = request.header(COOKIE, cookie);
        }

        let response = request.send().await.context("RSS request failed")?;
        let status = response.status();
        let body = response.text().await.context("Failed to read RSS response body")?;

        if status.is_success() {
            return Ok(body);
        }
        if stale_statuses.contains(&status.as_u16()) {
            return Err(anyhow::Error::new(StaleRegistration)
                .context(format!("RSS {path} returned {status}: {}", truncate(&body))));
        }
        bail!("RSS {path} returned {status}: {}", truncate(&body));
    }
}

impl fmt::Debug for RecordScanService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordScanService")
            .field("scanner_base", &self.scanner_base)
            .field("auth", &self.auth)
            .finish_non_exhaustive()
    }
}

// ── helpers ──────────────────────────────────────────────────────────────

/// Accept both documented shapes: a bare array, or `{"data": [...]}`.
///
/// An object *without* a `data` array is an error, not an empty result. A
/// caller that sees `Ok(vec![])` concludes "this account owns nothing", so
/// guessing there turns an unrecognised response into a wrong balance — the
/// failure mode that looks like success.
fn parse_owned_records(body: &str) -> Result<Vec<OwnedRecord>> {
    let value: serde_json::Value =
        serde_json::from_str(body).context("Failed to parse /records/owned response")?;

    let array = match value {
        serde_json::Value::Array(items) => items,
        serde_json::Value::Object(mut map) => match map.remove("data") {
            Some(serde_json::Value::Array(items)) => items,
            None => {
                let mut keys: Vec<String> = map.keys().cloned().collect();
                keys.sort();
                bail!(
                    "RSS /records/owned returned an object with no `data` array (keys: [{}])",
                    keys.join(", ")
                )
            }
            Some(other) => {
                bail!(
                    "RSS /records/owned returned `data` as {}, expected an array",
                    json_kind(&other)
                )
            }
        },
        other => bail!(
            "RSS /records/owned returned {}, expected an array",
            json_kind(&other)
        ),
    };

    array
        .into_iter()
        .map(|item| serde_json::from_value(item).context("Failed to parse an owned record"))
        .collect()
}

fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// Accept both documented shapes for an array of records: a bare array, or
/// `{"data": [...]}`. Shared by `/records/owned` and `/records/encrypted` so the
/// two cannot drift apart — an object without a record array is an error, not an
/// empty result, because a caller that sees `Ok(vec![])` concludes "nothing
/// here", and guessing there turns an unrecognised response into a wrong answer.
fn parse_record_array<T: serde::de::DeserializeOwned>(
    body: &str,
    endpoint: &str,
) -> Result<Vec<T>> {
    let value: serde_json::Value = serde_json::from_str(body)
        .with_context(|| format!("Failed to parse {endpoint} response"))?;

    let array = match value {
        serde_json::Value::Array(items) => items,
        serde_json::Value::Object(mut map) => match map.remove("data") {
            Some(serde_json::Value::Array(items)) => items,
            None => {
                let mut keys: Vec<String> = map.keys().cloned().collect();
                keys.sort();
                bail!(
                    "RSS {endpoint} returned an object with no `data` array (keys: [{}])",
                    keys.join(", ")
                )
            }
            Some(other) => {
                bail!(
                    "RSS {endpoint} returned `data` as {}, expected an array",
                    json_kind(&other)
                )
            }
        },
        other => bail!(
            "RSS {endpoint} returned {}, expected an array",
            json_kind(&other)
        ),
    };

    array
        .into_iter()
        .map(|item| {
            serde_json::from_value(item)
                .with_context(|| format!("Failed to parse a record from {endpoint}"))
        })
        .collect()
}

/// Parse a `{key: bool, …}` map from `/records/sns` or `/records/tags`.
///
/// A bare array or any non-boolean value is rejected: a map of spent flags that
/// silently drops an entry would let a caller treat an unprobed serial number as
/// unspent.
fn parse_string_bool_map(body: &str, endpoint: &str) -> Result<HashMap<String, bool>> {
    let value: serde_json::Value = serde_json::from_str(body)
        .with_context(|| format!("Failed to parse {endpoint} response"))?;
    let object = match &value {
        serde_json::Value::Object(object) => object,
        other => bail!(
            "RSS {endpoint} returned {}, expected an object mapping keys to booleans",
            json_kind(other)
        ),
    };

    let mut map = HashMap::with_capacity(object.len());
    for (key, value) in object {
        match value {
            serde_json::Value::Bool(flag) => {
                map.insert(key.clone(), *flag);
            }
            other => bail!(
                "RSS {endpoint} key {key} was {}, expected a boolean",
                json_kind(other)
            ),
        }
    }
    Ok(map)
}

/// Parse a `/records/encrypted` response (bare array or `{"data": [...]}`).
fn parse_encrypted_records(body: &str) -> Result<Vec<EncryptedRecord>> {
    parse_record_array(body, "/records/encrypted")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use snarkvm::prelude::{PrivateKey, Zero};
    use snarkvm::utilities::rand::TestRng;

    fn view_key() -> ViewKey<TestnetV0> {
        let mut rng = TestRng::default();
        let private_key = PrivateKey::<TestnetV0>::new(&mut rng).unwrap();
        ViewKey::try_from(&private_key).unwrap()
    }

    /// The scanner parses exactly `view_key ‖ u32 LE (start_block)`; the start
    /// block is the only part that is easy to get wrong (big-endian would make
    /// the scan start in the wrong place, and the service cannot tell you).
    #[test]
    fn registration_plaintext_is_view_key_then_le_start_block() {
        let vk = view_key();
        let vk_bytes = vk.to_bytes_le().unwrap();
        let ours = crypto_box::SecretKey::from([5u8; 32]);
        let ours_b64 = BASE64.encode(ours.public_key().to_bytes());

        let sealed = seal_registration(&ours_b64, &vk, 0x0102_0304).unwrap();
        let raw = BASE64.decode(&sealed).unwrap();
        // libsodium layout: ephemeral key ‖ tag ‖ plaintext.
        assert_eq!(raw.len(), 32 + 16 + vk_bytes.len() + 4);

        let plaintext = ours.unseal(&raw).expect("sealed box must open");
        assert_eq!(&plaintext[..vk_bytes.len()], vk_bytes.as_slice());
        assert_eq!(
            &plaintext[vk_bytes.len()..],
            &0x0102_0304u32.to_le_bytes(),
            "start block must be little-endian"
        );

        // The start block must actually reach the scanner, not be dropped.
        let other = seal_registration(&ours_b64, &vk, 7).unwrap();
        let other_plaintext = ours.unseal(&BASE64.decode(other).unwrap()).unwrap();
        assert_ne!(other_plaintext, plaintext);
    }

    #[test]
    fn owned_payload_carries_only_the_filters_that_are_set() {
        let payload = owned_payload("uuid-1", &OwnedFilter::unspent().program("credits.aleo"));
        assert_eq!(payload["uuid"], "uuid-1");
        assert_eq!(payload["unspent"], serde_json::json!(true));
        assert_eq!(payload["filter"]["program"], "credits.aleo");
        assert!(
            payload["filter"].get("record").is_none(),
            "an unset filter must not be sent"
        );

        // No filters at all: no `unspent`, no `filter` object.
        let bare = owned_payload("uuid-1", &OwnedFilter::default());
        assert_eq!(bare, serde_json::json!({ "uuid": "uuid-1" }));
    }

    #[test]
    fn owned_payload_sends_start_and_camel_case_response_filter() {
        let response_filter = OwnedRecordsResponseFilter {
            commitment: Some(true),
            record_ciphertext: Some(true),
            ..Default::default()
        };
        let payload = owned_payload(
            "uuid-1",
            &OwnedFilter::unspent()
                .program("credits.aleo")
                .record_name("credits")
                .start(42)
                .response_filter(response_filter),
        );

        assert_eq!(payload["uuid"], "uuid-1");
        assert_eq!(payload["filter"]["start"], 42);
        assert_eq!(
            payload["responseFilter"],
            serde_json::json!({ "commitment": true, "record_ciphertext": true }),
            "only the set columns go on the wire, under the JS camelCase key"
        );
        assert!(
            payload.get("response_filter").is_none(),
            "the Rust field name must not leak onto the wire"
        );
        assert!(
            payload["filter"].get("end").is_none(),
            "start must not imply any other filter field"
        );

        // Unset: neither key appears at all (not even as an empty object).
        let bare = owned_payload("uuid-1", &OwnedFilter::default());
        assert!(bare.get("responseFilter").is_none());
        assert!(bare.get("filter").is_none());
    }

    #[test]
    fn compute_uuid_is_deterministic_and_view_key_specific() {
        let vk = view_key();
        let uuid = compute_uuid(&vk).unwrap();
        assert_eq!(compute_uuid(&vk).unwrap(), uuid, "same key, same uuid");

        // A second draw from the same deterministic RNG yields a different key.
        let mut rng = TestRng::default();
        let _ = PrivateKey::<TestnetV0>::new(&mut rng).unwrap();
        let other_pk = PrivateKey::<TestnetV0>::new(&mut rng).unwrap();
        let other_vk = ViewKey::try_from(&other_pk).unwrap();
        assert_ne!(vk, other_vk);
        assert_ne!(
            compute_uuid(&other_vk).unwrap(),
            uuid,
            "a different view key must not collide"
        );

        // The JS recipe is hash_psd4([domain_separator, vk.to_field(), 1]).
        // The domain is written as a literal rather than the module constant,
        // so changing the constant alone cannot keep this test green.
        let domain = Field::<TestnetV0>::new_domain_separator("RecordScannerV0");
        let restated =
            TestnetV0::hash_psd4(&[domain, vk.to_field().unwrap(), Field::one()]).unwrap();
        assert_eq!(uuid, restated);
        assert_ne!(
            uuid,
            TestnetV0::hash_psd4(&[
                Field::<TestnetV0>::new_domain_separator("GraphKeyV0"),
                vk.to_field().unwrap(),
                Field::one()
            ])
            .unwrap(),
            "a different domain separator must change the uuid"
        );
        assert_ne!(
            uuid,
            TestnetV0::hash_psd4(&[domain, vk.to_field().unwrap(), Field::<TestnetV0>::zero()])
                .unwrap(),
            "the JS recipe ends in Field::one(), not zero"
        );
        assert!(
            uuid.to_string().ends_with("field"),
            "uuid must be an Aleo field literal"
        );
    }

    #[test]
    fn owned_records_accepts_both_response_shapes() {
        let item = serde_json::json!({
            "program_name": "credits.aleo",
            "record_ciphertext": "record1...",
            "spent": false,
        });

        let bare = parse_owned_records(&serde_json::json!([item.clone()]).to_string()).unwrap();
        assert_eq!(bare.len(), 1);
        assert_eq!(bare[0].program_name.as_deref(), Some("credits.aleo"));

        let wrapped =
            parse_owned_records(&serde_json::json!({ "data": [item] }).to_string()).unwrap();
        assert_eq!(wrapped.len(), 1);
    }

    #[test]
    fn owned_records_rejects_unexpected_shapes() {
        let err = parse_owned_records("\"nope\"").unwrap_err().to_string();
        assert!(err.contains("expected an array"), "unexpected error: {err}");

        let err = parse_owned_records(r#"{"data":"nope"}"#).unwrap_err().to_string();
        assert!(err.contains("expected an array"), "unexpected error: {err}");

        // An object with no `data` array is an error, not "you own nothing".
        let err = parse_owned_records(r#"{"error":"uuid not found"}"#).unwrap_err().to_string();
        assert!(err.contains("no `data` array"), "unexpected error: {err}");
        assert!(err.contains("error"), "the keys must be reported: {err}");

        // A genuinely empty result is still fine.
        assert!(parse_owned_records("[]").unwrap().is_empty());
        assert!(parse_owned_records(r#"{"data":[]}"#).unwrap().is_empty());
    }

    #[test]
    fn spent_stays_three_valued() {
        let record: OwnedRecord = serde_json::from_str("{}").unwrap();
        assert_eq!(
            record.spent, None,
            "absent spent must be unknown, not false"
        );

        let record: OwnedRecord = serde_json::from_str(r#"{"spent":true}"#).unwrap();
        assert_eq!(record.spent, Some(true));
    }

    #[test]
    fn decrypt_requires_a_ciphertext() {
        let err = OwnedRecord::default().decrypt(&view_key()).unwrap_err().to_string();
        assert!(err.contains("record_ciphertext"), "unexpected error: {err}");
    }

    #[test]
    fn stale_registration_is_a_distinct_error() {
        let err = anyhow::Error::new(StaleRegistration).context("RSS /records/owned returned 422");
        assert!(err.downcast_ref::<StaleRegistration>().is_some());
        assert!(err.to_string().contains("422"));
    }

    // ── /records/sns and /records/tags ──────────────────────────────────

    #[test]
    fn string_bool_map_parses_spent_flags() {
        let map = parse_string_bool_map(r#"{"sn1":true,"sn2":false}"#, "/records/sns").unwrap();
        assert_eq!(map.get("sn1"), Some(&true));
        assert_eq!(map.get("sn2"), Some(&false));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn string_bool_map_rejects_non_objects() {
        let err = parse_string_bool_map("[]", "/records/sns").unwrap_err().to_string();
        assert!(
            err.contains("expected an object"),
            "unexpected error: {err}"
        );

        // A value that is not a boolean must be rejected, not coerced.
        let err = parse_string_bool_map(r#"{"sn1":"yes"}"#, "/records/sns")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("expected a boolean"),
            "unexpected error: {err}"
        );
        assert!(
            err.contains("sn1"),
            "the offending key must be named: {err}"
        );
    }

    // ── /records/encrypted ─────────────────────────────────────────────

    #[test]
    fn encrypted_records_accepts_both_response_shapes() {
        let item = serde_json::json!({
            "commitment": "commitment1field",
            "program_name": "credits.aleo",
            "record_ciphertext": "record1...",
        });

        let bare = parse_encrypted_records(&serde_json::json!([item.clone()]).to_string()).unwrap();
        assert_eq!(bare.len(), 1);
        assert_eq!(bare[0].commitment, "commitment1field");
        assert_eq!(bare[0].program_name.as_deref(), Some("credits.aleo"));
        // Unset fields stay None, not false/0.
        assert_eq!(bare[0].block_height, None);

        let wrapped =
            parse_encrypted_records(&serde_json::json!({ "data": [item] }).to_string()).unwrap();
        assert_eq!(wrapped.len(), 1);
    }

    #[test]
    fn encrypted_records_rejects_unexpected_shapes() {
        let err = parse_encrypted_records("\"nope\"").unwrap_err().to_string();
        assert!(err.contains("expected an array"), "unexpected error: {err}");

        let err = parse_encrypted_records(r#"{"data":"nope"}"#).unwrap_err().to_string();
        assert!(err.contains("expected an array"), "unexpected error: {err}");

        // An object with no `data` array is an error, not "no records".
        let err = parse_encrypted_records(r#"{"error":"scan failed"}"#).unwrap_err().to_string();
        assert!(err.contains("no `data` array"), "unexpected error: {err}");

        assert!(parse_encrypted_records("[]").unwrap().is_empty());
        assert!(parse_encrypted_records(r#"{"data":[]}"#).unwrap().is_empty());
    }

    // ── EncryptedRecordsFilter serialization ───────────────────────────

    #[test]
    fn encrypted_filter_omits_unset_fields() {
        // Only the fields that are set should reach the wire.
        let filter = EncryptedRecordsFilter {
            start: Some(0),
            end: Some(100),
            programs: Some(vec!["credits.aleo".to_string()]),
            ..Default::default()
        };
        let json = serde_json::to_value(&filter).unwrap();
        assert_eq!(json["start"], serde_json::json!(0));
        assert_eq!(json["end"], serde_json::json!(100));
        assert_eq!(json["programs"], serde_json::json!(["credits.aleo"]));
        assert!(json.get("records").is_none(), "unset array must be omitted");
        assert!(
            json.get("response").is_none(),
            "unset response must be omitted"
        );
        assert!(json.get("page").is_none(), "unset page must be omitted");
    }

    #[test]
    fn encrypted_filter_response_subfilter_round_trips() {
        let filter = EncryptedRecordsFilter {
            response: Some(RecordsResponseFilter {
                commitment: Some(true),
                record_ciphertext: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        let json = serde_json::to_value(&filter).unwrap();
        assert_eq!(json["response"]["commitment"], serde_json::json!(true));
        assert_eq!(
            json["response"]["record_ciphertext"],
            serde_json::json!(true)
        );
        assert!(
            json["response"].get("owner").is_none(),
            "unset response fields must be omitted"
        );
    }
}
