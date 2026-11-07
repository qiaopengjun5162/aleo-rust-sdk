//! # Aleo Record — record discovery, decryption, and selection.
//!
//! Aleo's privacy model uses **records** (the privacy-preserving analogue of UTXOs):
//! ciphertexts on chain that only the owner can decrypt with their view key.
//!
//! This module provides:
//!
//! - [`RecordScanner`]: block-level scanning via JSON-RPC + decryption with a view key
//! - [`HostedScanner`]: the same shape, backed by Provable's Record Scanning Service
//! - [`AleoRecord`]: a decrypted, typed record
//! - [`RecordManager`]: high-level lifecycle (discover → decrypt → select → cache)
//! - [`SelectedRecords`]: coin selection result for spending
//!
//! ## Where records come from
//!
//! [`RecordManager`] does not care *how* ciphertexts are found, only that they
//! are decrypted locally. [`RecordSource`] is that seam, with two
//! implementations:
//!
//! | Source | Finds records by | Cost | Knows which are spent |
//! |--------|------------------|------|-----------------------|
//! | [`RecordSource::Local`] | walking `records/all` page by page | O(chain) | no |
//! | [`RecordSource::Hosted`] | asking the RSS, which indexed the ledger once | one query | yes |
//!
//! Both decrypt with your view key, so a lying source cannot invent a balance —
//! it can only hide records.
//!
//! ```no_run
//! use aleo_rust_sdk::hosted::ApiAuth;
//! use aleo_rust_sdk::record::{HostedScanner, RecordManager, RecordSource};
//! use aleo_rust_sdk::scanner::RecordScanService;
//!
//! # async fn run() -> anyhow::Result<()> {
//! let service = RecordScanService::new("testnet", ApiAuth::None)?;
//! let source = RecordSource::Hosted(HostedScanner::new(service, 0));
//! let mut mgr = RecordManager::with_source(source, "AViewKey1...")?;
//! println!("{} microcredits", mgr.get_balance().await?);
//! # Ok(())
//! # }
//! ```
//!
//! ## Architecture
//!
//! ```text
//! RecordSource ──fetch──▶ AleoRecord ──select──▶ SelectedRecords
//!      │                  (decrypted)       (coin selection)
//!      ├── Local: JSON-RPC records/all
//!      └── Hosted: RSS /records/owned
//! ```
//!
//! ## Usage
//!
//! ```no_run
//! use aleo_rust_sdk::record::{RecordScanner, RecordManager};
//! use aleo_rust_sdk::AleoHttpClient;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = AleoHttpClient::new("https://api.explorer.provable.com/v2/testnet")?;
//!
//!     // Quick scan
//!     let scanner = RecordScanner::new(client.clone());
//!     let records = scanner.scan_recent("AViewKey1...", 1000).await?;
//!     println!("Found {} records", records.len());
//!
//!     // Full manager with caching + coin selection
//!     let mut mgr = RecordManager::new(client, "AViewKey1...")?;
//!     let balance = mgr.get_balance().await?;
//!     println!("Balance: {} microcredits", balance);
//!
//!     let selection = mgr.select_records(1_000_000)?;
//!     println!("Selected {} records, total: {} microcredits",
//!         selection.records.len(), selection.total_microcredits);
//!     Ok(())
//! }
//! ```

use anyhow::{Context, Result};
use snarkvm::console::program::{Ciphertext, Record};
use snarkvm::prelude::{Address, TestnetV0, ViewKey};
use std::collections::BTreeMap;
use std::str::FromStr;

use crate::network::AleoHttpClient;
use crate::scanner::{OwnedFilter, OwnedRecord, RecordScanService, StaleRegistration};

/// How far back [`RecordSource::Local`] looks for [`ScanWindow::All`].
///
/// A local scan is O(chain), so "everything" has to be bounded by something.
/// This is the depth `RecordManager::scan` has always used; changing it changes
/// what "full scan" means for every existing caller.
const DEFAULT_SCAN_BLOCKS: u32 = 100_000;

/// An inclusive block range, as asked for by [`RecordManager::scan_range`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockRange {
    /// First block height to include.
    pub start: u32,
    /// Last block height to include.
    pub end: u32,
}

impl BlockRange {
    /// Build a range covering `start..=end`.
    pub fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    /// Whether `height` falls inside this range.
    pub fn contains(&self, height: u32) -> bool {
        (self.start..=self.end).contains(&height)
    }
}

/// What slice of the chain a fetch should cover.
///
/// This is a *filter*, not a promise: a source that cannot see as far back as
/// asked returns fewer records rather than failing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanWindow {
    /// Everything the source can see (100 000 blocks back, locally).
    All,
    /// The most recent `n` blocks.
    Recent(u32),
    /// An explicit inclusive range.
    Range(BlockRange),
}

/// A decrypted Aleo record, ready for inspection or spending.
///
/// Contains the original ciphertext (needed for creating spend proofs)
/// alongside decrypted metadata (owner, amount, data fields).
#[derive(Clone, Debug)]
pub struct AleoRecord {
    /// The Aleo program this record belongs to (e.g. `"credits.aleo"`).
    pub program_id: String,
    /// The owner address.
    pub owner: Address<TestnetV0>,
    /// Amount in microcredits (parsed from record data).
    pub microcredits: u64,
    /// Additional data fields from the record (key → display string).
    pub data: BTreeMap<String, String>,
    /// The original record ciphertext string (required for spending).
    pub ciphertext: String,
    /// Whether this record has been detected as spent.
    ///
    /// Only [`RecordSource::Hosted`] ever sets this to `true`. A local scan
    /// reports every record as unspent, because a spent record stays in the
    /// block it was created in — see [`RecordSource::reports_spent`] before
    /// treating `false` as "safe to spend".
    pub spent: bool,
}

/// Scans blocks on the Aleo network to discover and decrypt records
/// owned by a given view key.
///
/// Uses `records/all` JSON-RPC to fetch ciphertexts across a block range,
/// then decrypts each one to extract owner, amount, and data.
pub struct RecordScanner {
    client: AleoHttpClient,
}

impl RecordScanner {
    /// Create a new scanner backed by the given HTTP client.
    pub fn new(client: AleoHttpClient) -> Self {
        Self { client }
    }

    /// Reference to the underlying HTTP client.
    pub fn client(&self) -> &AleoHttpClient {
        &self.client
    }

    /// Scan a block range and decrypt all records owned by the given view key.
    ///
    /// Returns records sorted by amount (descending).
    pub async fn scan_blocks(
        &self,
        view_key: &str,
        start: u32,
        end: u32,
    ) -> Result<Vec<AleoRecord>> {
        let vk = ViewKey::<TestnetV0>::from_str(view_key).context("Invalid view key")?;
        let owner_addr = vk.to_address();

        tracing::info!("Scanning blocks {start}..{end} for records...");
        let mut results = Vec::new();
        let per_page = 500;
        let mut page = 0u32;

        loop {
            let records_json = self.client.fetch_all_records(start, end, page, per_page).await?;
            let count = records_json.as_array().map(|a| a.len()).unwrap_or(0);
            tracing::info!("  page {page}: {count} records");

            if let Some(arr) = records_json.as_array() {
                for entry in arr {
                    let program_id = entry["program_id"].as_str().unwrap_or("").to_string();
                    let ciphertext_str = entry["record_ciphertext"].as_str().unwrap_or("");
                    if ciphertext_str.is_empty() {
                        continue;
                    }
                    if let Some((microcredits, data)) =
                        Self::decrypt_record_parts(ciphertext_str, &vk)
                    {
                        results.push(AleoRecord {
                            program_id,
                            owner: owner_addr,
                            microcredits,
                            data,
                            ciphertext: ciphertext_str.to_string(),
                            spent: false,
                        });
                    }
                }
            }

            // Stop if this page returned fewer records than the page size (last page)
            if count < per_page as usize {
                break;
            }
            page += 1;

            // Safety: max 100 pages (50K records) to avoid infinite loops
            if page >= 100 {
                tracing::warn!("Reached max page limit (100) while scanning records");
                break;
            }
        }

        // Sort by amount descending (largest first for coin selection)
        results.sort_by_key(|a| std::cmp::Reverse(a.microcredits));
        Ok(results)
    }

    /// Scan the last `num_blocks` blocks (default 5_000) for records owned by the given view key.
    pub async fn scan_recent(&self, view_key: &str, num_blocks: u32) -> Result<Vec<AleoRecord>> {
        let height = self.client.fetch_block_height().await?;
        let start = height.saturating_sub(num_blocks);
        tracing::info!("Scanning last {num_blocks} blocks ({start}..{height}) for records...");
        self.scan_blocks(view_key, start, height).await
    }

    /// Decrypt a single record ciphertext.
    ///
    /// Returns `(microcredits, data_map)` if the record belongs to `vk`, or `None`
    /// if the ciphertext cannot be parsed, cannot be decrypted, or belongs to
    /// someone else.
    ///
    /// ## Where "is this record mine?" is decided
    ///
    /// Not here. `Record::decrypt` derives the record view key from `nonce * vk`,
    /// decrypts, and then bails unless the recovered owner equals `vk.to_address()`
    /// — so a successfully decrypted record is *by construction* owned by `vk`.
    ///
    /// This function used to re-check that equality against a separately passed
    /// `expected_owner` and skip mismatches. That branch was unreachable: the only
    /// caller passes `vk.to_address()`, and `decrypt` had already rejected exactly
    /// the records the check was looking for. Unreachable security checks are worse
    /// than none — they read as protection while the real protection lives one
    /// layer down, so a change that removed the real one would look safe here.
    /// The invariant is now guarded by `tests/record_decryption_test.rs`, which
    /// feeds in a record encrypted for a different account and requires it to be
    /// rejected.
    ///
    /// Shared with [`crate::scanner::OwnedRecord::decrypt`], which receives
    /// ciphertexts from a remote service rather than from `records/all`. "Is this
    /// record mine?" must be decided in exactly one place, or the two paths can
    /// drift apart.
    pub(crate) fn decrypt_record_parts(
        ciphertext_str: &str,
        vk: &ViewKey<TestnetV0>,
    ) -> Option<(u64, BTreeMap<String, String>)> {
        let encrypted = match Record::<TestnetV0, Ciphertext<TestnetV0>>::from_str(ciphertext_str) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Record::from_str failed: {e}");
                return None;
            }
        };
        let decrypted = match encrypted.decrypt(vk) {
            Ok(r) => r,
            Err(e) => {
                // Either the ciphertext is not ours, or it is malformed. Both mean
                // "not a record we can spend", so the scan continues.
                tracing::debug!("Record::decrypt failed: {e}");
                return None;
            }
        };

        // Extract microcredits — iterate over data entries matching "microcredits" key
        let mut microcredits = 0u64;
        let mut data = BTreeMap::new();
        for (id, entry) in decrypted.data().iter() {
            let key = id.to_string();
            let raw = entry.to_string();
            if key == "microcredits" {
                match parse_u64_entry(&raw) {
                    Some(amount) => microcredits = amount,
                    None => tracing::warn!("microcredits parse failed: {raw:?}"),
                }
            }
            data.insert(key, raw);
        }

        tracing::info!(
            "Decrypted record: owner matches, microcredits={microcredits}, entries={}",
            data.len()
        );
        Some((microcredits, data))
    }
}

/// Read a `u64` out of the textual form snarkVM uses for record entries.
///
/// `Entry::to_string()` renders `<value><type>.<visibility>` — `1000000u64.private`,
/// `5u64.public`, `0u64.constant`. The previous implementation stripped the
/// literal `"u64.private"` and then `"u64"`, which only worked for private
/// entries: a public entry `5u64.public` became `5.public` and failed to parse,
/// silently reporting a zero balance. Splitting on the visibility suffix and
/// then the type suffix handles all three visibilities and any integer width
/// that is not `u64` still fails the parse, which is what the caller wants.
pub(crate) fn parse_u64_entry(raw: &str) -> Option<u64> {
    // Drop the `.private` / `.public` / `.constant` visibility suffix.
    let value = raw.rsplit_once('.').map_or(raw, |(value, _)| value);
    // Drop the `u64` type suffix.
    let digits = value.strip_suffix("u64").unwrap_or(value);
    digits.trim().parse::<u64>().ok()
}

/// [`RecordScanService`] adapted to the [`RecordSource`] shape.
///
/// The service indexes a view key once and then answers by `uuid`, so this
/// adapter registers **lazily** — on the first fetch — and never twice, except
/// when the service reports the uuid stale (HTTP 422), which is the one failure
/// re-registering actually fixes.
///
/// ## What the registration fixes forever
///
/// `start_block` is sent at registration time and cannot be widened later: a
/// registration that starts at block 5_000_000 will never return a record from
/// block 4_999_999. Choose it as the lowest height you will ever need — `0` for
/// "from genesis".
pub struct HostedScanner {
    service: RecordScanService,
    /// Height the registration asks the service to index from.
    start_block: u32,
    /// Applied on every query. Defaults to no filter, which is the only setting
    /// that keeps `spent` current — see [`Self::with_filter`].
    filter: OwnedFilter,
    uuid: Option<String>,
}

impl HostedScanner {
    /// Wrap a service client. `start_block = 0` scans from genesis.
    pub fn new(service: RecordScanService, start_block: u32) -> Self {
        Self {
            service,
            start_block,
            filter: OwnedFilter::default(),
            uuid: None,
        }
    }

    /// Narrow what the service returns.
    ///
    /// The default (no filter) fetches spent *and* unspent records, because
    /// otherwise a record that has since been spent would stay in the
    /// manager's cache forever, still counted as unspent. Filtering to
    /// [`OwnedFilter::unspent`] makes responses smaller but freezes cached
    /// spend status at whatever it was when the record first appeared.
    pub fn with_filter(mut self, filter: OwnedFilter) -> Self {
        self.filter = filter;
        self
    }

    /// The `uuid` from the registration, once one has happened.
    pub fn uuid(&self) -> Option<&str> {
        self.uuid.as_deref()
    }

    /// The underlying service client.
    pub fn service(&self) -> &RecordScanService {
        &self.service
    }

    /// Fetch the records the service attributes to this view key.
    ///
    /// Every returned ciphertext is decrypted here, with the local view key —
    /// the service's own `record_plaintext` field is ignored.
    ///
    /// # Errors
    ///
    /// Fails if the registration fails, the query fails twice (once before and
    /// once after a re-registration), or the response contained records but
    /// none of them decrypted. The last case is a protocol break — a renamed
    /// field, an encrypted payload — and returning an empty list there would
    /// read as "your wallet is empty".
    pub async fn fetch(
        &mut self,
        view_key: &ViewKey<TestnetV0>,
        window: ScanWindow,
    ) -> Result<Vec<AleoRecord>> {
        let owned = self.owned(view_key).await?;
        let range = match window {
            ScanWindow::Range(range) => Some(range),
            // The service filters by its registration window, not per request,
            // and nothing here knows the chain tip, so `Recent(n)` cannot be
            // honoured without either guessing or a second endpoint. Returning
            // everything is the safe direction: too much, never too little.
            ScanWindow::All | ScanWindow::Recent(_) => None,
        };

        let total = owned.len();
        let mut candidates = 0usize;
        let mut records = Vec::with_capacity(total);

        for (index, entry) in owned.iter().enumerate() {
            // A record with no reported height is kept: dropping it because we
            // cannot prove it is in range would under-report the balance.
            if let (Some(range), Some(height)) = (range, entry.block_height)
                && !range.contains(height)
            {
                continue;
            }
            candidates += 1;

            match entry.decrypt(view_key) {
                Ok(record) => records.push(record),
                // Not ours, or forged. Either way it is not spendable, so the
                // scan continues — but it is logged, since a correct service
                // should never trigger this.
                Err(err) => tracing::warn!("Dropping record #{index} from the scanner: {err}"),
            }
        }

        if candidates > 0 && records.is_empty() {
            anyhow::bail!(
                "Scanner returned {candidates} records in range but none decrypted with this view key"
            );
        }

        records.sort_by_key(|a| std::cmp::Reverse(a.microcredits));
        Ok(records)
    }

    /// `records/owned`, registering first and healing a stale uuid once.
    async fn owned(&mut self, view_key: &ViewKey<TestnetV0>) -> Result<Vec<OwnedRecord>> {
        if self.uuid.is_none() {
            self.register(view_key).await?;
        }
        let uuid = self.uuid.clone().context("registration returned no uuid")?;

        match self.service.records_owned(&uuid, self.filter.clone()).await {
            Ok(records) => Ok(records),
            Err(err) if err.downcast_ref::<StaleRegistration>().is_some() => {
                // A stale uuid stays stale: exactly one re-registration, then
                // whatever happens happens.
                tracing::warn!("Scanner rejected the uuid; re-registering once");
                self.register(view_key).await?;
                let uuid = self.uuid.clone().context("registration returned no uuid")?;
                self.service.records_owned(&uuid, self.filter.clone()).await
            }
            Err(err) => Err(err),
        }
    }

    async fn register(&mut self, view_key: &ViewKey<TestnetV0>) -> Result<()> {
        let registration = self.service.register(view_key, self.start_block).await?;
        tracing::info!(
            "Registered view key with the scanner: {}",
            registration.uuid
        );
        self.uuid = Some(registration.uuid);
        Ok(())
    }
}

/// Where [`RecordManager`] gets ciphertexts from.
///
/// The two sources differ in *discovery*, not in trust: both decrypt every
/// record locally with your view key, so neither can fabricate a spendable
/// record. What the hosted source can do is tell you which records are spent,
/// which the local scanner cannot (it walks ciphertexts, and a spent record
/// stays in the block it was created in).
///
/// ```no_run
/// use aleo_rust_sdk::hosted::ApiAuth;
/// use aleo_rust_sdk::record::{HostedScanner, RecordSource};
/// use aleo_rust_sdk::scanner::RecordScanService;
///
/// let service = RecordScanService::new("testnet", ApiAuth::None).unwrap();
/// let source = RecordSource::Hosted(HostedScanner::new(service, 0));
/// assert!(source.reports_spent());
/// ```
#[non_exhaustive]
pub enum RecordSource {
    /// Walk `records/all` over JSON-RPC and decrypt each page locally.
    Local(RecordScanner),
    /// Ask Provable's Record Scanning Service for the records it indexed.
    Hosted(HostedScanner),
}

impl RecordSource {
    /// Whether this source learns *which* records are spent.
    ///
    /// `false` means [`AleoRecord::spent`] is always `false`, i.e. "not known
    /// to be spent" — not "confirmed unspent". A balance computed from a local
    /// scan can therefore be too high; it is never too low.
    pub fn reports_spent(&self) -> bool {
        matches!(self, Self::Hosted(_))
    }

    /// Fetch the records `view_key` owns.
    ///
    /// # Errors
    ///
    /// Propagates transport and decryption failures from the active source; see
    /// [`HostedScanner::fetch`] for the hosted-specific ones.
    pub async fn fetch(
        &mut self,
        view_key: &ViewKey<TestnetV0>,
        window: ScanWindow,
    ) -> Result<Vec<AleoRecord>> {
        match self {
            Self::Local(scanner) => {
                let view_key = view_key.to_string();
                match window {
                    ScanWindow::All => scanner.scan_recent(&view_key, DEFAULT_SCAN_BLOCKS).await,
                    ScanWindow::Recent(blocks) => scanner.scan_recent(&view_key, blocks).await,
                    ScanWindow::Range(range) => {
                        scanner.scan_blocks(&view_key, range.start, range.end).await
                    }
                }
            }
            Self::Hosted(hosted) => hosted.fetch(view_key, window).await,
        }
    }
}

/// High-level record manager providing cached scanning and coin selection.
///
/// ## Lifecycle
///
/// 1. **Create** — `RecordManager::new(client, view_key_str)` (local scan) or
///    `RecordManager::with_source(source, view_key_str)` (local or hosted)
/// 2. **Scan** — `mgr.get_balance().await?` or `mgr.scan().await?`
/// 3. **Select** — `mgr.select_records(amount)` for spending
/// 4. **Mark spent** — `mgr.mark_spent(ciphertext)` after a successful broadcast
pub struct RecordManager {
    source: RecordSource,
    view_key: ViewKey<TestnetV0>,
    address: Address<TestnetV0>,
    records: Vec<AleoRecord>,
}

impl RecordManager {
    /// Create a manager that finds records by scanning blocks locally.
    pub fn new(client: AleoHttpClient, view_key: &str) -> Result<Self> {
        Self::with_source(RecordSource::Local(RecordScanner::new(client)), view_key)
    }

    /// Create a manager over an explicit source.
    ///
    /// Everything downstream is source-agnostic: coin selection, dedupe,
    /// balance, and `spent` bookkeeping all live here, and run the same way
    /// whichever source filled the cache.
    pub fn with_source(source: RecordSource, view_key: &str) -> Result<Self> {
        let vk = ViewKey::<TestnetV0>::from_str(view_key)
            .map_err(|e| anyhow::anyhow!("Invalid view key: {e}"))?;
        let address = vk.to_address();
        Ok(Self {
            source,
            view_key: vk,
            address,
            records: Vec::new(),
        })
    }

    /// The source this manager fetches from.
    pub fn source(&self) -> &RecordSource {
        &self.source
    }

    /// Whether the source reports which records are spent.
    ///
    /// See [`RecordSource::reports_spent`]. The hosted source is the only one
    /// that ever sets [`AleoRecord::spent`] from remote data.
    pub fn reports_spent(&self) -> bool {
        self.source.reports_spent()
    }

    /// Scan the latest blocks (up to 100K locally, everything the service has
    /// when hosted) and update the internal cache.
    pub async fn scan(&mut self) -> Result<&[AleoRecord]> {
        let fetched = self.source.fetch(&self.view_key, ScanWindow::All).await?;
        self.merge_records(fetched);
        Ok(&self.records)
    }

    /// Scan the latest `num_blocks` blocks and update the internal cache.
    ///
    /// A hosted source has no per-request window — it was registered with a
    /// fixed `start_block` — so it returns every record it indexed instead of
    /// narrowing to `num_blocks`. That is more than asked, never less; use
    /// [`Self::scan_range`] when a specific window matters.
    pub async fn scan_recent(&mut self, num_blocks: u32) -> Result<&[AleoRecord]> {
        let fetched = self.source.fetch(&self.view_key, ScanWindow::Recent(num_blocks)).await?;
        self.merge_records(fetched);
        Ok(&self.records)
    }

    /// Scan a specific block range and update the cache.
    pub async fn scan_range(&mut self, start: u32, end: u32) -> Result<&[AleoRecord]> {
        let fetched = self
            .source
            .fetch(
                &self.view_key,
                ScanWindow::Range(BlockRange::new(start, end)),
            )
            .await?;
        self.merge_records(fetched);
        Ok(&self.records)
    }

    /// Merge new records into the cache, deduplicating by ciphertext.
    pub fn merge_records(&mut self, new_records: Vec<AleoRecord>) {
        for rec in new_records {
            if let Some(pos) = self.records.iter().position(|r| r.ciphertext == rec.ciphertext) {
                self.records[pos] = rec;
            } else {
                self.records.push(rec);
            }
        }
        // Keep sorted
        self.records.sort_by_key(|a| std::cmp::Reverse(a.microcredits));
    }

    /// Compute the balance across all cached, unspent `credits.aleo` records.
    ///
    /// Returns 0 if no records are cached (call `scan()` first to refresh).
    pub fn balance(&self) -> u64 {
        self.records
            .iter()
            .filter(|r| r.program_id == "credits.aleo" && !r.spent)
            .map(|r| r.microcredits)
            .sum()
    }

    /// Get balance, automatically scanning if the cache is empty.
    pub async fn get_balance(&mut self) -> Result<u64> {
        if self.records.is_empty() {
            self.scan().await?;
        }
        Ok(self.balance())
    }

    /// Select records to meet a spend target (coin selection).
    ///
    /// Uses largest-first strategy. Only considers unspent `credits.aleo` records.
    ///
    /// Returns an error if the total balance is insufficient.
    pub fn select_records(&self, amount_microcredits: u64) -> Result<SelectedRecords> {
        let mut selected = Vec::new();
        let mut total = 0u64;

        for rec in &self.records {
            if rec.program_id != "credits.aleo" || rec.spent {
                continue;
            }
            selected.push(rec.clone());
            total += rec.microcredits;
            if total >= amount_microcredits {
                return Ok(SelectedRecords {
                    records: selected,
                    total_microcredits: total,
                });
            }
        }

        anyhow::bail!("Insufficient funds: have {total} microcredits, need {amount_microcredits}");
    }

    /// Get a reference to all cached records.
    pub fn records(&self) -> &[AleoRecord] {
        &self.records
    }

    /// Mark a record as spent (call after a successful broadcast).
    pub fn mark_spent(&mut self, ciphertext: &str) {
        if let Some(rec) = self.records.iter_mut().find(|r| r.ciphertext == ciphertext) {
            rec.spent = true;
        }
    }

    /// The view key associated with this manager.
    pub fn view_key(&self) -> &ViewKey<TestnetV0> {
        &self.view_key
    }

    /// The owner address for this manager.
    pub fn address(&self) -> &Address<TestnetV0> {
        &self.address
    }
}

/// The result of coin selection: which records to spend and the total.
#[derive(Clone, Debug)]
pub struct SelectedRecords {
    /// The selected records to spend.
    pub records: Vec<AleoRecord>,
    /// Total microcredits across all selected records.
    pub total_microcredits: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a manager whose cache is pre-filled, so no scan is needed.
    ///
    /// The source is never exercised by these tests; they cover the
    /// source-agnostic half (dedupe, balance, coin selection, spend marking).
    fn manager_with(
        records: Vec<AleoRecord>,
        view_key: ViewKey<TestnetV0>,
        address: Address<TestnetV0>,
    ) -> RecordManager {
        RecordManager {
            source: RecordSource::Local(RecordScanner::new(
                AleoHttpClient::new("http://localhost:9999").unwrap(),
            )),
            view_key,
            address,
            records,
        }
    }

    #[test]
    fn block_range_contains_is_inclusive() {
        let range = BlockRange::new(10, 20);
        assert!(!range.contains(9));
        assert!(range.contains(10));
        assert!(range.contains(20));
        assert!(!range.contains(21));
    }

    /// A fresh hosted scanner has no uuid yet — it must not pretend to be
    /// registered, because every query needs the uuid the service handed back.
    #[test]
    fn hosted_scanner_starts_unregistered_and_keeps_its_filter() {
        let service = RecordScanService::with_endpoints(
            "http://127.0.0.1:1",
            "http://127.0.0.1:1",
            crate::hosted::ApiAuth::None,
        )
        .unwrap();

        let scanner = HostedScanner::new(service, 7);
        assert_eq!(scanner.uuid(), None);
        assert_eq!(scanner.service().scanner_base(), "http://127.0.0.1:1");

        let scanner = scanner.with_filter(OwnedFilter::unspent().program("credits.aleo"));
        assert_eq!(
            scanner.filter.unspent,
            Some(true),
            "the builder must keep what it was given"
        );
        assert_eq!(scanner.filter.program.as_deref(), Some("credits.aleo"));
    }

    #[test]
    fn test_aleo_record_struct() {
        // SnarkVM address from a known test private key
        let rng = &mut snarkvm::prelude::TestRng::default();
        let pk = snarkvm::prelude::PrivateKey::<TestnetV0>::new(rng).unwrap();
        let addr = snarkvm::prelude::Address::try_from(&pk).unwrap();

        let record = AleoRecord {
            program_id: "credits.aleo".into(),
            owner: addr,
            microcredits: 1_000_000,
            data: BTreeMap::new(),
            ciphertext: "record1qyh...test".into(),
            spent: false,
        };
        assert_eq!(record.program_id, "credits.aleo");
        assert_eq!(record.microcredits, 1_000_000);
        assert!(!record.spent);
        assert_eq!(record.owner, addr);
    }

    #[test]
    fn test_select_records_largest_first() {
        let rng = &mut snarkvm::prelude::TestRng::default();
        let pk = snarkvm::prelude::PrivateKey::<TestnetV0>::new(rng).unwrap();
        let addr = snarkvm::prelude::Address::try_from(&pk).unwrap();

        let records = vec![
            AleoRecord {
                program_id: "credits.aleo".into(),
                owner: addr,
                microcredits: 1_000_000,
                data: BTreeMap::new(),
                ciphertext: "record_large".into(),
                spent: false,
            },
            AleoRecord {
                program_id: "credits.aleo".into(),
                owner: addr,
                microcredits: 500_000,
                data: BTreeMap::new(),
                ciphertext: "record_medium".into(),
                spent: false,
            },
            AleoRecord {
                program_id: "credits.aleo".into(),
                owner: addr,
                microcredits: 100_000,
                data: BTreeMap::new(),
                ciphertext: "record_small".into(),
                spent: false,
            },
        ];

        // Build a manager with these pre-loaded records
        let view_key = snarkvm::prelude::ViewKey::try_from(&pk).unwrap();
        let mgr = manager_with(records, view_key, addr);

        // Select 600_000 microcredits — should pick largest (1M) first
        let selection = mgr.select_records(600_000).unwrap();
        assert_eq!(selection.records.len(), 1);
        assert_eq!(selection.records[0].ciphertext, "record_large");
        assert_eq!(selection.total_microcredits, 1_000_000);

        // Select 1_500_000 — need two records
        let selection = mgr.select_records(1_500_000).unwrap();
        assert_eq!(selection.records.len(), 2);
        assert_eq!(selection.total_microcredits, 1_500_000);

        // Select more than total — should error
        let result = mgr.select_records(10_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_balance() {
        let rng = &mut snarkvm::prelude::TestRng::default();
        let pk = snarkvm::prelude::PrivateKey::<TestnetV0>::new(rng).unwrap();
        let addr = snarkvm::prelude::Address::try_from(&pk).unwrap();
        let view_key = snarkvm::prelude::ViewKey::try_from(&pk).unwrap();

        let mgr = manager_with(
            vec![
                AleoRecord {
                    program_id: "credits.aleo".into(),
                    owner: addr,
                    microcredits: 500_000,
                    data: BTreeMap::new(),
                    ciphertext: "record1".into(),
                    spent: false,
                },
                AleoRecord {
                    program_id: "credits.aleo".into(),
                    owner: addr,
                    microcredits: 500_000,
                    data: BTreeMap::new(),
                    ciphertext: "r2".into(),
                    spent: false,
                },
            ],
            view_key,
            addr,
        );

        assert_eq!(mgr.balance(), 1_000_000);
    }

    #[test]
    fn test_mark_spent() {
        let rng = &mut snarkvm::prelude::TestRng::default();
        let pk = snarkvm::prelude::PrivateKey::<TestnetV0>::new(rng).unwrap();
        let addr = snarkvm::prelude::Address::try_from(&pk).unwrap();

        let view_key = snarkvm::prelude::ViewKey::try_from(&pk).unwrap();
        let mut mgr = manager_with(
            vec![AleoRecord {
                program_id: "credits.aleo".into(),
                owner: addr,
                microcredits: 1_000_000,
                data: BTreeMap::new(),
                ciphertext: "record_to_spend".into(),
                spent: false,
            }],
            view_key,
            addr,
        );

        assert_eq!(mgr.balance(), 1_000_000);
        mgr.mark_spent("record_to_spend");
        assert_eq!(mgr.balance(), 0);
    }
}
