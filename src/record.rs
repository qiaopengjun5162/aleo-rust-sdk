//! # Aleo Record — record discovery, decryption, and selection.
//!
//! Aleo's privacy model uses **records** (the privacy-preserving analogue of UTXOs):
//! ciphertexts on chain that only the owner can decrypt with their view key.
//!
//! This module provides:
//!
//! - [`RecordScanner`]: block-level scanning via JSON-RPC + decryption with a view key
//! - [`AleoRecord`]: a decrypted, typed record
//! - [`RecordManager`]: high-level lifecycle (discover → decrypt → select → cache)
//! - [`SelectedRecords`]: coin selection result for spending
//!
//! ## Architecture
//!
//! ```text
//! RecordScanner ──scan──▶ AleoRecord ──select──▶ SelectedRecords
//!      │                 (decrypted)       (coin selection)
//!      └── JSON-RPC: records/all, records/isOwner
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
use snarkvm::prelude::{Address, Owner, TestnetV0, ViewKey};
use std::collections::BTreeMap;
use std::str::FromStr;

use crate::network::AleoHttpClient;

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
        let records_json = self.client.fetch_all_records(start, end, 0, 500).await?;

        let mut results = Vec::new();
        if let Some(arr) = records_json.as_array() {
            for entry in arr {
                let program_id = entry["program_id"].as_str().unwrap_or("").to_string();
                let ciphertext_str = entry["record_ciphertext"].as_str().unwrap_or("");
                if ciphertext_str.is_empty() {
                    continue;
                }
                if let Some((microcredits, data)) =
                    Self::decrypt_record(ciphertext_str, &vk, &owner_addr)
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

        // Sort by amount descending (largest first for coin selection)
        results.sort_by(|a, b| b.microcredits.cmp(&a.microcredits));
        Ok(results)
    }

    /// Scan the last `num_blocks` blocks for records owned by the given view key.
    pub async fn scan_recent(&self, view_key: &str, num_blocks: u32) -> Result<Vec<AleoRecord>> {
        let height = self.client.fetch_block_height().await?;
        let start = height.saturating_sub(num_blocks);
        self.scan_blocks(view_key, start, height).await
    }

    /// Decrypt a single record ciphertext.
    ///
    /// Returns `(microcredits, data_map)` if the record is owned by `expected_owner`,
    /// or `None` if decryption fails or the owner doesn't match.
    fn decrypt_record(
        ciphertext_str: &str,
        vk: &ViewKey<TestnetV0>,
        expected_owner: &Address<TestnetV0>,
    ) -> Option<(u64, BTreeMap<String, String>)> {
        let encrypted =
            Record::<TestnetV0, Ciphertext<TestnetV0>>::from_str(ciphertext_str).ok()?;
        let decrypted = encrypted.decrypt(vk).ok()?;

        // Check owner
        let is_owned = match decrypted.owner() {
            Owner::Public(addr) => addr == expected_owner,
            Owner::Private(plain) => Address::from_str(&plain.to_string())
                .map(|addr| &addr == expected_owner)
                .unwrap_or(false),
        };
        if !is_owned {
            return None;
        }

        // Extract microcredits — iterate over data entries matching "microcredits" key
        let mut microcredits = 0u64;
        let mut data = BTreeMap::new();
        for (id, entry) in decrypted.data().iter() {
            let key = id.to_string();
            if key == "microcredits" {
                let amount_str = entry
                    .to_string()
                    .replace("u64", "")
                    .trim()
                    .to_string();
                if let Ok(amount) = amount_str.parse::<u64>() {
                    microcredits = amount;
                }
            }
            data.insert(key, entry.to_string());
        }

        Some((microcredits, data))
    }
}

/// High-level record manager providing cached scanning and coin selection.
///
/// ## Lifecycle
///
/// 1. **Create** — `RecordManager::new(client, view_key_str)`
/// 2. **Scan** — `mgr.get_balance().await?` or `mgr.scan().await?`
/// 3. **Select** — `mgr.select_records(amount)` for spending
/// 4. **Mark spent** — `mgr.mark_spent(ciphertext)` after a successful broadcast
pub struct RecordManager {
    scanner: RecordScanner,
    view_key: ViewKey<TestnetV0>,
    address: Address<TestnetV0>,
    records: Vec<AleoRecord>,
}

impl RecordManager {
    /// Create a new manager with the given HTTP client and view key.
    pub fn new(client: AleoHttpClient, view_key: &str) -> Result<Self> {
        let vk =
            ViewKey::<TestnetV0>::from_str(view_key).map_err(|e| anyhow::anyhow!("Invalid view key: {e}"))?;
        let address = vk.to_address();
        Ok(Self {
            scanner: RecordScanner::new(client),
            view_key: vk,
            address,
            records: Vec::new(),
        })
    }

    /// Scan the latest blocks (up to 100K) and update the internal cache.
    pub async fn scan(&mut self) -> Result<&[AleoRecord]> {
        let vk_str = self.view_key.to_string();
        let new_records = self
            .scanner
            .scan_recent(&vk_str, 100_000)
            .await?;
        self.merge_records(new_records);
        Ok(&self.records)
    }

    /// Scan a specific block range and update the cache.
    pub async fn scan_range(&mut self, start: u32, end: u32) -> Result<&[AleoRecord]> {
        let vk_str = self.view_key.to_string();
        let new_records = self.scanner.scan_blocks(&vk_str, start, end).await?;
        self.merge_records(new_records);
        Ok(&self.records)
    }

    /// Merge new records into the cache, deduplicating by ciphertext.
    fn merge_records(&mut self, new_records: Vec<AleoRecord>) {
        for rec in new_records {
            if let Some(pos) = self.records.iter().position(|r| r.ciphertext == rec.ciphertext) {
                self.records[pos] = rec;
            } else {
                self.records.push(rec);
            }
        }
        // Keep sorted
        self.records.sort_by(|a, b| b.microcredits.cmp(&a.microcredits));
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

        anyhow::bail!(
            "Insufficient funds: have {total} microcredits, need {amount_microcredits}"
        );
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
        let mut mgr = RecordManager {
            scanner: RecordScanner::new(
                AleoHttpClient::new("http://localhost:9999").unwrap(),
            ),
            view_key: view_key.clone(),
            address: addr,
            records,
        };

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

        let mgr = RecordManager {
            scanner: RecordScanner::new(
                AleoHttpClient::new("http://localhost:9999").unwrap(),
            ),
            view_key: view_key.clone(),
            address: addr,
            records: vec![
                AleoRecord {
                    program_id: "credits.aleo".into(),
                    owner: addr,
                    microcredits: 1_000_000,
                    data: BTreeMap::new(),
                    ciphertext: "r1".into(),
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
        };

        assert_eq!(mgr.balance(), 1_500_000);
    }

    #[test]
    fn test_mark_spent() {
        let rng = &mut snarkvm::prelude::TestRng::default();
        let pk = snarkvm::prelude::PrivateKey::<TestnetV0>::new(rng).unwrap();
        let addr = snarkvm::prelude::Address::try_from(&pk).unwrap();

        let view_key = snarkvm::prelude::ViewKey::try_from(&pk).unwrap();
        let mut mgr = RecordManager {
            scanner: RecordScanner::new(
                AleoHttpClient::new("http://localhost:9999").unwrap(),
            ),
            view_key: view_key.clone(),
            address: addr,
            records: vec![AleoRecord {
                program_id: "credits.aleo".into(),
                owner: addr,
                microcredits: 1_000_000,
                data: BTreeMap::new(),
                ciphertext: "record_to_spend".into(),
                spent: false,
            }],
        };

        assert_eq!(mgr.balance(), 1_000_000);
        mgr.mark_spent("record_to_spend");
        assert_eq!(mgr.balance(), 0);
    }
}
