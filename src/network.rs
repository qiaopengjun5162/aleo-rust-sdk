//! # Aleo Network — RPC client for interacting with Aleo blockchain nodes.
//!
//! Uses [Provable's v2 REST API](https://api.explorer.provable.com/v2/testnet) for GET
//! endpoints (block height, state root, programs) and JSON-RPC (`testnetbeta.aleorpc.com`)
//! for mapping/record queries.
//!
//! ## Endpoints
//!
//! | Endpoint | Protocol | Used For |
//! |----------|----------|----------|
//! | `api.explorer.provable.com/v2/testnet` | REST | Block height, state root, programs, broadcast |
//! | `testnetbeta.aleorpc.com` | JSON-RPC | Mapping values, records, `getMappingValue` |
//!
//! ## Usage
//!
//! ```no_run
//! use aleo_rust_sdk::AleoHttpClient;
//!
//! # async fn run() -> anyhow::Result<()> {
//! let client = AleoHttpClient::new("https://api.explorer.provable.com/v2/testnet")?;
//!
//! let height = client.fetch_block_height().await?;
//! println!("Block height: {height}");
//! # Ok(())
//! # }
//! ```

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use snarkvm::ledger::query::QueryTrait;
use snarkvm::prelude::{Field, Network, Program, StatePath, TestnetV0};
use std::io::Write;
use std::str::FromStr;

/// Browser-like User-Agent to bypass Cloudflare WAF.
const UA: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

/// JSON-RPC endpoint for Aleo testnet (used for mapping/records queries).
const JSON_RPC_URL: &str = "https://testnetbeta.aleorpc.com";

/// HTTP client with browser-like headers for Aleo network interaction.
#[derive(Clone, Debug)]
pub struct AleoHttpClient {
    /// Base URL for REST endpoints (e.g. `https://api.explorer.provable.com/v2/testnet`)
    pub base_url: String,
    /// JSON-RPC endpoint (e.g. `https://testnetbeta.aleorpc.com`)
    rpc_url: String,
    inner: reqwest::Client,
}

impl AleoHttpClient {
    /// Create a new client pointing at an Aleo node (default RPC endpoint).
    pub fn new(base_url: &str) -> Result<Self> {
        Self::new_with_rpc(base_url, JSON_RPC_URL)
    }

    /// Create a client with a custom RPC URL (useful for testing with wiremock).
    pub fn new_with_rpc(base_url: &str, rpc_url: &str) -> Result<Self> {
        let inner = reqwest::Client::builder()
            .http1_only()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .context("Failed to build HTTP client")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            rpc_url: rpc_url.trim_end_matches('/').to_string(),
            inner,
        })
    }

    fn headers() -> reqwest::header::HeaderMap {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert("User-Agent", UA.parse().unwrap());
        h.insert("Accept", "application/json, text/plain, */*".parse().unwrap());
        h
    }

    /// Helper: JSON-RPC POST call.
    async fn json_rpc(&self, method: &str, params: Vec<Value>) -> Result<Value> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let mut headers = Self::headers();
        headers.insert("Content-Type", "application/json".parse().unwrap());

        let resp = self.inner.post(&self.rpc_url).headers(headers).json(&body).send().await?;
        let text = resp.text().await?;
        let v: Value = serde_json::from_str(&text).context("Failed to parse JSON-RPC response")?;

        if let Some(err) = v.get("error") {
            anyhow::bail!("JSON-RPC error ({method}): {err}");
        }
        v.get("result").cloned().context("JSON-RPC response missing result")
    }

    /// Fetch a program from the network (REST GET).
    pub async fn fetch_program(&self, program_id: &str) -> Result<Program<TestnetV0>> {
        let url = format!("{}/program/{program_id}", self.base_url);
        tracing::info!("GET {url}");
        let text = self.inner.get(&url).headers(Self::headers()).send().await?.text().await?;

        let clean = text.trim_matches('"').replace("\\n", "\n");
        Program::<TestnetV0>::from_str(&clean).context("Failed to parse program")
    }

    /// Fetch latest state root + block height (REST GET).
    pub async fn fetch_state_root(&self) -> Result<(<TestnetV0 as Network>::StateRoot, u32)> {
        let root_url = format!("{}/stateRoot/latest", self.base_url);
        let text = self.inner.get(&root_url).headers(Self::headers()).send().await?.text().await?;
        let root_str = text.trim_matches('"');
        let state_root = <TestnetV0 as Network>::StateRoot::from_str(root_str)
            .context("Failed to parse state root")?;

        let height = self.fetch_block_height().await?;
        Ok((state_root, height))
    }

    /// Broadcast a JSON-serialized transaction (REST POST).
    pub async fn broadcast_transaction(&self, tx_json: String) -> Result<String> {
        let url = format!("{}/transaction/broadcast?check_transaction=true", self.base_url);
        let mut headers = Self::headers();
        headers.insert("Content-Type", "application/json".parse().unwrap());
        headers.insert("Origin", "https://explorer.provable.com".parse().unwrap());
        headers.insert("Referer", "https://explorer.provable.com/".parse().unwrap());

        let resp = self.inner.post(&url).headers(headers).body(tx_json).send().await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            anyhow::bail!("Broadcast rejected ({status}): {body}");
        }
        Ok(body)
    }

    /// Poll for confirmation (up to 30 attempts, 5s apart).
    pub async fn wait_for_confirmation(&self, tx_id: &str) -> Result<()> {
        let check_url = format!("{}/transaction/{tx_id}", self.base_url);
        tracing::info!("Waiting for confirmation... (polling every 5s)");

        for _ in 1..=30 {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

            match self.inner.get(&check_url).headers(Self::headers()).send().await {
                Ok(res) if res.status().is_success() => {
                    tracing::info!("Confirmed on chain!");
                    tracing::info!("🔗 https://testnet.explorer.provable.com/transaction/{tx_id}");
                    return Ok(());
                }
                _ => {
                    print!(".");
                    std::io::stdout().flush().ok();
                }
            }
        }
        anyhow::bail!("Timed out waiting for confirmation of {tx_id}")
    }

    // ── On-chain state queries ──────────────────────────────────────────

    /// Query a mapping value via JSON-RPC `getMappingValue`.
    ///
    /// Returns `None` if the key does not exist in the mapping.
    pub async fn fetch_mapping_value(
        &self,
        program_id: &str,
        mapping_name: &str,
        key: &str,
    ) -> Result<Option<String>> {
        let result = self.json_rpc(
            "getMappingValue",
            vec![
                Value::String(program_id.to_string()),
                Value::String(mapping_name.to_string()),
                Value::String(key.to_string()),
            ],
        ).await;

        match result {
            Ok(Value::String(s)) => Ok(Some(s)),
            Ok(v) => Ok(Some(v.to_string())),
            Err(e) => {
                tracing::warn!("Mapping query note (key may not exist): {e}");
                Ok(None)
            }
        }
    }

    /// Fetch the current block height (REST GET).
    pub async fn fetch_block_height(&self) -> Result<u32> {
        let url = format!("{}/block/height/latest", self.base_url);
        let text = self.inner.get(&url).headers(Self::headers()).send().await?.text().await?;
        Ok(text.trim().parse()?)
    }

    /// Fetch latest state root only (REST GET).
    pub async fn fetch_state_root_only(&self) -> Result<<TestnetV0 as Network>::StateRoot> {
        let url = format!("{}/stateRoot/latest", self.base_url);
        let text = self.inner.get(&url).headers(Self::headers()).send().await?.text().await?;
        <TestnetV0 as Network>::StateRoot::from_str(text.trim_matches('"'))
            .context("Failed to parse state root")
    }

    /// Fetch unspent records by view key via JSON-RPC.
    pub async fn fetch_records(&self, view_key: &str) -> Result<String> {
        let height = self.fetch_block_height().await?;
        let start = height.saturating_sub(1000);

        let result = self.json_rpc(
            "records/isOwner",
            vec![
                Value::String(view_key.to_string()),
                Value::Number(serde_json::Number::from(start)),
                Value::Number(serde_json::Number::from(height)),
            ],
        ).await?;

        Ok(serde_json::to_string_pretty(&result)?)
    }

    /// Fetch all records within a block range via JSON-RPC `records/all`.
    ///
    /// Returns raw record ciphertexts that must be decrypted with a view key.
    pub async fn fetch_all_records(&self, start: u32, end: u32, page: u32, per_page: u32) -> Result<Value> {
        let params = serde_json::json!({
            "start": start,
            "end": end,
            "page": page,
            "recordsPerRequest": per_page,
        });
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "records/all",
            "params": params,
        });
        let mut headers = Self::headers();
        headers.insert("Content-Type", "application/json".parse().unwrap());

        let resp = self.inner.post(&self.rpc_url).headers(headers).json(&body).send().await?;
        let text = resp.text().await?;
        let v: Value = serde_json::from_str(&text).context("Failed to parse records/all response")?;
        if let Some(err) = v.get("error") {
            anyhow::bail!("records/all error: {err}");
        }
        v.get("result").cloned().context("records/all response missing result")
    }

    /// Find unspent `credits.aleo` record ciphertexts owned by the given view key.
    /// Scans recent blocks via `records/all`, decrypts each record, and returns
    /// those containing `credits.aleo` with the owner matching the view key's address.
    pub async fn find_private_credits_records(
        &self,
        view_key: &str,
    ) -> Result<Vec<(String, u64)>> {
        use snarkvm::console::program::Record;
        use snarkvm::prelude::Ciphertext;
        use std::str::FromStr;

        let vk = snarkvm::prelude::ViewKey::<TestnetV0>::from_str(view_key)?;
        let owner_addr = vk.to_address();

        let height = self.fetch_block_height().await?;
        let start = height.saturating_sub(100_000); // scan last ~100K blocks
        let mut results = Vec::new();

        tracing::info!("Scanning blocks {start}..{height} for private records...");
        let records = self.fetch_all_records(start, height, 0, 500).await?;

        if let Some(arr) = records.as_array() {
            for record_entry in arr {
                let program_id = record_entry["program_id"].as_str().unwrap_or("");
                if program_id != "credits.aleo" {
                    continue;
                }
                let ciphertext_str = record_entry["record_ciphertext"].as_str().unwrap_or("");
                if ciphertext_str.is_empty() {
                    continue;
                }
                // Try to parse and decrypt
                if let Ok(record) = Record::<TestnetV0, Ciphertext<TestnetV0>>::from_str(ciphertext_str) {
                    if let Ok(decrypted) = record.decrypt(&vk) {
                        // Check owner matches
                        if *decrypted.owner() == snarkvm::prelude::Owner::Public(owner_addr)
                            || *decrypted.owner() == snarkvm::prelude::Owner::Private(
                                snarkvm::prelude::Plaintext::from(
                                    snarkvm::prelude::Literal::Address(owner_addr),
                                ),
                            )
                        {
                            // Extract microcredits from data
                            for (id, entry) in decrypted.data().iter() {
                                if id.to_string() == "microcredits" {
                                    let amount_str = entry.to_string().replace("u64", "").trim().to_string();
                                    if let Ok(amount) = amount_str.parse::<u64>() {
                                        results.push((ciphertext_str.to_string(), amount));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Sort by amount descending
        results.sort_by(|a, b| b.1.cmp(&a.1));
        Ok(results)
    }
}

/// Custom query returning a fixed state root (bypasses ureq/WAF issues).
#[derive(Clone, Debug)]
pub struct FixedStateRootQuery<N: Network> {
    pub state_root: N::StateRoot,
    pub block_height: u32,
}

#[async_trait(?Send)]
impl<N: Network> QueryTrait<N> for FixedStateRootQuery<N> {
    fn current_state_root(&self) -> Result<N::StateRoot> {
        Ok(self.state_root)
    }
    fn current_block_height(&self) -> Result<u32> {
        Ok(self.block_height)
    }
    fn get_state_path_for_commitment(&self, _commitment: &Field<N>) -> Result<StatePath<N>> {
        StatePath::from_str("").or_else(|_| anyhow::bail!("State path not available"))
    }
    fn get_state_paths_for_commitments(&self, _commitments: &[Field<N>]) -> Result<Vec<StatePath<N>>> {
        Ok(Vec::new())
    }
    async fn current_state_root_async(&self) -> Result<N::StateRoot> {
        Ok(self.state_root)
    }
    async fn current_block_height_async(&self) -> Result<u32> {
        Ok(self.block_height)
    }
    async fn get_state_path_for_commitment_async(&self, _commitment: &Field<N>) -> Result<StatePath<N>> {
        StatePath::from_str("").or_else(|_| anyhow::bail!("State path not available"))
    }
    async fn get_state_paths_for_commitments_async(&self, _commitments: &[Field<N>]) -> Result<Vec<StatePath<N>>> {
        Ok(Vec::new())
    }
}
