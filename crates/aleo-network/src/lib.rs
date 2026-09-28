/// Aleo Network — RPC client for interacting with Aleo blockchain nodes.
///
/// Features:
/// - Browser-like fingerprint to bypass Cloudflare WAF on public endpoints
/// - Fetch programs, state roots, broadcast transactions
/// - Poll for transaction confirmation

use anyhow::{Context, Result};
use async_trait::async_trait;
use snarkvm::ledger::query::QueryTrait;
use snarkvm::prelude::{Field, Network, Program, StatePath, TestnetV0};
use std::io::Write;
use std::str::FromStr;

/// Browser-like User-Agent to bypass Cloudflare WAF.
const UA: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

/// HTTP client with browser-like headers for Aleo network interaction.
#[derive(Clone, Debug)]
pub struct AleoHttpClient {
    pub base_url: String,
    inner: reqwest::Client,
}

impl AleoHttpClient {
    /// Create a new client for the given node URL.
    pub fn new(base_url: &str) -> Result<Self> {
        let inner = reqwest::Client::builder()
            .http1_only()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .context("Failed to build HTTP client")?;
        Ok(Self { base_url: base_url.trim_end_matches('/').to_string(), inner })
    }

    fn headers() -> reqwest::header::HeaderMap {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert("User-Agent", UA.parse().unwrap());
        h.insert("Accept", "application/json, text/plain, */*".parse().unwrap());
        h
    }

    /// Fetch a program from the network.
    pub async fn fetch_program(&self, program_id: &str) -> Result<Program<TestnetV0>> {
        let url = format!("{}/program/{}", self.base_url, program_id);
        tracing::info!("GET {}", url);

        let text = self.inner.get(&url).headers(Self::headers()).send().await?.text().await?;

        let clean = text.trim_matches('"').replace("\\n", "\n");
        Program::<TestnetV0>::from_str(&clean).context("Failed to parse program")
    }

    /// Fetch latest state root + block height.
    pub async fn fetch_state_root(&self) -> Result<(<TestnetV0 as Network>::StateRoot, u32)> {
        let url = format!("{}/stateRoot/latest", self.base_url);
        let text = self.inner.get(&url).headers(Self::headers()).send().await?.text().await?;

        let root_str = text.trim_matches('"');
        let state_root = <TestnetV0 as Network>::StateRoot::from_str(root_str)
            .context("Failed to parse state root")?;

        let height_url = format!("{}/block/height/latest", self.base_url);
        let height_text = self.inner.get(&height_url).headers(Self::headers()).send().await?.text().await?;
        let height: u32 = height_text.trim().parse()?;

        Ok((state_root, height))
    }

    /// Broadcast a JSON-serialized transaction.
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
            anyhow::bail!("Broadcast rejected ({}): {}", status, body);
        }
        Ok(body)
    }

    /// Poll for confirmation (up to 30 attempts, 5s apart).
    pub async fn wait_for_confirmation(&self, tx_id: &str) -> Result<()> {
        let check_url = format!("{}/transaction/{}", self.base_url, tx_id);
        tracing::info!("Waiting for confirmation... (polling every 5s)");

        for _ in 1..=30 {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

            match self.inner.get(&check_url).headers(Self::headers()).send().await {
                Ok(res) if res.status().is_success() => {
                    tracing::info!("Confirmed on chain!");
                    tracing::info!("🔗 https://testnet.explorer.provable.com/transaction/{}", tx_id);
                    return Ok(());
                }
                _ => {
                    print!(".");
                    std::io::stdout().flush().ok();
                }
            }
        }
        anyhow::bail!("Timed out waiting for confirmation of {}", tx_id)
    }
}

/// Custom query returning a fixed state root (bypasses ureq/WAF).
#[derive(Clone, Debug)]
pub struct FixedStateRootQuery<N: Network> {
    pub state_root: N::StateRoot,
    pub block_height: u32,
}

#[async_trait(?Send)]
impl<N: Network> QueryTrait<N> for FixedStateRootQuery<N> {
    fn current_state_root(&self) -> Result<N::StateRoot> {
        Ok(self.state_root.clone())
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
        Ok(self.state_root.clone())
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
