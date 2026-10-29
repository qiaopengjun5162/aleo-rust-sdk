//! Async REST + JSON-RPC transport for Aleo nodes.
//!
//! See [`super`] for the endpoint map and for the two Merkle-query types that
//! live alongside this client.

use anyhow::{Context, Result};
use serde_json::Value;
use snarkvm::prelude::{Network, Program, TestnetV0};
use std::str::FromStr;

use super::BROWSER_UA;

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
        let mut builder = reqwest::Client::builder()
            .http1_only()
            .timeout(std::time::Duration::from_secs(120));

        // Certificate verification is ON by default. Behind a corporate TLS
        // intercepting proxy you can opt out with ALEO_INSECURE_TLS=1 — but
        // never disable it silently: this client signs and broadcasts
        // transactions, so a MITM can steal funds.
        if std::env::var("ALEO_INSECURE_TLS")
            .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        {
            tracing::warn!("ALEO_INSECURE_TLS is set — TLS certificate verification is DISABLED");
            builder = builder.danger_accept_invalid_certs(true);
        }

        // Respect HTTP_PROXY / HTTPS_PROXY env vars (e.g. Clash at 127.0.0.1:7890).
        // No manual proxy detection needed — reqwest 0.12 respects these by default
        // when Proxy::system() is used. We set custom() to control exactly.
        if let Ok(proxy_url) = std::env::var("HTTP_PROXY")
            .or_else(|_| std::env::var("http_proxy"))
            .or_else(|_| std::env::var("HTTPS_PROXY"))
            .or_else(|_| std::env::var("https_proxy"))
            && let Ok(proxy) =
                reqwest::Proxy::http(&proxy_url).or_else(|_| reqwest::Proxy::all(&proxy_url))
        {
            builder = builder.proxy(proxy);
        }

        let inner = builder.build().context("Failed to build HTTP client")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            rpc_url: rpc_url.trim_end_matches('/').to_string(),
            inner,
        })
    }

    fn headers() -> reqwest::header::HeaderMap {
        use reqwest::header::{ACCEPT, HeaderValue, USER_AGENT};
        let mut h = reqwest::header::HeaderMap::new();
        // Static literals go through `from_static`: no runtime parsing, no
        // `unwrap()`. `parse().unwrap()` on a constant is a latent panic that
        // a future edit to the constant would turn into a crash.
        h.insert(USER_AGENT, HeaderValue::from_static(BROWSER_UA));
        h.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/plain, */*"),
        );
        h
    }

    /// JSON headers (`Content-Type: application/json`) — required by both the
    /// JSON-RPC POST and the broadcast POST.
    fn json_headers() -> reqwest::header::HeaderMap {
        let mut headers = Self::headers();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        headers
    }

    /// Helper: JSON-RPC POST call.
    async fn json_rpc(&self, method: &str, params: Vec<Value>) -> Result<Value> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let resp = self
            .inner
            .post(&self.rpc_url)
            .headers(Self::json_headers())
            .json(&body)
            .send()
            .await?;
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
    ///
    /// Uses `?check_transaction=true` so the node runs `check_transaction_basic`
    /// and returns a detailed error message if the transaction is invalid,
    /// rather than silently dropping it after accepting the broadcast.
    ///
    /// The Cloud API at `api.explorer.provable.com/v2/testnet/transaction/broadcast` (singular)
    /// matches the snarkOS node REST route definition in `node/rest/src/lib.rs:337`.
    pub async fn broadcast_transaction(&self, tx_json: String) -> Result<String> {
        let url = format!(
            "{}/transaction/broadcast?check_transaction=true",
            self.base_url
        );
        let mut headers = Self::json_headers();
        headers.insert(
            reqwest::header::ORIGIN,
            reqwest::header::HeaderValue::from_static("https://explorer.provable.com"),
        );
        headers.insert(
            reqwest::header::REFERER,
            reqwest::header::HeaderValue::from_static("https://explorer.provable.com/"),
        );

        let resp = self.inner.post(&url).headers(headers).body(tx_json).send().await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            anyhow::bail!("Broadcast rejected ({status}): {body}");
        }
        Ok(body)
    }

    /// Fetch a transaction by its ID from the explorer API.
    /// Returns the raw JSON response as a String.
    pub async fn fetch_transaction(&self, tx_id: &str) -> Result<String> {
        let url = format!("{}/transaction/{tx_id}", self.base_url);
        let res = self.inner.get(&url).headers(Self::headers()).send().await?;
        let body = res.text().await?;
        Ok(body)
    }

    /// Poll for confirmation (up to 30 attempts, 5s apart).
    ///
    /// Checks that the transaction response contains a `block_hash` field,
    /// which is the only reliable indicator that the transaction has been
    /// included in a block on Provable's testnet V2 API. A plain HTTP 200
    /// only means the API accepted the transaction (it may still be in the
    /// mempool waiting for a validator to pack it).
    pub async fn wait_for_confirmation(&self, tx_id: &str) -> Result<()> {
        let check_url = format!("{}/transaction/{tx_id}", self.base_url);
        tracing::info!("Waiting for confirmation... (polling every 5s)");

        for _ in 1..=30 {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

            match self.inner.get(&check_url).headers(Self::headers()).send().await {
                Ok(res) if res.status().is_success() => {
                    let body = res.text().await.unwrap_or_default();
                    if body.contains("\"block_hash\"") {
                        tracing::info!("Confirmed on chain!");
                        tracing::info!(
                            "🔗 https://testnet.explorer.provable.com/transaction/{tx_id}"
                        );
                        return Ok(());
                    }
                    // Transaction accepted by API but not yet in a block
                    tracing::debug!("not yet confirmed (attempt)");
                }
                _ => {
                    tracing::debug!("confirmation poll failed");
                }
            }
        }
        anyhow::bail!("Timed out waiting for confirmation of {tx_id}")
    }

    // ── On-chain state queries ──────────────────────────────────────────

    /// GET a mapping entry and return the raw body, or `None` when the key is
    /// absent (the API answers 404).
    ///
    /// Both public mapping helpers below resolve to the *same* REST route and
    /// the same "4xx means absent" rule; the only difference between them is
    /// whether the body is parsed as a `u64`. This is the single place that
    /// knows the route, so the two cannot drift.
    async fn mapping_value_raw(
        &self,
        program_id: &str,
        mapping_name: &str,
        key: &str,
    ) -> Result<Option<String>> {
        let url = format!(
            "{}/program/{program_id}/mapping/{mapping_name}/{key}",
            self.base_url
        );
        let resp = self.inner.get(&url).headers(Self::headers()).send().await?;
        if resp.status().is_client_error() {
            return Ok(None); // 404 = no entry
        }
        Ok(Some(resp.text().await?))
    }

    /// Query a numeric mapping value (`credits.aleo/account`).
    ///
    /// Returns `None` if the key does not exist (404), or if the body is not a
    /// `u64` — the latter is logged, because a value that does not parse means
    /// the response format changed, not that the account is empty.
    pub async fn fetch_mapping_value_rest(
        &self,
        program_id: &str,
        mapping_name: &str,
        key: &str,
    ) -> Result<Option<u64>> {
        let Some(text) = self.mapping_value_raw(program_id, mapping_name, key).await? else {
            return Ok(None);
        };
        let cleaned = text.trim().trim_matches('"').replace("u64", "");
        match cleaned.parse::<u64>() {
            Ok(v) => Ok(Some(v)),
            Err(e) => {
                tracing::warn!("Failed to parse REST mapping value '{text}': {e}");
                Ok(None)
            }
        }
    }

    /// Query a mapping value as its raw serialized string.
    ///
    /// Use this for mappings whose values are not `u64` (structs, addresses,
    /// other plaintext literals). Returns `None` on 404.
    pub async fn fetch_mapping_value(
        &self,
        program_id: &str,
        mapping_name: &str,
        key: &str,
    ) -> Result<Option<String>> {
        self.mapping_value_raw(program_id, mapping_name, key).await
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

        let result = self
            .json_rpc(
                "records/isOwner",
                vec![
                    Value::String(view_key.to_string()),
                    Value::Number(serde_json::Number::from(start)),
                    Value::Number(serde_json::Number::from(height)),
                ],
            )
            .await?;

        Ok(serde_json::to_string_pretty(&result)?)
    }

    /// Fetch all records within a block range via JSON-RPC `records/all`.
    ///
    /// Returns raw record ciphertexts that must be decrypted with a view key —
    /// see [`RecordScanner`](crate::record::RecordScanner) for that half.
    pub async fn fetch_all_records(
        &self,
        start: u32,
        end: u32,
        page: u32,
        per_page: u32,
    ) -> Result<Value> {
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

        let resp = self
            .inner
            .post(&self.rpc_url)
            .headers(Self::json_headers())
            .json(&body)
            .send()
            .await?;
        let text = resp.text().await?;
        let v: Value =
            serde_json::from_str(&text).context("Failed to parse records/all response")?;
        if let Some(err) = v.get("error") {
            anyhow::bail!("records/all error: {err}");
        }
        v.get("result").cloned().context("records/all response missing result")
    }

    // ── Stablecoin API methods ──────────────────────────────────────────

    /// Fetch the Merkle tree for a compliant stablecoin (USAD/USDCx) from the Provable API.
    ///
    /// Endpoint: `GET /v2/{network}/stablecoin/{stablecoin}/merkle-tree`
    ///
    /// Returns the freeze list as an array of decimal strings representing U256 values,
    /// which can be converted to `Field` via `SealanceMerkleTree::convert_tree_to_fields`.
    pub async fn fetch_stablecoin_merkle_tree(&self, stablecoin: &str) -> Result<Vec<String>> {
        let url = format!("{}/stablecoin/{}/merkle-tree", self.base_url, stablecoin);
        tracing::info!("GET {url}");
        let text = self.inner.get(&url).headers(Self::headers()).send().await?.text().await?;

        let tree: Vec<String> = serde_json::from_str(&text)
            .context("Failed to parse stablecoin Merkle tree response")?;
        Ok(tree)
    }
}
