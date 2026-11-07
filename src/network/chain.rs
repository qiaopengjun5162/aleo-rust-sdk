//! Chain reads: blocks, transactions, program metadata, committees, mempool.
//!
//! Everything here is a `GET` against the node REST API. The routes were taken
//! from `node/rest/src/{lib,routes}.rs` in snarkOS and then checked against the
//! live endpoint, because the published SDK docs and the deployed service
//! disagree in at least one place that matters — see
//! [`AleoHttpClient::fetch_block_range`].
//!
//! Object responses come back as [`serde_json::Value`] rather than parsed
//! snarkVM types: a block's JSON is hundreds of kilobytes and is the node's
//! stable public contract, while the in-memory type changes with every snarkVM
//! release. Endpoints that answer with a single id (a hash, a transition id)
//! are returned as strings, and a body that is not a JSON string is an error —
//! an id that was never fetched must not look like one that was.

use anyhow::{Context, Result};
use serde_json::Value;

use super::AleoHttpClient;

/// How many blocks one `/blocks` call may cover.
///
/// The Cloud API rejects a range wider than this with a 400 ("Range must be 50
/// blocks or less"); [`AleoHttpClient::fetch_block_range`] chunks to stay under
/// it rather than surfacing the limit to callers.
pub const MAX_BLOCKS_PER_REQUEST: u32 = 50;

impl AleoHttpClient {
    // ── Blocks ──────────────────────────────────────────────────────────

    /// Fetch the latest block.
    pub async fn fetch_latest_block(&self) -> Result<Value> {
        let url = format!("{}/block/latest", self.base_url);
        self.get_json(&url).await
    }

    /// Fetch a block by height **or** by hash — the node serves both from one
    /// route, so there is no separate `fetch_block_by_hash`.
    ///
    /// A height the node does not have yet is an error, not an empty block.
    pub async fn fetch_block(&self, height_or_hash: &str) -> Result<Value> {
        let url = format!("{}/block/{height_or_hash}", self.base_url);
        self.get_json(&url).await
    }

    /// Fetch the hash of the latest block.
    pub async fn fetch_latest_block_hash(&self) -> Result<String> {
        let url = format!("{}/block/hash/latest", self.base_url);
        self.get_json_string(&url).await
    }

    /// Height of a block, given its hash.
    ///
    /// The inverse of [`Self::fetch_latest_block_hash`]; useful for turning a
    /// hash handed out by an explorer into the height a consensus-version
    /// lookup needs.
    pub async fn fetch_block_height_of_hash(&self, block_hash: &str) -> Result<u32> {
        let url = format!("{}/height/{block_hash}", self.base_url);
        let text = self.get_text_checked(&url).await?;
        text.trim()
            .parse()
            .with_context(|| format!("height for {block_hash} is not a u32: {text}"))
    }

    /// Fetch the transactions of one block, by height or hash.
    pub async fn fetch_block_transactions(&self, height_or_hash: &str) -> Result<Value> {
        let url = format!("{}/block/{height_or_hash}/transactions", self.base_url);
        self.get_json(&url).await
    }

    /// Fetch a range of blocks, half-open (`start..end`).
    ///
    /// ## The wire is not half-open
    ///
    /// The Cloud API treats `end` as **inclusive**: `?start=20962820&end=20962822`
    /// returns three blocks, and `?start=20962700&end=20962749` returns fifty.
    /// snarkOS's own handler (`get_blocks`) treats it as exclusive — it iterates
    /// `start..end`. Those cannot both be satisfied with one parameter, so this
    /// method follows Rust conventions (`start..end`) and sends `end - 1`,
    /// which is correct for the Cloud API that [`AleoHttpClient::new`] points at
    /// by default. Against a raw snarkOS node the last block of each chunk is
    /// lost; that is the price of a single translation rule, and it is why the
    /// translation is asserted in `tests/network_coverage.rs` rather than left
    /// implicit.
    ///
    /// ## Chunking
    ///
    /// The API refuses ranges wider than [`MAX_BLOCKS_PER_REQUEST`]. Longer
    /// ranges are fetched in windows of that size, and a window that comes back
    /// short is an error: a node that is behind would otherwise turn "give me
    /// 500 blocks" into a silently truncated answer.
    ///
    /// `start == end` is an empty range and performs no request.
    pub async fn fetch_block_range(&self, start: u32, end: u32) -> Result<Vec<Value>> {
        if end <= start {
            return Ok(Vec::new());
        }

        let mut blocks = Vec::new();
        let mut cursor = start;
        while cursor < end {
            let chunk_end = end.min(cursor.saturating_add(MAX_BLOCKS_PER_REQUEST));
            let wire_end = chunk_end - 1;
            let url = format!("{}/blocks?start={cursor}&end={wire_end}", self.base_url);

            let page: Vec<Value> = serde_json::from_str(&self.get_text_checked(&url).await?)
                .with_context(|| format!("GET {url} did not return an array of blocks"))?;

            let expected = (chunk_end - cursor) as usize;
            if page.len() != expected {
                anyhow::bail!(
                    "GET {url} returned {} blocks for a {expected}-block range; \
                     the node is behind the requested range",
                    page.len()
                );
            }

            blocks.extend(page);
            cursor = chunk_end;
        }
        Ok(blocks)
    }

    // ── Programs ────────────────────────────────────────────────────────

    /// Names of a program's mappings, in the order the node reports them.
    ///
    /// A body that is not an array of strings is an error rather than an empty
    /// list: "no mappings" and "the response shape changed" must not look the
    /// same.
    pub async fn fetch_mapping_names(&self, program_id: &str) -> Result<Vec<String>> {
        let url = format!("{}/program/{program_id}/mappings", self.base_url);
        let value = self.get_json(&url).await?;
        let Value::Array(items) = value else {
            anyhow::bail!("GET {url}: expected an array of mapping names, got {value}");
        };
        items
            .into_iter()
            .map(|item| match item {
                Value::String(name) => Ok(name),
                other => Err(anyhow::anyhow!(
                    "GET {url}: mapping name is not a string: {other}"
                )),
            })
            .collect()
    }

    /// The latest edition of a program on chain (0 for a program deployed once).
    pub async fn fetch_latest_program_edition(&self, program_id: &str) -> Result<u16> {
        let url = format!("{}/program/{program_id}/latest_edition", self.base_url);
        let text = self.get_text_checked(&url).await?;
        text.trim()
            .parse()
            .with_context(|| format!("latest edition of {program_id} is not a u16: {text}"))
    }

    /// Transaction ID of the deployment that put `program_id` on chain.
    pub async fn fetch_deployment_transaction_id(&self, program_id: &str) -> Result<String> {
        let url = format!(
            "{}/find/transactionID/deployment/{program_id}",
            self.base_url
        );
        self.get_json_string(&url).await
    }

    // ── Transactions ────────────────────────────────────────────────────

    /// Fetch a transaction that is confirmed on chain.
    ///
    /// Distinct from [`AleoHttpClient::fetch_transaction`], which returns the
    /// body of `/transaction/{id}` whatever it holds. This one hits
    /// `/transaction/confirmed/{id}`, so an unconfirmed id is a 404 instead of a
    /// JSON object whose shape the caller has to inspect.
    pub async fn fetch_confirmed_transaction(&self, tx_id: &str) -> Result<Value> {
        let url = format!("{}/transaction/confirmed/{tx_id}", self.base_url);
        self.get_json(&url).await
    }

    /// The transition that contains an input or output id.
    ///
    /// Note the direction: this maps an input/output id to a transition id. The
    /// reverse (`/find/transactionID/{transition_id}`) is a different route and
    /// is not wrapped here.
    pub async fn fetch_transition_id(&self, input_or_output_id: &str) -> Result<String> {
        let url = format!("{}/find/transitionID/{input_or_output_id}", self.base_url);
        self.get_json_string(&url).await
    }

    // ── Committee and mempool ───────────────────────────────────────────

    /// The current committee (validator set, stakes and rounds).
    pub async fn fetch_committee(&self) -> Result<Value> {
        let url = format!("{}/committee/latest", self.base_url);
        self.get_json(&url).await
    }

    /// The committee as of a specific block height.
    pub async fn fetch_committee_at(&self, height: u32) -> Result<Value> {
        let url = format!("{}/committee/{height}", self.base_url);
        self.get_json(&url).await
    }

    /// Transactions currently in a node's memory pool.
    ///
    /// Only a validator exposes this route — the Cloud API answers 404, which
    /// is a property of the endpoint and not something to work around. Use it
    /// against a node whose `base_url` points at `/v2/{network}` on a validator.
    pub async fn fetch_mempool_transactions(&self) -> Result<Value> {
        let url = format!("{}/memoryPool/transactions", self.base_url);
        self.get_json(&url).await
    }

    // ── Balances ────────────────────────────────────────────────────────

    /// Public balance of an address in microcredits (`credits.aleo/account`).
    ///
    /// A missing mapping entry means the address was never paid, so 0 is the
    /// right answer there. A body that is present but not a `u64` is an error:
    /// reporting 0 for it is how a funded account comes to look drained.
    pub async fn fetch_public_balance(&self, address: &str) -> Result<u64> {
        let Some(text) = self.mapping_value_raw("credits.aleo", "account", address).await? else {
            return Ok(0);
        };
        let cleaned = text.trim().trim_matches('"');
        let digits = cleaned.strip_suffix("u64").unwrap_or(cleaned);
        digits.parse().with_context(|| {
            format!(
                "credits.aleo/account for {address} is not a u64: {}",
                crate::hosted::truncate(&text)
            )
        })
    }
}
