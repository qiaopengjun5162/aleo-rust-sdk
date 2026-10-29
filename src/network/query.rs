//! `snarkVM` `QueryTrait` implementations used during proving.
//!
//! Proving needs Merkle state paths for the commitments a transition touches.
//! snarkVM defines the [`QueryTrait`] abstraction for that; this module supplies
//! two implementations:
//!
//! - [`ProvableQuery`] — fetches real paths from Provable API v2 (production).
//! - [`FixedStateRootQuery`] — returns a pinned root and no paths (offline/tests).

use anyhow::Result;
use async_trait::async_trait;
use snarkvm::ledger::query::QueryTrait;
use snarkvm::prelude::{Field, Network, StatePath, TestnetV0};
use std::str::FromStr;

use super::BROWSER_UA;

/// Blocking GET with the browser User-Agent, returning the raw body.
///
/// `ureq` is used rather than `reqwest` because `QueryTrait::get_state_path_*`
/// are synchronous and called from inside snarkVM's prover, which is not an
/// async context. Cloudflare rejects `ureq`'s default agent, hence the shared
/// [`BROWSER_UA`].
fn ureq_get_text(label: &str, url: &str) -> Result<String> {
    let response = ureq::get(url)
        .set("User-Agent", BROWSER_UA)
        .set("Accept", "application/json")
        .call()
        .map_err(|e| anyhow::anyhow!("Provable {label} GET {url} failed: {e}"))?;
    response
        .into_string()
        .map_err(|e| anyhow::anyhow!("Failed to read {label} response from {url}: {e}"))
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
    fn get_state_paths_for_commitments(
        &self,
        _commitments: &[Field<N>],
    ) -> Result<Vec<StatePath<N>>> {
        Ok(Vec::new())
    }
    async fn current_state_root_async(&self) -> Result<N::StateRoot> {
        Ok(self.state_root)
    }
    async fn current_block_height_async(&self) -> Result<u32> {
        Ok(self.block_height)
    }
    async fn get_state_path_for_commitment_async(
        &self,
        _commitment: &Field<N>,
    ) -> Result<StatePath<N>> {
        StatePath::from_str("").or_else(|_| anyhow::bail!("State path not available"))
    }
    async fn get_state_paths_for_commitments_async(
        &self,
        _commitments: &[Field<N>],
    ) -> Result<Vec<StatePath<N>>> {
        Ok(Vec::new())
    }
}

/// A custom query that fetches Merkle state paths from the Provable API v2
/// `statePath/{commitment}` endpoint during `trace.prepare()`.
///
/// The state root returned by `current_state_root()` is cached from the most
/// recently fetched state path — ensuring the Merkle proof and the root it
/// verifies against are consistent.
#[derive(Debug)]
pub struct ProvableQuery {
    pub state_root: <TestnetV0 as Network>::StateRoot,
    pub block_height: u32,
    /// Provable API v2 base URL (e.g. `https://api.provable.com/v2/testnet`)
    pub api_base_url: String,
    /// Cached state root extracted from the most recently fetched state path.
    /// `current_state_root()` returns this cached value so the Merkle proof
    /// verifies against the same root.
    last_state_root: std::sync::Mutex<Option<<TestnetV0 as Network>::StateRoot>>,
}

impl Clone for ProvableQuery {
    fn clone(&self) -> Self {
        Self {
            state_root: self.state_root,
            block_height: self.block_height,
            api_base_url: self.api_base_url.clone(),
            // Each clone gets a fresh empty cache — it will be populated lazily
            // on the first get_state_path_for_commitment call.
            last_state_root: std::sync::Mutex::new(None),
        }
    }
}

impl ProvableQuery {
    /// Lock the state-root cache, recovering from a poisoned mutex.
    ///
    /// The guarded value is a cache that gets overwritten on the next
    /// `statePath` fetch, so poisoning carries no useful information. Using
    /// `.unwrap()` here would mean that one panic anywhere under this lock
    /// makes every subsequent call panic forever — turning a single transient
    /// failure into a permanently unusable query object.
    fn lock_state_root(
        &self,
    ) -> std::sync::MutexGuard<'_, Option<<TestnetV0 as Network>::StateRoot>> {
        self.last_state_root.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn new(
        state_root: <TestnetV0 as Network>::StateRoot,
        block_height: u32,
        api_base_url: &str,
    ) -> Self {
        Self {
            state_root,
            block_height,
            api_base_url: api_base_url.trim_end_matches('/').to_string(),
            last_state_root: std::sync::Mutex::new(None),
        }
    }
}

#[async_trait(?Send)]
impl QueryTrait<TestnetV0> for ProvableQuery {
    fn current_state_root(&self) -> Result<<TestnetV0 as Network>::StateRoot> {
        // Return the root cached from the most recently fetched state path.
        // This ensures the Merkle proof returned by get_state_path_for_commitment
        // verifies against the same root.
        let guard = self.lock_state_root();
        match *guard {
            Some(root) => Ok(root),
            None => Ok(self.state_root),
        }
    }
    fn current_block_height(&self) -> Result<u32> {
        Ok(self.block_height)
    }
    fn get_state_path_for_commitment(
        &self,
        commitment: &Field<TestnetV0>,
    ) -> Result<StatePath<TestnetV0>> {
        let url = format!("{}/statePath/{commitment}", self.api_base_url);
        let body = ureq_get_text("statePath", &url)?;
        // Provable returns state path as a quoted string.
        let trimmed = body.trim().trim_matches('"');
        let path = StatePath::<TestnetV0>::from_str(trimmed)
            .map_err(|e| anyhow::anyhow!("Failed to parse state path from '{trimmed}': {e}"))?;
        // Cache the global state root embedded in the path so current_state_root
        // returns the same root the Merkle proof was built against.
        let path_root = path.global_state_root();
        let mut guard = self.lock_state_root();
        *guard = Some(path_root);
        Ok(path)
    }
    fn get_state_paths_for_commitments(
        &self,
        commitments: &[Field<TestnetV0>],
    ) -> Result<Vec<StatePath<TestnetV0>>> {
        if commitments.is_empty() {
            return Ok(Vec::new());
        }
        let cm_strings: Vec<String> = commitments.iter().map(|c| c.to_string()).collect();
        let url = format!(
            "{}/statePaths?commitments={}",
            self.api_base_url,
            cm_strings.join(",")
        );
        let body = ureq_get_text("statePaths", &url)?;
        serde_json::from_str(&body)
            .map_err(|e| anyhow::anyhow!("Failed to parse state paths from '{body}': {e}"))
    }
    async fn current_state_root_async(&self) -> Result<<TestnetV0 as Network>::StateRoot> {
        // Must match the sync version: return the root cached from the last
        // `statePath` fetch so the Merkle proof and the root agree.
        let guard = self.lock_state_root();
        Ok((*guard).unwrap_or(self.state_root))
    }
    async fn current_block_height_async(&self) -> Result<u32> {
        Ok(self.block_height)
    }
    async fn get_state_path_for_commitment_async(
        &self,
        commitment: &Field<TestnetV0>,
    ) -> Result<StatePath<TestnetV0>> {
        self.get_state_path_for_commitment(commitment)
    }
    async fn get_state_paths_for_commitments_async(
        &self,
        commitments: &[Field<TestnetV0>],
    ) -> Result<Vec<StatePath<TestnetV0>>> {
        self.get_state_paths_for_commitments(commitments)
    }
}
