//! # Aleo Network — transport and Merkle-query layer.
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
//! ## Layout
//!
//! This module is split into two private submodules, both re-exported here:
//!
//! | Item | Submodule | Role |
//! |------|-----------|------|
//! | [`AleoHttpClient`] | `client` | Async REST + JSON-RPC transport (`reqwest`) |
//! | [`ProvableQuery`] | `query` | Live Merkle state paths for proving (`ureq`) |
//! | [`FixedStateRootQuery`] | `query` | Offline stub that returns a pinned root |
//!
//! This layer is **pure transport**. Anything that interprets what a record
//! *means* (decryption, owner matching, coin selection) lives in
//! [`record`](crate::record); anything that sequences a workflow lives in
//! [`AleoClient`](crate::AleoClient).
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

mod client;
mod query;

pub use client::AleoHttpClient;
pub use query::{FixedStateRootQuery, ProvableQuery};

/// Browser-like User-Agent to bypass Cloudflare WAF.
///
/// Shared by both transports: the async `reqwest` client and the blocking
/// `ureq` calls used during proving. Cloudflare rejects the default
/// `ureq`/`reqwest` agents, and duplicating this literal is how the copies
/// silently drift apart.
pub(crate) const BROWSER_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
