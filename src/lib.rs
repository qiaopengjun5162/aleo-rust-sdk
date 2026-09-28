//! # Aleo Rust SDK
//!
//! A comprehensive Rust SDK for interacting with the [Aleo](https://aleo.org) blockchain.
//! Provides tools for account management, program loading, local execution, proof generation,
//! network querying, and transaction broadcasting.
//!
//! ## Architecture
//!
//! The SDK is organized into five modules, each wrapping a layer of the Aleo stack:
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`account`] | Key chain: `PrivateKey → ViewKey → ComputeKey → Address` |
//! | [`program`] | Load, parse, and inspect Aleo programs |
//! | [`execution`] | Authorize, execute, prove, and package transactions |
//! | [`network`] | HTTP client for Aleo v2 JSON-RPC and REST endpoints |
//! | [`client`] | High-level `AleoClient` orchestrating the full lifecycle |
//!
//! ## Quick Start
//!
//! ```no_run
//! use aleo_rust_sdk::{AleoClient, AleoAccount};
//! use snarkvm::prelude::TestRng;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let mut rng = TestRng::default();
//!     let client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;
//!
//!     // Create a random account
//!     let account = AleoAccount::new_random(&mut rng)?;
//!     println!("Address: {}", account.address_str());
//!
//!     // Query the network
//!     let height = client.get_block_height().await?;
//!     println!("Block height: {height}");
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Feature flags
//!
//! None yet — all features are built-in. The heavy lifting dependency is
//! [snarkVM](https://github.com/ProvableHQ/snarkVM) for zero-knowledge proving.

pub mod account;
pub mod client;
pub mod execution;
pub mod network;
pub mod program;

// Re-export the main types at the crate root for convenience
pub use account::AleoAccount;
pub use client::AleoClient;
pub use execution::ExecutionEngine;
pub use network::{AleoHttpClient, FixedStateRootQuery};
pub use program::AleoProgram;
