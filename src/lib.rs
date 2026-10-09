//! # Aleo Rust SDK
//!
//! A comprehensive **Rust SDK** for interacting with the [Aleo](https://aleo.org) blockchain.
//! Provides tools for account management, program loading, local zero-knowledge execution,
//! proof generation, network querying, and transaction broadcasting.
//!
//! Built on top of [snarkVM 4.10.0](https://github.com/ProvableHQ/snarkVM) for zero-knowledge
//! proving and [reqwest](https://crates.io/crates/reqwest) for async HTTP.
//!
//! ## Architecture
//!
//! The SDK is organized into five modules:
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`account`] | Key chain: `PrivateKey → ViewKey → ComputeKey → Address` |
//! | [`program`] | Load, parse, and inspect Aleo programs |
//! | [`execution`] | Authorize, execute, prove, and package transactions |
//! | [`network`] | HTTP client for Aleo v2 JSON-RPC and REST endpoints |
//! | [`record`] | Record discovery, decryption, and coin selection |
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
//! All features are built-in. The heavy lifting dependency is
//! [snarkVM](https://github.com/ProvableHQ/snarkVM) for zero-knowledge proving.
//!
//! ## Related crates
//!
//! - [`aleo-cli`](https://crates.io/crates/aleo-cli) — CLI tool built on this SDK
//! - [`snarkvm`](https://crates.io/crates/snarkvm) — Zero-knowledge VM for Aleo
//!
//! ## License
//!
//! Licensed under MIT OR Apache-2.0.

pub mod account;
pub mod client;
pub mod error;
pub mod execution;
pub mod network;
pub mod program;
pub mod record;
pub mod sealance;

// Re-export the main types at the crate root for convenience
pub use account::AleoAccount;
pub use client::AleoClient;
pub use error::AleoError;
pub use execution::ExecutionEngine;
pub use network::{AleoHttpClient, FixedStateRootQuery, ProvableQuery};
pub use program::AleoProgram;
