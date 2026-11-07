//! # Aleo Rust SDK
//!
//! A comprehensive **Rust SDK** for interacting with the [Aleo](https://aleo.org) blockchain.
//! Provides tools for account management, program loading, local zero-knowledge execution,
//! proof generation, network querying, and transaction broadcasting.
//!
//! Built on top of [snarkVM 4.12.0](https://crates.io/crates/snarkvm) for
//! zero-knowledge proving, [reqwest](https://crates.io/crates/reqwest) for async
//! HTTP, and [ureq](https://crates.io/crates/ureq) for the synchronous
//! `ProvableQuery` state-path fetches.
//!
//! ## Architecture
//!
//! The SDK is organized into eleven modules — nine of them functional layers,
//! two of them support:
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`account`] | Key chain, encrypted-key storage, signing, per-record view keys |
//! | [`program`] | Load, parse, and inspect Aleo programs |
//! | [`execution`] | Authorize, execute, prove, and package transactions |
//! | [`delegated`] | Delegated proving: hand the proof to Provable's TEE prover |
//! | [`network`] | HTTP client for Aleo v2 JSON-RPC and REST endpoints |
//! | [`record`] | Record discovery (local or hosted), decryption, coin selection |
//! | [`scanner`] | Record scanning: let Provable's TEE index a view key |
//! | [`sealance`] | Merkle exclusion proofs for compliant-stablecoin freeze lists |
//! | [`client`] | High-level `AleoClient` orchestrating the full lifecycle |
//! | [`hosted`] | Shared plumbing for the TEE services (auth, sealed boxes) |
//! | [`version`] | Crate version constant |
//!
//! ## Proving: locally or delegated
//!
//! [`ExecutionEngine`] proves locally, which is free but costs tens of seconds
//! of CPU per transaction. [`delegated::DelegatedProver`] sends the same
//! authorization to Provable's delegated proving service, which proves it
//! inside a TEE and returns a ready-to-broadcast transaction. The request is
//! encrypted with a libsodium sealed box, so the private inputs are only
//! readable inside the enclave.
//!
//! ## Finding records: locally or delegated
//!
//! The same split applies to record discovery. [`record::RecordScanner`] walks
//! `records/all` and decrypts locally — trustless, but O(chain).
//! [`scanner::RecordScanService`] registers the view key (encrypted the same
//! way) with Provable's record scanning service, which indexes once and then
//! answers queries by `uuid`. Records it returns are still decrypted locally,
//! so a forged response cannot produce a spendable-looking record.
//!
//! [`record::RecordSource`] is the seam between the two: [`record::RecordManager`]
//! takes either, and everything above it — caching, dedupe, coin selection —
//! is unchanged. `RecordManager::new` stays the local-only short form;
//! `RecordManager::with_source` takes a `RecordSource` you built.
//!
//! ## Error handling
//!
//! Every fallible API returns `anyhow::Result`. That is deliberate: the majority
//! of failures originate inside snarkVM (parsing a program, tracing a transition,
//! synthesizing a circuit) and arrive as `anyhow::Error` already, with a context
//! chain that would be destroyed by flattening it into a fixed enum. This crate
//! adds context at each step (`.context("Failed to parse program")`) instead of
//! re-typing the error, so `err.to_string()` stays readable and
//! `err.chain()` still shows the root cause.
//!
//! Match on the *message* only as a last resort; if you need to branch on a
//! failure, check it before the call (e.g. `client.require_account()`), not after.
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
//! ## Cargo features
//!
//! This crate defines **no optional features** — every module is always
//! compiled. The heavy lifting comes from [snarkVM](https://crates.io/crates/snarkvm),
//! which dominates both build time and binary size.
//!
//! ## Related crates
//!
//! - [`aleo-cli`](https://crates.io/crates/aleo-cli) — a companion command-line
//!   tool built on this SDK
//! - [`snarkvm`](https://crates.io/crates/snarkvm) — Zero-knowledge VM for Aleo
//!
//! ## License
//!
//! Licensed under MIT OR Apache-2.0.

pub mod account;
pub mod client;
pub mod delegated;
pub mod execution;
pub mod hosted;
pub mod network;
pub mod program;
pub mod record;
pub mod scanner;
pub mod sealance;
pub mod version;

// Re-export the main types at the crate root for convenience
pub use account::{AleoAccount, RecordPlaintext};
pub use client::AleoClient;
pub use delegated::{ApiAuth, DelegatedProver, ProvingRequest, ProvingResponse};
pub use execution::{ExecutionEngine, consensus_version_to_varuna};
pub use network::{AleoHttpClient, ConfirmationPoll, FixedStateRootQuery, ProvableQuery};
pub use program::AleoProgram;
pub use scanner::{OwnedFilter, OwnedRecord, RecordScanService, Registration};
