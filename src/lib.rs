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
//! The SDK is organized into these modules:
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`account`] | Key chain, encrypted-key storage, signing, per-record view keys |
//! | [`address`] | JS `Address` parity: plaintext form, program addresses, arbitrary-address verification |
//! | [`authorization`] | JS `Authorization` parity: root function name, plus the semantics of the native type |
//! | [`boolean`] | JS `Boolean` parity: plaintext form, explicit-RNG sampling, encoding traps |
//! | [`ciphertext`] | JS `Ciphertext` parity: the three decryption keys and the `(program, function, index)` derivation |
//! | [`signature`] | JS `Signature` parity: signing and verifying Aleo *values*, plaintext form |
//! | [`encryption`] | JS `EncryptionToolkit` parity: record/sender/transition decryption without the view key |
//! | [`keys`] | Key providers: embedded credits keys, offline store, remote downloads |
//! | [`program`] | Load, parse, and inspect Aleo programs |
//! | [`execution`] | Authorize, execute, prove, and package transactions; plus `Execution` object parity (proof/state-root/transitions, height-aware verification) |
//! | [`credits`] | credits.aleo value operations: transfers, joins, splits, staking |
//! | [`delegated`] | Delegated proving: hand the proof to Provable's TEE prover |
//! | [`network`] | HTTP client for Aleo v2 JSON-RPC and REST endpoints |
//! | [`record`] | Record discovery (local or hosted), decryption, coin selection |
//! | [`scanner`] | Record scanning: let Provable's TEE index a view key |
//! | [`sealance`] | Merkle exclusion proofs for compliant-stablecoin freeze lists |
//! | [`circle`] | Circle USDCx shielded-mint hook data |
//! | [`client`] | High-level `AleoClient` orchestrating the full lifecycle |
//! | [`options`] | [`AleoNetworkOptions`]: one network name, every service base |
//! | [`hosted`] | Shared plumbing for the TEE services (auth, sealed boxes) |
//! | [`version`] | Crate version constant |
//!
//! ## Endpoints
//!
//! Five services are involved: REST reads, JSON-RPC record queries, delegated
//! proving, record scanning, and the JWT mint. [`AleoNetworkOptions`] states
//! the network once and derives every service base from it, so switching to
//! mainnet is one value rather than four call sites:
//!
//! ```no_run
//! use aleo_rust_sdk::AleoNetworkOptions;
//!
//! # fn run() -> anyhow::Result<()> {
//! let options = AleoNetworkOptions::new("testnet")?;
//! let client = options.client()?;              // REST + JSON-RPC
//! let prover = options.prover()?;              // delegated proving
//! let scanner = options.scanner()?;            // record scanning
//! # let _ = (client, prover, scanner);
//! # Ok(())
//! # }
//! ```
//!
//! The individual constructors ([`AleoClient::new`], [`DelegatedProver::new`],
//! [`RecordScanService::new`]) remain available; the options type is for when
//! more than one of them is in play.
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
pub mod address;
pub mod authorization;
pub mod boolean;
pub mod ciphertext;
pub mod circle;
pub mod client;
pub mod credits;
pub mod delegated;
pub mod encryption;
pub mod execution;
pub mod hosted;
pub mod keys;
pub mod network;
pub mod options;
pub mod program;
pub mod record;
pub mod scanner;
pub mod sealance;
pub mod signature;
pub mod version;

// Re-export the main types at the crate root for convenience
pub use account::{AleoAccount, RecordPlaintext};
pub use circle::{
    HOOK_DATA_COMMITMENT_LEN, HOOK_DATA_COMMITMENT_OFFSET, HOOK_DATA_LEN, HOOK_DATA_RECIPIENT,
    HOOK_DATA_VERSION, SECRET_NONCE, generate_hook_data,
};
pub use client::{AleoClient, PipelineFee};
pub use credits::{CreditsCall, TransferKind};
pub use delegated::{ApiAuth, DelegatedProver, ProvingRequest, ProvingResponse};
pub use execution::{DeploymentKind, ExecutionEngine, consensus_version_to_varuna};
pub use keys::{
    AleoKeyProvider, AleoKeyProviderParams, CreditsFunction, FunctionKeyPair, KeyByteTransport,
    OfflineKeyProvider, ReqwestKeyTransport,
};
pub use network::{AleoHttpClient, ConfirmationPoll, FixedStateRootQuery, ProvableQuery};
pub use options::AleoNetworkOptions;
pub use program::AleoProgram;
pub use scanner::{
    EncryptedRecord, EncryptedRecordsFilter, OwnedFilter, OwnedRecord, OwnedRecordsResponseFilter,
    RecordScanService, RecordsResponseFilter, Registration, compute_uuid,
};
pub use sealance::{DEFAULT_TREE_DEPTH, SealanceMerkleTree, SiblingPath};
