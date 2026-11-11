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
//! | [`transaction`] | JS `Transaction` parity: deploy/execute/fee wrapper — string/bytes, type checks, fee folding, record lookup, structured `summary` |
//! | [`view_key`] | JS `ViewKey` parity: native type covers the page; `decrypt`, `toScalar`/`toField` casts, byte (de)serialization wrapped |
//! | [`graph_key`] | JS `GraphKey` parity: native type covers the page; `sk_tag` derivation from a view key, string round-trip wrapped |
//! | [`compute_key`] | JS `ComputeKey` parity: native type covers the page (`fromPrivateKey`, `toAddress`, `skPrf`/`pkSig`/`prSig` components) |
//! | [`private_key_ciphertext`] | JS `PrivateKeyCiphertext` parity: `ciphertext1…` container delegating to the JS-compatible encrypted-key scheme |
//! | [`transition`] | JS `Transition` parity: native `Transition<N>` introspection, records, `tvk`, and `decryptTransition` |
//! | [`program_parity`] | JS `Program` parity: introspection of functions, mappings, records, structs, imports |
//! | [`record_ciphertext`] | JS `RecordCiphertext` parity: view-key and record-view-key decryption, ownership, tag, encodings |
//! | [`record_plaintext`] | JS `RecordPlaintext` parity: members, JSON view, commitments, serial numbers, sender recovery |
//! | [`proving_key`] | JS `ProvingKey` parity: checksum, copy, and string/byte serialization over the native key |
//! | [`verifying_key`] | JS `VerifyingKey` parity: checksum, constraint count, and single/batch proof verification |
//! | [`integer_types`] | JS `Integer Types` parity: the ten native integers, checked-halts semantics, lossy cross-casts |
//! | [`hash_functions`] | JS `Hash Functions` parity: the nine BHP/Pedersen/Poseidon defaults, the `toGroup` naming bridge, input-width traps |
//! | [`encryption`] | JS `EncryptionToolkit` parity: record/sender/transition decryption without the view key, plus the batch owned-record pass |
//! | [`keys`] | Key providers: embedded credits keys, offline store, remote downloads |
//! | [`program`] | Load, parse, and inspect Aleo programs |
//! | [`execution`] | Authorize, execute, prove, and package transactions; plus `Execution` object parity (proof/state-root/transitions, height-aware verification) |
//! | [`execution_response`] | JS `ExecutionResponse` parity: the off-chain result bundle (outputs, program, keys) and its consuming key getters |
//! | [`execution_request`] | JS `ExecutionRequest` parity: signed requests, the missing `is_dynamic` argument, and why `verify` re-derives every input |
//! | [`field`] | JS `Field` parity: negate-vs-inverse trap, strict/lossy casts, integer truncation semantics |
//! | [`group`] | JS `Group` parity: x-coordinate-driven lossy casts, strict `fromField`, the correctly-named `inverse` |
//! | [`keypair`] | JS `KeyPair` parity: the standalone take-once key bag, with the upstream error-message bug fixed |
//! | [`offline_query`] | JS `OfflineQuery` parity: offline inclusion-proof query bundle (`QueryTrait` impl) and its setter/JSON traps |
//! | [`plaintext`] | JS `Plaintext` parity: raw-vs-variant bits, `plaintextType` trap, `toObject` JSON mapping, `toBytesRawBe` reversal |
//! | [`private_key`] | JS `PrivateKey` parity: JS-compatible `ciphertext1…` encrypted keys (Poseidon), seed recovery, RNG injection |
//! | [`scalar`] | JS `Scalar` parity: negation-not-inverse trap, `toField`-bridged lossy casts, strict/lossy semantics |
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
pub mod compute_key;
pub mod credits;
pub mod delegated;
pub mod encryption;
pub mod execution;
pub mod execution_request;
pub mod execution_response;
pub mod field;
pub mod graph_key;
pub mod group;
pub mod hash_functions;
pub mod hosted;
pub mod integer_types;
pub mod keypair;
pub mod keys;
pub mod network;
pub mod offline_query;
pub mod options;
pub mod plaintext;
pub mod private_key;
pub mod private_key_ciphertext;
pub mod program;
pub mod program_parity;
pub mod proving_key;
pub mod record;
pub mod record_ciphertext;
pub mod record_plaintext;
pub mod scalar;
pub mod scanner;
pub mod sealance;
pub mod signature;
pub mod transaction;
pub mod transition;
pub mod verifying_key;
pub mod version;
pub mod view_key;

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
pub use execution_response::{ExecutionKeys, ExecutionResponse};
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
