# Aleo Rust SDK

[![Crates.io](https://img.shields.io/crates/v/aleo-rust-sdk?color=orange)](https://crates.io/crates/aleo-rust-sdk)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE)
[![CI](https://github.com/qiaopengjun5162/aleo-rust-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/qiaopengjun5162/aleo-rust-sdk/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs.rs-aleo--rust--sdk-blue)](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/)
[![Rust](https://img.shields.io/badge/rustc-1.85+-orange?logo=rust)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0.html)

[English](README.md) | [中文](README.zh-CN.md)

A **Rust SDK** for interacting with the [Aleo](https://aleo.org) blockchain — account management, program loading, local execution with zero-knowledge proof generation, network querying, transaction broadcasting, and **live Merkle path fetching** for private transfers (via Provable API v2).

> **Why this SDK?** The official [ProvableHQ/aleo-rust](https://github.com/ProvableHQ/aleo-rust) has been **archived** and is no longer maintained. This SDK provides an up-to-date implementation using snarkVM 4.10.0 and the current Aleo testnet endpoints.

---

## Table of Contents

- [Packages](#packages)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Examples](#examples)
- [Roadmap](#roadmap)
- [CLI Tools](#cli-tools)
- [Related Projects](#related-projects)
- [Development](#development)
- [Pre-commit Quality Gates](#pre-commit-quality-gates)
- [Contributing](#contributing)
- [License](#license)

## Packages

| Package | crates.io | docs.rs | Description |
|---------|-----------|---------|-------------|
| aleo-rust-sdk | [crates.io](https://crates.io/crates/aleo-rust-sdk) | [docs.rs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/) | **Meta-package** — all modules below |
| aleo-rust-sdk (account) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/account/index.html) | Key chain: `PrivateKey → ViewKey → ComputeKey → Address` |
| aleo-rust-sdk (program) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/program/index.html) | Program loading, parsing, inspection |
| aleo-rust-sdk (execution) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/execution/index.html) | Authorize, execute, prove, package transactions |
| aleo-rust-sdk (network) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/network/index.html) | v2 JSON-RPC + REST HTTP client + **ProvableQuery** (live state path) |
| aleo-rust-sdk (record) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/record/index.html) | Record discovery, decryption, and coin selection |
| aleo-rust-sdk (client) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/client/index.html) | High-level `AleoClient` orchestrator |

The CLI tool [`aleo-cli`](https://github.com/qiaopengjun5162/aleo-cli) is a separate crate that consumes this SDK.

## Features

| Category | Feature |
|----------|---------|
| **🔑 Account Management** | Generate, import, and derive Aleo accounts (PrivateKey, ViewKey, ComputeKey, Address). Full key derivation chain. |
| **📦 Program Loading** | Fetch programs from the network via REST API, parse `.aleo` source files, inspect function/mapping definitions. |
| **⚡ Local Execution** | Authorize and execute Aleo program transitions locally **without broadcasting** — ideal for dry-runs and testing. |
| **🔐 Proof Generation** | Generate zero-knowledge proofs (Varuna V2) for local execution. Fee proving with V0 fee keys for testnet. |
| **🌐 Network Queries** | Query block height, state root, program source, and mapping values via REST + JSON-RPC. |
| **🔗 Live State Paths** (v0.5.0+) | `ProvableQuery` fetches real Merkle paths from Provable API v2 (`api.provable.com/v2/testnet/statePath/{commitment}`) — no dummy queries, no 502 errors. |
| **📋 Record Management** | Fetch, decrypt, and filter private `credits.aleo` records by owner. Scan record ciphertexts across block ranges. |
| **🚀 Transaction Broadcasting** | Submit serialized transactions to the network and poll for confirmation. |
| **🏗️ High-level Client** | `AleoClient` orchestrates the full lifecycle: account → program → execute → prove → broadcast. |

## Architecture

```text
┌─────────────────────────────────────────────────────┐
│                    AleoClient                        │
│   (high-level orchestrator — account, program,       │
│    execute, prove, broadcast in one place)           │
├──────────┬──────────┬──────────┬──────────────────────┤
│  account │  program │ execution│      network         │
│  │        │         │          │                     │
│  │        │         │          │  AleoHttpClient      │
│ PK → VK  │ parse    │ auth     │  ├─ REST (v2)       │
│ CK → ADDR│ inspect  │ execute  │  ├─ JSON-RPC        │
│  │        │ from_net │ prove    │  ├─ ProvableQuery   │
│  ▼        │  ▼       │  ▼      │       ▼            │
├──────────┴──────────┴──────────┴──────────────────────┤
│  record                                                │
│  AleoRecord · RecordScanner · RecordManager · CoinSel  │
├────────────────────────────────────────────────────────┤
│              snarkVM 4.10.0 (Process<TestnetV0>)       │
│          reqwest (async HTTP) — tokio runtime         │
└──────────────────────────────────────────────────────┘
```

**v0.5.0+ new:** `ProvableQuery` (in the network layer) replaces the dummy `FixedStateRootQuery`. It fetches live Merkle state paths from `api.provable.com/v2/testnet/statePath/{commitment}` using `ureq` (sync HTTP), caches the `global_state_root()` from the response, and returns it in `current_state_root()` — ensuring the state root used for verification matches the root the Merkle path was built against.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
aleo-rust-sdk = "0.5.0"
tokio = { version = "1", features = ["full"] }
```

**Requirements:**
- Rust **1.85+**
- snarkVM **4.10.0** (automatically resolved)
- For proving: ~16 GB RAM recommended

## Quick Start

### Query testnet (no account needed)

```rust
use aleo_rust_sdk::AleoClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = AleoClient::new("https://api.provable.com/v2/testnet")?;

    let height = client.get_block_height().await?;
    let root = client.get_state_root().await?;
    println!("Block height: {height}");
    println!("State root:   {root}");

    Ok(())
}
```

### Generate an account and fetch balance

```rust
use aleo_rust_sdk::{AleoClient, AleoAccount};
use snarkvm::prelude::TestRng;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut rng = TestRng::default();
    let mut client = AleoClient::new("https://api.provable.com/v2/testnet")?;

    // Create a random account
    let account = AleoAccount::new_random(&mut rng)?;
    println!("Address: {}", account.address_str());

    // Set the account on the client
    client.set_account_from_private_key_str(&account.private_key_str())?;

    // Query testnet
    let height = client.get_block_height().await?;
    println!("Block height: {height}");

    // Fetch balance (None if account has no credits)
    let balance = client.get_balance().await?;
    match balance {
        Some(b) => println!("Balance: {b} microcredits"),
        None => println!("No credits found (new account)"),
    }

    Ok(())
}
```

### Public transfer (simple string inputs)

```rust
use aleo_rust_sdk::AleoClient;
use snarkvm::{prelude::TestRng, console::program::ProgramID};
use std::str::FromStr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut client = AleoClient::new("https://api.provable.com/v2/testnet")?;
    client.set_account_from_private_key_str("APrivateKey1...")?;

    let tx_id = client.execute_and_broadcast(
        &client.require_account()?.private_key,
        &ProgramID::from_str("credits.aleo")?,
        "transfer_public",
        vec!["aleo1recipient...", "1000000u64"],
        50000,   // base fee (microcredits)
        0,       // priority fee
    ).await?;

    println!("Transaction: {tx_id}");
    println!("🔗 https://testnet.aleo.info/tx/{tx_id}");
    Ok(())
}
```

### Private transfer (with record decryption)

For private transfers, you must provide **decrypted record values** rather than raw `&str` arguments. Use `execute_and_broadcast_with_values` (v0.5.0+) to pass pre-parsed `Vec<Value>`:

```rust
use aleo_rust_sdk::AleoClient;
use snarkvm::{
    prelude::{TestRng, Network, FromBytes},
    console::{
        program::{Value, Record, Ciphertext, Literal, Plaintext, Identifier},
        account::ViewKey,
        network::TestnetV0,
    },
    utilities::Deserialize,
};
use std::str::FromStr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut client = AleoClient::new("https://api.provable.com/v2/testnet")?;
    client.set_account_from_private_key_str("APrivateKey1...")?;

    // Load records (from file, scan, or cached)
    let ciphertext = Ciphertext::from_str("record1qyq...")?;
    let view_key = ViewKey::from_str("AViewKey1...")?;

    // Decrypt the record
    let record = ciphertext.decrypt(&view_key)?;

    // Build the input values
    // credits.aleo transfer_private(record, address, u64) -> (record)
    let values = vec![
        Value::Record(record),
        Value::from_str("aleo1recipient...")?,
        Value::from_str("1000000u64")?,
    ];

    let tx_id = client.execute_and_broadcast_with_values(
        &client.require_account()?.private_key,
        &ProgramID::from_str("credits.aleo")?,
        "transfer_private",
        values,
        50000,
        0,
    ).await?;

    println!("Private transfer: {tx_id}");
    Ok(())
}
```

The CLI tool handles this automatically — see the `aleo-cli transfer --mode private` command below.

## Examples

| Example | Source | Description |
|---------|--------|-------------|
| `testnet_query` | [examples/testnet_query.rs](examples/testnet_query.rs) | Query testnet: block height, state root, program info (no key needed) |
| `testnet_transfer` | [examples/testnet_transfer.rs](examples/testnet_transfer.rs) | Full pipeline: authorize → execute → prove → broadcast credits transfer |
| `simple_execute` | [examples/simple_execute.rs](examples/simple_execute.rs) | Minimal workflow: load program, execute locally (dry-run) |

Run an example:

```bash
# Query testnet state (no private key required)
cargo run --example testnet_query

# Full transfer (requires PRIVATE_KEY env var)
export PRIVATE_KEY="APrivateKey1..."
cargo run --example testnet_transfer

# Local dry-run execution
cargo run --example simple_execute
```

## Roadmap

Planned features (in order of priority):

- [ ] **WASM support** — compile SDK for browser/Node.js via `wasm-pack`
- [ ] **Transaction history** — fetch and decode historical transactions
- [ ] **Program deployment helper** — streamline program ID and edition handling
- [ ] **Mainnet support** — add mainnet configuration alongside testnet
- [ ] **Record merging** — join multiple small records into a single larger record
- [ ] **Batch transfers** — send multiple transfers in one transaction
- [ ] **Type-safe program bindings** — generate Rust structs from Aleo program mappings

## CLI Tools

The [`aleo-cli`](https://github.com/qiaopengjun5162/aleo-cli) command-line tool is built on top of this SDK:

```bash
# Install
cargo install aleo-cli

# Query testnet status
aleo-cli query

# Check account balance
aleo-cli balance aleo1cu0xk4tt99pgxglpqltzk3tmpgh7qftjwukxcmewzpy0fkqghvgsxu0g03

# Generate a new Aleo account
aleo-cli generate

# Send a public transfer
aleo-cli transfer aleo1ss6e8... 1000000 --mode public

# Send a private transfer (v0.4.0+)
aleo-cli transfer aleo1ss6e8... 30000 --mode private

# Deploy a program
aleo-cli deploy /path/to/program.aleo program_name

# Execute and broadcast
aleo-cli exec credits.aleo transfer_public aleo1ss6e8... 1000u64 --base-fee 50000

# Verify a transaction on-chain
aleo-cli verify at136grnr...

# Deep ZK proof verification
aleo-cli verify at136grnr... --deep
```

## Related Projects

| Project | Description |
|---------|-------------|
| [ProvableHQ/snarkVM](https://github.com/ProvableHQ/snarkVM) | Zero-knowledge VM for the Aleo blockchain (this SDK's core dependency) |
| [ProvableHQ/snarkOS](https://github.com/ProvableHQ/snarkOS) | Decentralized OS for ZK applications — Aleo node software |
| [ProvableHQ/sdk](https://github.com/ProvableHQ/sdk) | Official JavaScript/TypeScript SDK for Aleo (NPM: `@provablehq/sdk`) |
| [Provable API v2 docs](https://docs.explorer.provable.com/docs/api/v2/intro) | REST API reference — block queries, state paths, transaction data |
| [qiaopengjun5162/aleo-cli](https://github.com/qiaopengjun5162/aleo-cli) | Aleo CLI tool built on this SDK |
| [AleoNet/workshop](https://github.com/AleoNet/workshop) | Starter guide to building ZK applications on Aleo |
| [Aleo developer docs](https://developer.aleo.org/) | Official Aleo developer documentation |

## Development

```bash
git clone https://github.com/qiaopengjun5162/aleo-rust-sdk.git
cd aleo-rust-sdk

# Build
just build            # cargo build --all-features
just build-release    # release build

# Test
just test             # cargo nextest run --all-features

# Lint
just check            # cargo check --all-features
just clippy           # cargo clippy -- -D warnings
just format           # cargo fmt --all -- --check

# Generate docs
just docs             # cargo doc --no-deps --open

# Full check suite
just all              # format + check + clippy + test
```

## Pre-commit Quality Gates

This project uses [pre-commit](https://pre-commit.com) to enforce code quality on every commit:

```bash
# Install hooks (one-time after clone)
pre-commit install --hook-type pre-commit --hook-type commit-msg

# Or run all checks manually
pre-commit run --all-files
```

The following 12 checks run automatically before each commit:

| # | Hook | What it checks |
|---|------|---------------|
| 1 | fix-byte-order-marker | BOM encoding |
| 2 | check-case-conflict | Case-sensitive filename conflicts |
| 3 | check-merge-conflict | Unresolved merge markers |
| 4 | check-symlinks | Broken symlinks |
| 5 | check-yaml | YAML syntax validity |
| 6 | end-of-file-fixer | Files end with newline |
| 7 | mixed-line-ending | Consistent line endings |
| 8 | trailing-whitespace | No trailing whitespace |
| 9 | cargo fmt | Rust formatting (`cargo fmt --check`) |
| 10 | cargo check | Compilation (`cargo check`) |
| 11 | cargo clippy | Lint (`cargo clippy -- -D warnings`) |
| 12 | typos | Spelling errors |

**`language: system`** note: All local hooks use `language: system` (not `language: rust`), which means they run tools from your system PATH. This ensures the hooks actually execute instead of silently skipping.

> **History:** v0.4.1 and earlier had `language: rust` in `.pre-commit-config.yaml`, which caused all hooks to silently skip (pre-commit tried to install them as crates.io packages). This was fixed in v0.5.0 by switching to `language: system` and running `pre-commit install`.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on reporting bugs, suggesting features, and submitting code changes.

**Before submitting a PR:**
1. Ensure pre-commit hooks pass (`pre-commit run --all-files`)
2. Check CI passes (GitHub Actions)
3. Update CHANGELOG.md following [conventional commits](https://www.conventionalcommits.org/)

## License

Licensed under either [MIT License](LICENSE) or [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) at your option.

---

<p align="center">
  <b>Aleo Rust SDK</b> — Built for the Aleo ecosystem. 🚀
</p>
