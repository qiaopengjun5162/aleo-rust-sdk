# Aleo Rust SDK

[![Crates.io](https://img.shields.io/crates/v/aleo-rust-sdk?color=orange)](https://crates.io/crates/aleo-rust-sdk)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![CI](https://github.com/qiaopengjun5162/aleo-rust-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/qiaopengjun5162/aleo-rust-sdk/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs.rs-aleo--rust--sdk-blue)](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/)
[![Rust](https://img.shields.io/badge/rustc-1.85+-orange?logo=rust)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0.html)

[English](README.md) | [中文](README.zh-CN.md)

A comprehensive **Rust SDK** for interacting with the [Aleo](https://aleo.org) blockchain.
Provides tools for account management, program loading, local execution, proof generation,
network querying, and transaction broadcasting.

> **Note:** The official [ProvableHQ/aleo-rust](https://github.com/ProvableHQ/aleo-rust) has been
> **deprecated** (archived). This SDK fills the gap with an up-to-date implementation using
> snarkVM's latest APIs and the current v2/testnet JSON-RPC endpoints.

## Architecture

| Module | Purpose |
|--------|---------|
| `account` | Key chain: `PrivateKey → ViewKey → ComputeKey → Address` |
| `program` | Load, parse, and inspect Aleo programs |
| `execution` | Authorize, execute, prove, and package transactions |
| `network` | HTTP client for Aleo v2 JSON-RPC and REST endpoints |
| `client` | High-level `AleoClient` orchestrating the full lifecycle |

## Features

- **Account Management** — Generate keys, derive addresses, handle view keys
- **Program Loading** — Fetch, parse, and inspect Aleo programs from the network
- **Local Execution** — Authorize and execute transitions without broadcasting
- **Proof Generation** — Generate zero-knowledge proofs for local execution
- **Network Queries** — Block height, state root, program info, record scanning
- **Record Management** — Fetch, decrypt, and filter private records by owner
- **Transaction Broadcasting** — Submit and confirm transactions on Aleo testnet
- **High-level Client** — `AleoClient` orchestrates the full lifecycle end-to-end

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
aleo-rust-sdk = "0.2.0"
```

This SDK requires **Rust 1.85+** and supports **snarkVM 4.10.0**.

## Quick Start

```rust
use aleo_rust_sdk::{AleoClient, AleoAccount};
use snarkvm::prelude::TestRng;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut rng = TestRng::default();
    let client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;

    // Create a random account
    let account = AleoAccount::new_random(&mut rng)?;
    println!("Address: {}", account.address_str());

    // Query the network
    let height = client.get_block_height().await?;
    println!("Block height: {height}");

    Ok(())
}
```

## Examples

| Example | Description |
|---------|-------------|
| `testnet_query` | Query testnet: block height, state root, program info (no key needed) |
| `testnet_transfer` | Full pipeline: authorize → execute → prove → broadcast credits transfer |
| `simple_execute` | Minimal workflow: load program, execute locally (dry-run) |

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

## CLI Tools

The [`aleo-cli`](https://github.com/qiaopengjun5162/aleo-cli) command-line tool is built on top of this SDK:

```bash
# Install
cargo install aleo-cli

# Query testnet status
aleo-cli query

# Check account balance
aleo-cli balance <ADDRESS>

# Generate a new Aleo account
aleo-cli generate

# Send a private transfer
aleo-cli transfer --amount 1.5 --to <RECIPIENT_ADDRESS>
```

## API Reference

| Module | Key Types | Key Methods |
|--------|-----------|-------------|
| `AleoAccount` | `PrivateKey`, `ViewKey`, `ComputeKey`, `Address` | `new_random()`, `from_private_key()`, `address_str()` |
| `AleoProgram` | `Program`, `ProgramManager` | `from_str()`, `get_function()`, `get_mappings()` |
| `AleoExecutor` | `Execution`, `ProvingKey`, `VerifyingKey` | `authorize()`, `execute()`, `prove()`, `package_transaction()` |
| `AleoHttpClient` | `reqwest::Client` | `get_block_height()`, `get_state_root()`, `fetch_program()`, `fetch_all_records()`, `broadcast_transaction()` |
| `AleoClient` | high-level orchestrator | `find_private_credits_records()`, `get_balance()`, `transfer_private()` |

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

# Coverage
just coverage         # cargo llvm-cov --all-features --lcov

# Full check suite
just all              # format + check + clippy + test
```

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on reporting bugs, suggesting features, and submitting code changes.

## License

Licensed under [MIT License](LICENSE).

---

<p align="center">
  <b>Aleo Rust SDK</b> — Built for the Aleo ecosystem. 🚀
</p>
