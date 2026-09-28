# Aleo Rust SDK

[![Crates.io](https://img.shields.io/badge/crates.io-v0.1.0-orange)](https://crates.io/crates/aleo-rust-sdk)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)]()

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

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
