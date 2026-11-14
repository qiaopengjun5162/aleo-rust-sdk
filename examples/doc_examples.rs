//! Compile-guard for the runnable snippets in `docs/js-rust-guide.md`.
//!
//! These mirror the examples a `@provablehq/sdk` user would copy when porting
//! to Rust. If a public API used here changes, `cargo clippy --all-targets`
//! (CI) fails, so doc drift cannot ship silently. This file is never executed
//! in CI — it only needs to compile.
//!
//! # Usage
//!
//! ```bash
//! cargo check --example doc_examples
//! ```

use aleo_rust_sdk::{AleoAccount, AleoClient};
use snarkvm::console::program::ProgramID;
use snarkvm::prelude::TestRng;
use std::str::FromStr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // --- Read chain state (no private key) ---
    let client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;
    println!("height: {}", client.get_block_height().await?);
    println!("state root: {}", client.get_state_root().await?);

    // --- Create an account and read its balance ---
    let mut rng = TestRng::default();
    let account = AleoAccount::new_random(&mut rng)?;
    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;
    client.set_account_from_private_key_str(&account.private_key_str())?;
    println!("address: {}", account.address_str());
    println!("balance: {:?}", client.get_balance().await?);

    // --- Public transfer ---
    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;
    client.set_account_from_private_key_str("APrivateKey1...")?;
    let tx_id = client
        .execute_and_broadcast(
            &client.require_account()?.private_key,
            &ProgramID::from_str("credits.aleo")?,
            "transfer_public",
            vec!["aleo1recipient...", "1000000u64"],
            0,
        )
        .await?;
    println!("{tx_id}");

    // --- Waiting for confirmation lives on the network client ---
    client.network.wait_for_confirmation(&tx_id).await?;

    Ok(())
}
