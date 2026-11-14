//! SDK v2 broadcast smoke test for a real credits transfer on testnet.
//!
//! Unlike the other examples this one **broadcasts a real transaction** (a
//! 1-microcredit self-transfer) and polls until it is confirmed. It therefore
//! needs a funded testnet account and spends a small amount of testnet fees.
//!
//! # Usage
//!
//! ```bash
//! export PRIVATE_KEY="APrivateKey1..."
//! cargo run --example sdk_v2_broadcast_test
//! ```

use aleo_rust_sdk::{AleoAccount, AleoClient, AleoProgram};
use anyhow::Context;
use snarkvm::prelude::{PrivateKey, ProgramID, TestnetV0};
use std::str::FromStr;

const V2_API: &str = "https://api.explorer.provable.com/v2/testnet";

/// `credits.aleo/account` values arrive as a quoted `"<n>u64"` string.
///
/// A parse failure is surfaced instead of being reported as a zero balance:
/// silently swallowing it would make a REST format change look like an empty
/// account, which is exactly the kind of drift this example is meant to catch.
fn parse_microcredits(raw: Option<String>) -> anyhow::Result<u64> {
    match raw {
        Some(s) => s
            .trim_matches('"')
            .trim_end_matches("u64")
            .parse()
            .context("unexpected credits.aleo/account value"),
        None => Ok(0),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let pk_str = std::env::var("PRIVATE_KEY")
        .context("PRIVATE_KEY environment variable required (see module docs)")?;

    let account = AleoAccount::from_private_key_str(&pk_str)?;
    let private_key = PrivateKey::<TestnetV0>::from_str(&pk_str)?;
    let self_addr = account.address_str();
    println!("Account: {self_addr}");

    let mut client = AleoClient::new(V2_API)?;
    client.set_account_from_private_key_str(&pk_str)?;
    client.set_program(AleoProgram::credits()?);

    // 1. Check current balance
    let balance_raw = client
        .network
        .fetch_mapping_value("credits.aleo", "account", &self_addr)
        .await?;
    println!(
        "Balance before: {} microcredits",
        parse_microcredits(balance_raw)?
    );

    // 2. Transfer to self
    let amount = 1u64; // 1 microcredit
    println!("Transferring {amount} microcredits to self...");

    let program_id = ProgramID::<TestnetV0>::from_str("credits.aleo")?;
    // Bind the formatted input up front: a temporary `format!` inside `vec!`
    // only works because of deref coercion and is easy to break when editing.
    let amount_arg = format!("{amount}u64");
    let tx_id = client
        .execute_and_broadcast(
            &private_key,
            &program_id,
            "transfer_public",
            vec![self_addr.as_str(), amount_arg.as_str()],
            0,
        )
        .await?;

    println!("Broadcast returned tx: {tx_id}");

    // 3. Wait for confirmation
    match client.network.wait_for_confirmation(&tx_id).await {
        Ok(()) => println!("✅ CONFIRMED on chain!"),
        Err(e) => eprintln!("⚠️  Not confirmed: {e}"),
    }

    // 4. Verify final balance
    let balance_raw2 = client
        .network
        .fetch_mapping_value("credits.aleo", "account", &self_addr)
        .await?;
    println!(
        "Balance after: {} microcredits",
        parse_microcredits(balance_raw2)?
    );

    Ok(())
}
