/// Aleo Testnet Transfer Demo
///
/// Full pipeline: authorize → execute → prove → broadcast an Aleo credit transfer.
///
/// # Prerequisites
///
/// 1. Export your private key:
///    ```bash
///    export PRIVATE_KEY="APrivateKey1..."
///    ```
///
/// 2. The account must have testnet credits (use the Aleo testnet faucet).
///
/// # Usage
///
/// ```bash
/// cargo run --example testnet_transfer
/// ```

use aleo_rust_sdk::AleoAccount;
use aleo_rust_sdk::AleoClient;
use aleo_rust_sdk::AleoProgram;
use snarkvm::console::program::ProgramID;
use snarkvm::prelude::PrivateKey;
use std::str::FromStr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    println!("=== Aleo Testnet Transfer Demo ===\n");

    // ── 1. Load account from environment ────────────────────────────────
    let pk_str = std::env::var("PRIVATE_KEY")
        .expect("PRIVATE_KEY environment variable required");
    let private_key = PrivateKey::from_str(&pk_str)?;
    let account = AleoAccount::from_private_key_str(&pk_str)?;
    println!("🔑 Account address: {}", account.address_str());

    // Test address (receiver) — use the account's own address for self-transfer
    let self_addr = account.address_str();

    // ── 2. Create AleoClient and set up ─────────────────────────────────
    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;
    client.set_account_from_private_key_str(&pk_str)?;
    client.set_program(AleoProgram::credits()?);

    // ── 3. Dry-run: local execution (no proof, no broadcast) ────────────
    println!("\n📝 Dry-run: executing transfer_public locally...");
    let result = client.execute_local(
        "credits.aleo",
        "transfer_public",
        &[self_addr.clone(), "1000000u64".to_string()],
    )?;
    println!("✅ Dry-run succeeded:\n   {result}\n");

    // ── 4. Full pipeline: prove + broadcast ─────────────────────────────
    println!("📡 Full pipeline: proving and broadcasting...");
    let program_id = ProgramID::<snarkvm::prelude::TestnetV0>::from_str("credits.aleo")?;

    let tx_id = client.execute_and_broadcast(
        &private_key,
        &program_id,
        "transfer_public",
        vec![self_addr.as_str(), "1000000u64"],
        100_000,   // base_fee (0.0001 credits)
        0,         // priority_fee
    ).await?;

    println!("\n🎉 Transaction ID: {tx_id}");
    println!("🔗 Explorer: https://testnet.explorer.provable.com/transaction/{tx_id}");

    // ── 5. Wait for confirmation ────────────────────────────────────────
    println!("\n⏳ Waiting for confirmation...");
    client.network.wait_for_confirmation(&tx_id).await?;

    println!("\n=== Transfer complete ===");
    Ok(())
}
