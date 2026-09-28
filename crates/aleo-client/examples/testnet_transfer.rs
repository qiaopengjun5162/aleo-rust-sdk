/// Example: Transfer credits on Aleo testnet (local dry-run + broadcast).
///
/// This example runs the full SDK pipeline:
///   1. Create client → load account → load credits.aleo
///   2. Authorize + execute locally (dry-run, no proving)
///   3. Prove + package + broadcast to real testnet
///
/// Prerequisites:
/// - `PRIVATE_KEY` env var set to a testnet private key with credits
///
/// Run:
///   export PRIVATE_KEY="APrivateKey1..."
///   cargo run --example testnet_transfer

use aleo_client::AleoClient;
use aleo_program::AleoProgram;
use anyhow::Result;
use snarkvm::prelude::{Address, FromStr, PrivateKey, ProgramID};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Read private key from env
    let pk_str = std::env::var("PRIVATE_KEY")
        .expect("Set PRIVATE_KEY env var to a testnet private key");
    let private_key = PrivateKey::from_str(&pk_str)?;

    // 1. Create client with v2 testnet endpoint
    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;
    client.set_account_from_private_key_str(&pk_str)?;
    let addr = client.require_account()?.address_str();
    println!("Account: {addr}");

    // 2. Load credits.aleo
    println!("Loading credits.aleo...");
    let credits = AleoProgram::credits()?;
    client.set_program(credits);
    println!("Program loaded ✓");

    // 3. Dry-run: authorize + execute locally (no proving, no broadcast)
    let to: Address<snarkvm::prelude::TestnetV0> = Address::from_str(&addr)?;
    println!("\n--- Step 1: Local dry-run ---");
    println!("💸 Self-transfer: {addr} → {addr} (0.001 credits)");
    let result = client.execute_local("credits.aleo", "transfer_public", &[
        to.to_string(),
        "1000000u64".to_string(),
    ])?;
    println!("✅ Dry-run success!");
    println!("   Response: {result}");

    // 4. Full pipeline: prove + broadcast
    let program_id = ProgramID::from_str("credits.aleo")?;
    println!("\n--- Step 2: Prove + Broadcast ---");
    println!("⏳ This may take a while (proving is CPU-intensive)...");

    let tx_id = client.execute_and_broadcast(
        &private_key,
        &program_id,
        "transfer_public",
        vec![addr.as_str(), "1000000u64"],
        100000,  // base_fee (0.0001 credits, minimum non-zero for testnet)
        0,       // priority_fee
    ).await?;

    println!("\n🎉 Transaction broadcast!");
    println!("   TX ID: {tx_id}");
    println!("   Explorer: https://testnet.explorer.provable.com/transaction/{tx_id}");

    Ok(())
}
