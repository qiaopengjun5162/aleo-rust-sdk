/// Example: Transfer credits on Aleo testnet.
///
/// This example creates a transfer using the SDK's `AleoClient`.
///
/// Prerequisites:
/// - Set PRIVATE_KEY env var to a testnet private key with credits
/// - The program "credits.aleo" must exist on testnet (it does by default)
///
/// Run: `PRIVATE_KEY=APrivateKey1... cargo run --example testnet_transfer`
///
/// Note: This is a dry-run only (authorize + execute locally, no broadcast).
/// To actually broadcast, call client.execute_and_broadcast() instead.

use aleo_client::AleoClient;
use aleo_program::AleoProgram;
use anyhow::Result;
use snarkvm::prelude::{Address, FromStr};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Read private key from env
    let pk_str = std::env::var("PRIVATE_KEY")
        .expect("Set PRIVATE_KEY env var to a testnet private key");

    // 1. Create client with testnet endpoint
    let mut client = AleoClient::new("https://api.explorer.provable.com/v1")?;
    client.set_account_from_private_key_str(&pk_str)?;
    println!("Account: {}", client.require_account()?.address_str());

    // 2. Load credits.aleo program (built into snarkVM)
    println!("Loading credits.aleo...");
    let credits = AleoProgram::credits()?;
    client.set_program(credits);
    println!("Program loaded ✓");

    // 3. Authorize + execute locally (dry-run)
    let to: Address<snarkvm::prelude::TestnetV0> = Address::from_str("aleo1rhgdu77hgyqd3d7w7pw4a0l28wz3y7w3y7w3y7w3y7w3y7w3y7q3q3q3q")?;
    let result = client.execute_local("credits.aleo", "transfer_public", &[
        to.to_string(),
        "1000000".to_string(), // 0.001 credits in microcredits
    ])?;
    
    println!("✅ Local execution successful!");
    println!("  Function: credits.aleo/transfer_public");
    println!("  To: {to}");
    println!("  Amount: 0.001 credits");
    println!("  Result: {result:?}");

    // 4. To actually broadcast, uncomment:
    // let tx_id = client.execute_and_broadcast("credits.aleo", "transfer_public", &[...]).await?;
    // println!("Broadcast tx: {tx_id}");

    Ok(())
}
