/// Aleo Testnet Query Demo
///
/// Queries the testnet for current block height, state root, and program info.
/// No private key required — works on any network endpoint.
///
/// # Usage
///
/// ```bash
/// cargo run --example testnet_query
/// ```

use aleo_rust_sdk::AleoHttpClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Aleo Testnet Query Demo (v2 JSON-RPC) ===\n");

    // Create network client pointing at Provable's testnet explorer API
    let client = AleoHttpClient::new("https://api.explorer.provable.com/v2/testnet")?;

    // Query block height
    let height = client.fetch_block_height().await?;
    println!("📊 Current block height: {height}");

    // Query latest state root
    let state_root = client.fetch_state_root_only().await?;
    println!("🔬 Latest state root: {state_root}");

    // Fetch the credits program
    match client.fetch_program("credits.aleo").await {
        Ok(program) => println!("📜 credits.aleo ID: {}", program.id()),
        Err(e) => println!("⚠️  Failed to fetch credits.aleo: {e}"),
    }

    // Try querying a test address (faucet address from training camp)
    let test_addr = "aleo1dev793afmhq2xwuv9k7uxrxxwljhyf9hysp883hs7p2ryq5z7pqsk2hp35";
    match client.fetch_mapping_value("credits.aleo", "account", test_addr).await {
        Ok(Some(balance)) => println!("💰 Faucet address balance: {balance}"),
        Ok(None) => println!("ℹ️  No public balance entry found (account may be private-only)"),
        Err(e) => println!("⚠️  Balance query error: {e}"),
    }

    println!("\n=== Done ===");
    Ok(())
}
