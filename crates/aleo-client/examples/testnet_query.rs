/// Example: Query Aleo testnet for on-chain state.
///
/// This example connects to the public Aleo testnet API and fetches
/// block height, state root, program source, and an account balance.
///
/// Run: `cargo run --example testnet_query`
use aleo_client::AleoClient;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Connect to public testnet explorer API
    let client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;
    println!("=== Aleo Testnet Query Demo (v2 JSON-RPC) ===\n");

    // 1. Block height
    let height = client.get_block_height().await?;
    println!("📊 Current block height: {height}");

    // 2. State root
    let state_root = client.get_state_root().await?;
    println!("🔬 Latest state root: {state_root}");

    // 3. Fetch credits.aleo program (by ID) — uses REST GET
    let credits = client.fetch_program("credits.aleo").await?;
    println!("📜 credits.aleo ID: {}", credits.id());

    // 4. Query a known account's public balance — uses JSON-RPC getMappingValue
    let faucet_addr = "aleo1dev793afmhq2xwuv9k7uxrxxwljhyf9hysp883hs7p2ryq5z7pqsk2hp35";
    println!("\n💳 Querying faucet account: {faucet_addr}");
    let balance = client
        .network
        .fetch_mapping_value("credits.aleo", "account", faucet_addr)
        .await?;
    match balance {
        Some(b) => println!("💰 Faucet public balance: {b} microcredits"),
        None => println!("ℹ️  No public balance entry found (account may be private-only)"),
    }

    // 5. Try a second address
    let test_addr = "aleo1rhgdu77hgyqd3d7w7pw4a0l28wz3y7w3y7w3y7w3y7w3y7w3y7q3q3q3q";
    let balance2 = client
        .network
        .fetch_mapping_value("credits.aleo", "account", test_addr)
        .await?;
    match balance2 {
        Some(b) => println!("💰 Test address balance: {b} microcredits"),
        None => println!("ℹ️  Test address: no public balance"),
    }

    println!("\n=== Done ===");
    Ok(())
}
