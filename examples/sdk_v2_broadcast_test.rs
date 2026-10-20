//! SDK V2 broadcast test — uses the corrected singular path + `?check_transaction=true`
//!
//! Before running: ensure `~/Code/Aleo/hello/.env` has the private key.

use aleo_rust_sdk::{AleoAccount, AleoClient, AleoProgram};
use snarkvm::prelude::{PrivateKey, ProgramID, TestnetV0};
use std::str::FromStr;

const V2_API: &str = "https://api.explorer.provable.com/v2/testnet";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load private key from hello/.env
    let env_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("hello/.env");
    let env_content = std::fs::read_to_string(&env_path)?;
    let pk_line = env_content.lines().find(|l| l.starts_with("PRIVATE_KEY=")).unwrap();
    let pk_str = pk_line.trim_start_matches("PRIVATE_KEY=");

    let account = AleoAccount::from_private_key_str(pk_str).unwrap();
    let private_key = PrivateKey::<TestnetV0>::from_str(pk_str).unwrap();
    let self_addr = account.address_str();
    println!("Account: {self_addr}");

    let mut client = AleoClient::new(V2_API)?;
    client.set_account_from_private_key_str(pk_str)?;
    client.set_program(AleoProgram::credits().unwrap());

    // 1. Check current balance
    let balance_raw = client
        .network
        .fetch_mapping_value("credits.aleo", "account", &self_addr)
        .await?;
    let balance: u64 = match balance_raw {
        Some(s) => s.trim_matches('"').trim_end_matches("u64").parse().unwrap_or(0),
        None => 0,
    };
    println!("Balance before: {balance} microcredits");

    // 2. Transfer to self
    let amount = 1u64; // 1 microcredit
    println!("Transferring {amount} microcredits to self...");

    let program_id = ProgramID::<TestnetV0>::from_str("credits.aleo").unwrap();
    let tx_id = client
        .execute_and_broadcast(
            &private_key,
            &program_id,
            "transfer_public",
            vec![self_addr.as_str(), &format!("{amount}u64")],
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
    let balance_after: u64 = match balance_raw2 {
        Some(s) => s.trim_matches('"').trim_end_matches("u64").parse().unwrap_or(0),
        None => 0,
    };
    println!("Balance after: {balance_after} microcredits");

    Ok(())
}
