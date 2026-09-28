/// Simple Aleo Program Execution Demo
///
/// Demonstrates the minimal SDK workflow: load a program, execute it locally (dry-run).
///
/// # Usage
///
/// ```bash
/// cargo run --example simple_execute
/// ```

use aleo_rust_sdk::{AleoAccount, AleoClient};
use snarkvm::prelude::TestRng;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Aleo Simple Execute Demo ===\n");

    // Create a random account for testing
    let mut rng = TestRng::default();
    let account = AleoAccount::new_random(&mut rng)?;
    println!("🔑 Generated address: {}", account.address_str());

    // Create a simple test program
    let program_source = r#"
program hello.aleo;

function main:
    input r0 as u32.public;
    output r0 as u32.public;
"#;

    // Initialize the client
    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;
    client.set_account_from_private_key_str(&account.private_key_str())?;
    client.load_program_from_source(program_source)?;

    // Dry-run execution
    println!("📝 Executing hello.aleo/main with input [\"42u32\"]...");
    let result = client.execute_local("hello.aleo", "main", &["42u32".to_string()])?;
    println!("✅ Execution result:\n   {result}\n");

    println!("=== Done ===");
    Ok(())
}
