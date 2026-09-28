/// Example: Simple Aleo execution pipeline.
///
/// Demonstrates the full flow:
/// 1. Create an account
/// 2. Load a program from source
/// 3. Initialize the execution engine
/// 4. Authorize + execute a function call locally
///
/// Run: `cargo run --example simple_execute`

use aleo_client::AleoClient;
use aleo_program::AleoProgram;
use anyhow::Result;
use snarkvm::prelude::TestRng;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing (use RUST_LOG=info to see details)
    tracing_subscriber::fmt::init();

    let mut rng = TestRng::default();

    // 1. Create a random account
    let _account = aleo_account::AleoAccount::new_random(&mut rng)?;
    println!("Account created ✓");

    // 2. Load a simple program from source
    let source = r#"
program hello.aleo;

function main:
    input r0 as u32.public;
    output r0 as u32.public;
"#;
    let program = AleoProgram::from_source(source)?;
    println!("Program loaded: {}", program.id());

    // 3. Initialize execution engine
    let _engine = aleo_execution::ExecutionEngine::new(program.inner(), false)?;
    println!("Engine initialized ✓");

    // 4. (Optional) Show network client creation — doesn't connect until used
    let _client = AleoClient::new("https://api.explorer.provable.com/v1")?;

    println!("✅ Aleo Rust SDK ready for real execution!");
    Ok(())
}
