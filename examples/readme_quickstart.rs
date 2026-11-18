//! The README Quick Start, kept compilable.
//!
//! Every function body below is the corresponding snippet from `README.md`,
//! copied verbatim apart from the signature: the README shows `main`, and four
//! `main`s cannot share one file, so they are named instead.
//!
//! This exists because the README used to be nobody's job. The private-transfer
//! example imported a path that does not exist (`snarkvm::utilities::Deserialize`),
//! called `Ciphertext::decrypt` with one argument where it takes two, and used
//! `ProgramID` without importing it — three compile errors in the snippet aimed at
//! the reader who needs the most help. Nothing caught it, because README code
//! blocks are not doctests.
//!
//! `cargo build --all-targets` (and therefore `just gate`, and therefore CI)
//! builds this file. A README snippet that stops compiling now fails here first.
//!
//! **Changing `README.md`'s Quick Start means changing this file too.** That
//! duplication is the price of the check; the alternative is the state this file
//! was written to end.
//!
//! `main` deliberately does not call any of them — one of them broadcasts a
//! transfer.

#![allow(dead_code)]

/// README: "Query testnet (no account needed)"
mod query_testnet {
    use aleo_rust_sdk::AleoClient;

    async fn run() -> anyhow::Result<()> {
        let client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;

        let height = client.get_block_height().await?;
        let root = client.get_state_root().await?;
        println!("Block height: {height}");
        println!("State root:   {root}");

        Ok(())
    }
}

/// README: "Generate an account and fetch balance"
mod generate_account {
    use aleo_rust_sdk::{AleoAccount, AleoClient};
    use snarkvm::prelude::TestRng;

    async fn run() -> anyhow::Result<()> {
        let mut rng = TestRng::default();
        let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;

        // Create a random account
        let account = AleoAccount::new_random(&mut rng)?;
        println!("Address: {}", account.address_str());

        // Set the account on the client
        client.set_account_from_private_key_str(&account.private_key_str())?;

        // Query testnet
        let height = client.get_block_height().await?;
        println!("Block height: {height}");

        // Fetch balance (None if account has no credits)
        let balance = client.get_balance().await?;
        match balance {
            Some(b) => println!("Balance: {b} microcredits"),
            None => println!("No credits found (new account)"),
        }

        Ok(())
    }
}

/// README: "Public transfer (simple string inputs)"
mod public_transfer {
    use aleo_rust_sdk::AleoClient;
    use snarkvm::console::program::ProgramID;
    use std::str::FromStr;

    async fn run() -> anyhow::Result<()> {
        let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;
        client.set_account_from_private_key_str("APrivateKey1...")?;

        let tx_id = client
            .execute_and_broadcast(
                &client.require_account()?.private_key,
                &ProgramID::from_str("credits.aleo")?,
                "transfer_public",
                vec!["aleo1recipient...", "1000000u64"],
                0, // priority fee
            )
            .await?;

        println!("Transaction: {tx_id}");
        println!("🔗 https://testnet.aleo.info/tx/{tx_id}");
        Ok(())
    }
}

/// README: "Private transfer (with record decryption)"
mod private_transfer {
    use aleo_rust_sdk::AleoClient;
    use aleo_rust_sdk::record_ciphertext::RecordCiphertext;
    use snarkvm::{
        console::program::{ProgramID, Value},
        prelude::{FromStr, TestnetV0, ViewKey},
    };

    async fn run() -> anyhow::Result<()> {
        let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;
        client.set_account_from_private_key_str("APrivateKey1...")?;

        // Load records (from file, scan, or cached)
        let ciphertext = RecordCiphertext::<TestnetV0>::from_string("record1qyq...")?;
        let view_key = ViewKey::<TestnetV0>::from_str("AViewKey1...")?;

        // Decrypt the record
        let record = ciphertext.decrypt(&view_key)?;

        // Build the input values
        // credits.aleo transfer_private(record, address, u64) -> (record)
        let values = vec![
            Value::Record(record),
            Value::from_str("aleo1recipient...")?,
            Value::from_str("1000000u64")?,
        ];

        let tx_id = client
            .execute_and_broadcast_with_values(
                &client.require_account()?.private_key,
                &ProgramID::from_str("credits.aleo")?,
                "transfer_private",
                values,
                0, // priority fee
            )
            .await?;

        println!("Private transfer: {tx_id}");
        Ok(())
    }
}

fn main() {
    println!("This example is a compile-time check of the README Quick Start.");
    println!("Run one of the snippets by copying it from README.md instead —");
    println!("one of them broadcasts a transfer, so nothing here is executed.");
}
