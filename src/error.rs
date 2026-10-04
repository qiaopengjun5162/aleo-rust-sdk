//! # Aleo SDK — custom error types.
//!
//! Consolidates all SDK errors into a single [`AleoError`] enum with
//! [`thiserror`](https://docs.rs/thiserror) for ergonomic `Display` and `Error` derives.
//!
//! ## Usage
//!
//! ```no_run
//! use aleo_rust_sdk::AleoError;
//!
//! fn example() -> Result<(), AleoError> {
//!     Err(AleoError::Custom("something went wrong".into()))
//! }
//! ```

use thiserror::Error;

/// Unified error type for the Aleo Rust SDK.
#[derive(Error, Debug)]
pub enum AleoError {
    /// Account not configured.
    #[error("Account not set. Call set_account_from_private_key_str() first.")]
    AccountNotSet,

    /// Program not loaded.
    #[error("Program not loaded. Call load_program_from_source() first.")]
    ProgramNotSet,

    /// Network/HTTP error.
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    /// serde error.
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// SnarkVM error (anyhow wrapper).
    #[error("SnarkVM error: {0}")]
    SnarkVm(#[from] anyhow::Error),

    /// Custom string error.
    #[error("{0}")]
    Custom(String),
}
