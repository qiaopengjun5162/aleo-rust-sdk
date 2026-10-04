//! # Aleo Program — load and inspect Aleo programs.
//!
//! Wraps snarkVM [`Program<TestnetV0>`] with ergonomic constructors and queries.
//!
//! ## Usage
//!
//! ```no_run
//! use aleo_rust_sdk::AleoProgram;
//!
//! // Load from source string
//! let program = AleoProgram::from_source("program hello.aleo;\nfunction main:\n    input r0 as u32.public;\n    output r0 as u32.public;\n").unwrap();
//! println!("Program ID: {}", program.id());
//!
//! // Load the built-in credits program
//! let credits = AleoProgram::credits().unwrap();
//! assert!(credits.id().to_string().contains("credits.aleo"));
//! ```

use anyhow::{Context, Result};
use snarkvm::prelude::{Program, ProgramID, TestnetV0};
use std::str::FromStr;

/// A loaded Aleo program for TestnetV0.
#[derive(Clone, Debug)]
pub struct AleoProgram {
    pub(crate) program: Program<TestnetV0>,
}

impl AleoProgram {
    /// Load a program from a `.aleo` file on disk.
    pub fn from_local_file(path: &str) -> Result<Self> {
        let source = std::fs::read_to_string(path).context(format!("Failed to read {path}"))?;
        let program = Program::<TestnetV0>::from_str(&source).context("Failed to parse program")?;
        Ok(Self { program })
    }

    /// Parse a program from its source string.
    pub fn from_source(source: &str) -> Result<Self> {
        let program = Program::<TestnetV0>::from_str(source).context("Failed to parse program")?;
        Ok(Self { program })
    }

    /// Load the credits program (built-in).
    pub fn credits() -> Result<Self> {
        let program = Program::<TestnetV0>::credits()?;
        Ok(Self { program })
    }

    /// Return the program ID.
    pub fn id(&self) -> &ProgramID<TestnetV0> {
        self.program.id()
    }

    /// Return a reference to the inner snarkVM `Program`.
    pub fn inner(&self) -> &Program<TestnetV0> {
        &self.program
    }

    /// Consume self and return the inner `Program`.
    pub fn into_inner(self) -> Program<TestnetV0> {
        self.program
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credits_program() {
        let prog = AleoProgram::credits().unwrap();
        assert!(prog.id().to_string().contains("credits.aleo"));
    }

    #[test]
    fn test_parse_simple_program() {
        let source = r#"
program hello.aleo;

function main:
    input r0 as u32.public;
    output r0 as u32.public;
"#;
        let prog = AleoProgram::from_source(source).unwrap();
        assert_eq!(prog.id().to_string(), "hello.aleo");
    }
}
