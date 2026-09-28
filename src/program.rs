/// Aleo Program — load and inspect Aleo programs.
///
/// Wraps snarkVM `Program<TestnetV0>` with ergonomic constructors and queries.

use anyhow::{Context, Result};
use snarkvm::prelude::{Network, Program, ProgramID, TestnetV0};
use std::marker::PhantomData;
use std::str::FromStr;

/// A loaded Aleo program, parameterized over a network.
#[derive(Clone, Debug)]
pub struct AleoProgram<N: Network> {
    pub(crate) program: Program<N>,
    _network: PhantomData<N>,
}

impl AleoProgram<TestnetV0> {
    /// Load a program from a `.aleo` file on disk.
    pub fn from_local_file(path: &str) -> Result<Self> {
        let source =
            std::fs::read_to_string(path).context(format!("Failed to read {path}"))?;
        let program =
            Program::<TestnetV0>::from_str(&source).context("Failed to parse program")?;
        Ok(Self { program, _network: PhantomData })
    }

    /// Parse a program from its source string.
    pub fn from_source(source: &str) -> Result<Self> {
        let program =
            Program::<TestnetV0>::from_str(source).context("Failed to parse program")?;
        Ok(Self { program, _network: PhantomData })
    }

    /// Load the credits program (built-in).
    pub fn credits() -> Result<Self> {
        let program = Program::<TestnetV0>::credits()?;
        Ok(Self { program, _network: PhantomData })
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
