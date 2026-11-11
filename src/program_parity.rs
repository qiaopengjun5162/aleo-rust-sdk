//! # Program — parity with the JS SDK's wasm `Program`.
//!
//! Inspect an Aleo program's functions, records, structs, mappings and imports
//! without executing anything. The JS class is a wasm newtype over snarkVM's
//! [`ProgramNative`]; this module keeps that shape and reproduces the JS
//! **object shapes** with `serde_json::Value`.
//!
//! ## JS `Program` → Rust mapping
//!
//! | # | JS | Rust equivalent | Where |
//! |---|---|---|---|
//! | 1 | `fromString(program)` | [`Program::from_string`] | native `FromStr` |
//! | 2 | `toString()` | [`Program::to_string`] | native `Display` |
//! | 3 | `hasFunction(name)` | [`Program::has_function`] | native `contains_function` |
//! | 4 | `getFunctions()` | [`Program::get_functions`] | native `functions()` |
//! | 5 | `getFunctionInputs(name)` | [`Program::get_function_inputs`] | **this module** (JSON shape) |
//! | 6 | `getMappings()` | [`Program::get_mappings`] | **this module** (JSON shape) |
//! | 7 | `getRecordMembers(name)` | [`Program::get_record_members`] | **this module** (JSON shape) |
//! | 8 | `getStructMembers(name)` | [`Program::get_struct_members`] | **this module** (JSON shape) |
//! | 9 | `getCreditsProgram()` | [`Program::get_credits_program`] | native `Program::credits()` |
//! | 10 | `id()` | [`Program::id`] | native getter |
//! | 11 | `address()` | [`Program::address`] | native `ProgramID::to_address()` |
//! | 12 | `isEqual(other)` | [`Program::is_equal`] | derived `PartialEq` |
//! | 13 | `getImports()` | [`Program::get_imports`] | native `imports()` |
//!
//! ## Object shapes (pinned to upstream, not to the JS docs)
//!
//! 🔴 The JS docs' `getMappings` example shows `key_name` / `value_name`, but
//! the upstream implementation only sets `name` / `key_type` / `value_type`.
//! This module follows **the implementation**. Likewise `getRecordMembers`
//! appends a synthetic `_nonce` member (`group`, `public`) that the docs omit.
//!
//! 🔴 The JS docs' examples predate snarkVM 4.12: `credits.aleo` no longer has
//! `mint`/`fee` (they are `fee_private`/`fee_public` now), the record is named
//! **`credits`** (lowercase) and declares only `microcredits` — no `owner`
//! member. Function inputs/outputs must also carry an explicit visibility
//! (`u64.private`), otherwise `Program::from_str` rejects the source. Tests
//! here pin the *observed* 4.12 shapes rather than the stale doc examples.
//!
//! `getFunctionInputs` maps each `ValueType`:
//! `Constant|Public|Private(plaintext)` → the plaintext object with a
//! `visibility` and `register`; `Record(identifier)` → the record object plus
//! `register`; `ExternalRecord|Future(locator)` → `{type, locator, register}`;
//! `DynamicRecord|DynamicFuture` → `{type: "dynamic.record"|"dynamic.future",
//! register}`. Nested `PlaintextType::Struct` recursively expands `members`.
//!
//! ## Not on this page
//!
//! Upstream `program.rs` also exposes `getCallGraph`, `isArc20`, `isArc22`,
//! `nameToField` and `toChecksum`, but the JS API reference page for `Program`
//! does not list them, so they are out of scope here.
//!
//! ## Example
//!
//! ```
//! use aleo_rust_sdk::program_parity::Program;
//! use snarkvm::prelude::TestnetV0;
//!
//! let p = Program::<TestnetV0>::get_credits_program().unwrap();
//! assert_eq!(p.id(), "credits.aleo");
//! assert!(p.has_function("transfer_private"));
//! let mappings = p.get_mappings();
//! assert!(mappings.iter().any(|m| m["name"] == "account"));
//! ```

use anyhow::Result;
use serde_json::{Value as JsonValue, json};
use snarkvm::prelude::{
    Address, EntryType, Identifier, Network, PlaintextType, Program as ProgramNative, ValueType,
};
use std::{fmt, ops::Deref, str::FromStr};

/// An Aleo program, wrapping snarkVM's native [`ProgramNative`].
///
/// Distinct from [`crate::program::AleoProgram`], which is this crate's
/// higher-level "load a program and run it" abstraction. This type is a pure
/// introspection wrapper matching the JS wasm class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program<N: Network>(ProgramNative<N>);

impl<N: Network> Deref for Program<N> {
    type Target = ProgramNative<N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<N: Network> From<ProgramNative<N>> for Program<N> {
    fn from(program: ProgramNative<N>) -> Self {
        Self(program)
    }
}

impl<N: Network> From<Program<N>> for ProgramNative<N> {
    fn from(program: Program<N>) -> Self {
        program.0
    }
}

impl<N: Network> FromStr for Program<N> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(Self(ProgramNative::<N>::from_str(s)?))
    }
}

impl<N: Network> fmt::Display for Program<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<N: Network> Program<N> {
    /// Parses Aleo program source — JS `Program.fromString`.
    pub fn from_string(source: &str) -> Result<Self> {
        Self::from_str(source)
    }

    /// Renders the canonical program source — JS `toString`.
    #[allow(clippy::inherent_to_string, clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }

    /// Whether the program defines `function_name` — JS `hasFunction`.
    ///
    /// An invalid identifier is simply "not present", matching upstream (which
    /// uses `Identifier::from_str(...).is_ok_and(...)`).
    pub fn has_function(&self, function_name: &str) -> bool {
        Identifier::<N>::from_str(function_name)
            .is_ok_and(|identifier| self.0.contains_function(&identifier))
    }

    /// All function names, in declaration order — JS `getFunctions`.
    pub fn get_functions(&self) -> Vec<String> {
        self.0
            .functions()
            .values()
            .map(|function| function.name().to_string())
            .collect()
    }

    /// Structured inputs of a function — JS `getFunctionInputs`.
    ///
    /// Each element carries a `register` (`r0`, `r1`, …) plus the type
    /// description produced by the crate-internal `plaintext_input` helper.
    pub fn get_function_inputs(&self, function_name: &str) -> Result<Vec<JsonValue>> {
        let function_id = Identifier::<N>::from_str(function_name)?;
        let function = self.0.functions().get(&function_id).ok_or_else(|| {
            anyhow::anyhow!("function {function_name} not found in {}", self.0.id())
        })?;

        function
            .inputs()
            .iter()
            .map(|input| {
                let register = input.register().to_string();
                let mut value = match input.value_type() {
                    ValueType::Constant(plaintext) => {
                        self.plaintext_input(plaintext, Some("constant"), None)?
                    }
                    ValueType::Public(plaintext) => {
                        self.plaintext_input(plaintext, Some("public"), None)?
                    }
                    ValueType::Private(plaintext) => {
                        self.plaintext_input(plaintext, Some("private"), None)?
                    }
                    ValueType::Record(identifier) => {
                        self.get_record_members(&identifier.to_string())?
                    }
                    ValueType::ExternalRecord(locator) => {
                        json!({"type": "external_record", "locator": locator.to_string()})
                    }
                    ValueType::Future(locator) => {
                        json!({"type": "future", "locator": locator.to_string()})
                    }
                    ValueType::DynamicRecord => json!({"type": "dynamic.record"}),
                    ValueType::DynamicFuture => json!({"type": "dynamic.future"}),
                };
                value["register"] = json!(register);
                Ok(value)
            })
            .collect()
    }

    /// Mappings with their key/value types — JS `getMappings`.
    ///
    /// 🔴 Only `name`, `key_type`, `value_type` are emitted. The JS docs'
    /// `key_name` / `value_name` fields are **not** produced upstream.
    pub fn get_mappings(&self) -> Vec<JsonValue> {
        self.0
            .mappings()
            .iter()
            .map(|(name, mapping)| {
                json!({
                    "name": name.to_string(),
                    "key_type": mapping.key().plaintext_type().to_string(),
                    "value_type": mapping.value().plaintext_type().to_string(),
                })
            })
            .collect()
    }

    /// A record's members plus the synthetic `_nonce` — JS `getRecordMembers`.
    pub fn get_record_members(&self, record_name: &str) -> Result<JsonValue> {
        let record_id = Identifier::<N>::from_str(record_name)?;
        let record = self
            .0
            .get_record(&record_id)
            .map_err(|_| anyhow::anyhow!("record {record_name} not found in {}", self.0.id()))?;

        let mut members = record
            .entries()
            .iter()
            .map(|(name, entry_type)| {
                let (plaintext, visibility) = match entry_type {
                    EntryType::Constant(plaintext) => (plaintext, "constant"),
                    EntryType::Public(plaintext) => (plaintext, "public"),
                    EntryType::Private(plaintext) => (plaintext, "private"),
                };
                self.plaintext_input(plaintext, Some(visibility), Some(name))
            })
            .collect::<Result<Vec<_>>>()?;

        // Every record has an implicit public `_nonce` group element; upstream
        // pushes it after setting `members` on the (shared) JS array.
        members.push(json!({"name": "_nonce", "type": "group", "visibility": "public"}));

        Ok(json!({"type": "record", "record": record_name, "members": members}))
    }

    /// A struct's members — JS `getStructMembers`.
    pub fn get_struct_members(&self, struct_name: &str) -> Result<Vec<JsonValue>> {
        let struct_id = Identifier::<N>::from_str(struct_name)?;
        let program_struct = self
            .0
            .get_struct(&struct_id)
            .map_err(|_| anyhow::anyhow!("struct {struct_name} not found in {}", self.0.id()))?;

        program_struct
            .members()
            .iter()
            .map(|(name, member_type)| self.plaintext_input(member_type, None, Some(name)))
            .collect()
    }

    /// The built-in `credits.aleo` program — JS `getCreditsProgram`.
    pub fn get_credits_program() -> Result<Self> {
        Ok(Self(ProgramNative::<N>::credits()?))
    }

    /// The program ID (`name.aleo`) — JS `id()`.
    pub fn id(&self) -> String {
        self.0.id().to_string()
    }

    /// The program's unique address — JS `address()`.
    pub fn address(&self) -> Result<Address<N>> {
        self.0.id().to_address()
    }

    /// Equality with another program — JS `isEqual`.
    pub fn is_equal(&self, other: &Self) -> bool {
        self == other
    }

    /// Imported program IDs — JS `getImports`.
    pub fn get_imports(&self) -> Vec<String> {
        self.0.imports().keys().map(|program_id| program_id.to_string()).collect()
    }

    /// The JSON description of a `PlaintextType` (upstream's private
    /// `get_plaintext_input` helper).
    ///
    /// `name` is set for struct members / record entries; `visibility` is set
    /// for value types and record entries. Structs recurse into their members.
    fn plaintext_input(
        &self,
        plaintext: &PlaintextType<N>,
        visibility: Option<&str>,
        name: Option<&Identifier<N>>,
    ) -> Result<JsonValue> {
        let mut value = match plaintext {
            PlaintextType::Array(array_type) => json!({
                "type": "array",
                "element_type": self.plaintext_input(array_type.base_element_type(), None, None)?,
                "length": **array_type.length(),
            }),
            PlaintextType::Literal(literal_type) => json!({"type": literal_type.to_string()}),
            PlaintextType::Struct(struct_id) => {
                let struct_name = struct_id.to_string();
                json!({
                    "type": "struct",
                    "struct_id": struct_name,
                    "members": self.get_struct_members(&struct_name)?,
                })
            }
            PlaintextType::ExternalStruct(locator) => {
                let struct_name = locator.name().to_string();
                json!({
                    "type": "struct",
                    "struct_id": struct_name,
                    "members": self.get_struct_members(&struct_name)?,
                })
            }
        };
        if let Some(name) = name {
            value["name"] = json!(name.to_string());
        }
        if let Some(visibility) = visibility {
            value["visibility"] = json!(visibility);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::TestnetV0;

    type N = TestnetV0;

    /// Upstream wasm doc example: nested structs.
    const STRUCT_PROGRAM: &str = r#"program token_issue.aleo;

struct token_metadata:
    network as u32;
    version as u32;

struct token:
    token_id as u32;
    metadata as token_metadata;

function no_op:
    input r0 as u64.private;
    output r0 as u64.private;"#;

    /// Upstream wasm doc example: an import (must precede the program decl).
    const DOUBLE_TEST: &str = r#"import multiply_test.aleo;

program double_test.aleo;

function double_it:
    input r0 as u32.private;
    call multiply_test.aleo/multiply 2u32 r0 into r1;
    output r1 as u32.private;"#;

    fn credits() -> Program<N> {
        Program::<N>::get_credits_program().unwrap()
    }

    #[test]
    fn credits_program_functions_and_identity() {
        let p = credits();
        assert_eq!(p.id(), "credits.aleo");
        let functions = p.get_functions();
        for expected in [
            "transfer_private",
            "transfer_public",
            "join",
            "split",
            "fee_private",
            "fee_public",
        ] {
            assert!(
                functions.contains(&expected.to_string()),
                "missing {expected}"
            );
        }
        assert!(!functions.contains(&"mint".to_string()));
        assert!(p.has_function("transfer_private"));
        assert!(!p.has_function("no_such_function"));
        assert!(!p.has_function("1invalid"));
        assert!(p.address().is_ok());
    }

    #[test]
    fn string_round_trip_and_equality() {
        let p = Program::<N>::from_string(STRUCT_PROGRAM).unwrap();
        assert!(p.to_string().contains("struct token_metadata"));
        assert_eq!(Program::<N>::from_string(&p.to_string()).unwrap(), p);
        assert!(p.is_equal(&p));
        assert!(!p.is_equal(&credits()));
        assert!(Program::<N>::from_string("not a program").is_err());
    }

    #[test]
    fn credits_function_inputs_match_upstream_shape() {
        let inputs = credits().get_function_inputs("transfer_private").unwrap();
        assert_eq!(inputs.len(), 3);
        assert_eq!(inputs[0]["type"], "record");
        assert_eq!(inputs[0]["record"], "credits");
        assert_eq!(inputs[0]["register"], "r0");
        // In 4.12 the credits record declares only `microcredits`; the
        // synthetic `_nonce` is appended by getRecordMembers.
        assert_eq!(inputs[0]["members"].as_array().unwrap().len(), 2);
        assert_eq!(inputs[1]["type"], "address");
        assert_eq!(inputs[1]["visibility"], "private");
        assert_eq!(inputs[1]["register"], "r1");
        assert_eq!(inputs[2]["type"], "u64");
        assert_eq!(inputs[2]["register"], "r2");
        assert!(credits().get_function_inputs("missing").is_err());
    }

    #[test]
    fn credits_mappings_and_record_members() {
        let p = credits();
        let mappings = p.get_mappings();
        assert!(mappings.iter().any(|m| m["name"] == "account"));
        let account = mappings.iter().find(|m| m["name"] == "account").unwrap();
        assert_eq!(account["key_type"], "address");
        assert_eq!(account["value_type"], "u64");
        // The docs' key_name/value_name are NOT emitted upstream.
        assert!(account.get("key_name").is_none());

        let record = p.get_record_members("credits").unwrap();
        assert_eq!(record["type"], "record");
        assert_eq!(record["record"], "credits");
        let members = record["members"].as_array().unwrap();
        assert_eq!(members[0]["name"], "microcredits");
        assert_eq!(members[0]["type"], "u64");
        assert_eq!(members[0]["visibility"], "private");
        assert_eq!(members.last().unwrap()["name"], "_nonce");
        assert!(p.get_record_members("Missing").is_err());
    }

    #[test]
    fn struct_members_recurse_into_nested_struct() {
        let p = Program::<N>::from_string(STRUCT_PROGRAM).unwrap();
        let members = p.get_struct_members("token").unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0], json!({"name": "token_id", "type": "u32"}));
        assert_eq!(members[1]["name"], "metadata");
        assert_eq!(members[1]["type"], "struct");
        assert_eq!(members[1]["struct_id"], "token_metadata");
        let nested = members[1]["members"].as_array().unwrap();
        assert_eq!(nested[0], json!({"name": "network", "type": "u32"}));
        assert_eq!(nested[1], json!({"name": "version", "type": "u32"}));
        assert!(p.get_struct_members("missing").is_err());
    }

    #[test]
    fn imports_are_program_ids() {
        let p = Program::<N>::from_string(DOUBLE_TEST).unwrap();
        assert_eq!(p.get_imports(), vec!["multiply_test.aleo"]);
        assert_eq!(credits().get_imports().len(), 0);
    }
}
