//! Guards the import rule the README states: snarkVM types enter through
//! `aleo_rust_sdk::snarkvm`, never through a second `snarkvm` dependency.
//!
//! This has to be a file scan rather than a compile test. An example that says
//! `use snarkvm::…` compiles *in this repository* — snarkvm is a direct
//! dependency here — so `cargo clippy --all-targets` is perfectly happy while
//! the example teaches the wrong thing. A user who copies it gets
//! "unresolved import `snarkvm`", adds the dependency, and ends up with two
//! copies of snarkVM in one build whose types do not unify. Four examples had
//! drifted this way before this test existed.
//!
//! Only `examples/` is scanned. The crate's own `tests/` are not user-facing
//! and reach for snarkvm directly on purpose.

use std::fs;
use std::path::Path;

/// Lines in an example that pull snarkVM in without the re-export.
fn bare_snarkvm_imports(text: &str) -> Vec<String> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            let trimmed = line.trim_start();
            trimmed.starts_with("use snarkvm::") || trimmed.starts_with("extern crate snarkvm")
        })
        .map(|(index, line)| format!("line {}: {}", index + 1, line.trim()))
        .collect()
}

#[test]
fn examples_import_snarkvm_through_the_reexport() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let mut offenders = Vec::new();

    for entry in fs::read_dir(&dir).expect("examples/ should exist") {
        let path = entry.expect("examples/ should be readable").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("an example should be readable UTF-8");
        let hits = bare_snarkvm_imports(&text);
        if !hits.is_empty() {
            offenders.push(format!("{path:?}:\n  {}", hits.join("\n  ")));
        }
    }

    assert!(
        offenders.is_empty(),
        "examples must import snarkVM through `aleo_rust_sdk::snarkvm`, \
         because a reader cannot add a second `snarkvm` dependency without \
         getting two incompatible copies:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_scan_actually_recognises_the_bad_form() {
    // Without this, a typo in the pattern above would make the first test pass
    // for the wrong reason — it would find nothing because it looks for nothing.
    let bad = "use aleo_rust_sdk::AleoAccount;\nuse snarkvm::prelude::TestRng;\n";
    assert_eq!(bare_snarkvm_imports(bad).len(), 1);
    let good = "use aleo_rust_sdk::snarkvm::prelude::TestRng;\n";
    assert!(bare_snarkvm_imports(good).is_empty());
}
