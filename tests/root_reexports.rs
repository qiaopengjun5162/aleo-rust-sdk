//! The record-scanning types are reachable from the crate root, like every
//! other module's entry points.
//!
//! `credits` exports `CreditsCall` at the root and `scanner` exports its whole
//! set, so `record` exporting nothing at the root was the odd one out. The
//! 0.12 upgrade guide is where it showed: §1 names `CreditsCall`, §2 names
//! `ScanOutcome`, and only one of them could be imported from the root.

use aleo_rust_sdk::{
    AleoRecord, HostedScanner, RecordManager, RecordScanner, RecordSearchParams, RecordSource,
    ScanOutcome,
};

/// Resolving every name above is most of this test; the assertions cover the
/// one type that can be built without a network or a view key.
#[test]
fn record_types_are_exported_at_the_root() {
    let outcome = ScanOutcome::default();
    assert!(outcome.is_empty());
    assert!(!outcome.truncated);
    assert_eq!(outcome.len(), 0);

    // Compile-time only: a type position is enough to prove the import is not
    // dead code.
    fn _types_resolve(
        _: Option<RecordScanner>,
        _: Option<RecordManager>,
        _: Option<HostedScanner>,
        _: Option<RecordSearchParams>,
        _: Option<AleoRecord>,
        _: Option<RecordSource>,
    ) {
    }
}
