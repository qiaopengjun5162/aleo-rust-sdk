//! Compile-guard for the code snippets in `docs/upgrading-0.12.md`.
//!
//! Nothing here runs. Each function mirrors one "0.12" snippet from that doc;
//! if an API changes and the doc goes stale, `cargo clippy --all-targets`
//! (CI) fails. The `0.11` columns are deliberately not compiled — they no
//! longer exist by definition.

use aleo_rust_sdk::credits::{
    plan_bond_public, plan_bond_validator, plan_claim_unbond_public, plan_set_validator_state,
    plan_unbond_public,
};
use aleo_rust_sdk::record::RecordScanner;
use aleo_rust_sdk::{AleoHttpClient, CreditsFunction};

// §1 — the five planners now return `CreditsCall` directly (no unwrap / ?).
#[allow(dead_code)]
fn planners_need_no_unwrap() {
    let _ = plan_bond_public("aleo1validator...", "aleo1withdraw...", 1_000_000);
    let _ = plan_bond_validator("aleo1withdraw...", 1_000_000, 10);
    let _ = plan_unbond_public("aleo1staker...", 1_000_000);
    let _ = plan_claim_unbond_public("aleo1staker...");
    let _ = plan_set_validator_state(true);
}

// §2 — scanners return `ScanOutcome`; `.records` / `.truncated` / `.into_records()`.
#[allow(dead_code)]
async fn scanner_returns_outcome(scanner: &RecordScanner, view_key: &str) -> anyhow::Result<()> {
    let outcome = scanner.scan_recent(view_key, 100).await?;
    if outcome.truncated {
        // narrow the range or scan in slices
    }
    let _records = outcome.records;
    let _owned = scanner.scan_recent(view_key, 100).await?.into_records();
    Ok(())
}

// Keep the `AleoHttpClient` -> `RecordScanner` construction in the doc compilable.
#[allow(dead_code)]
fn build_scanner(client: AleoHttpClient) -> RecordScanner {
    RecordScanner::new(client)
}

// §3 — `CreditsFunction` is non_exhaustive: a wildcard arm is required.
#[allow(dead_code)]
fn credits_function_match_needs_wildcard(function: CreditsFunction) -> &'static str {
    match function {
        CreditsFunction::TransferPublic => "transfer",
        _ => "other",
    }
}

fn main() {}
