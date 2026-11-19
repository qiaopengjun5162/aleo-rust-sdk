# Upgrading to 0.12

Three things changed in the public API. If you only use accounts, transfers,
execution, or the REST client, **nothing below applies to you** — no code change
is needed.

Each change below shows the old shape and the exact edit.

## 1. Five staking planners no longer return `Result`

`plan_bond_public`, `plan_bond_validator`, `plan_unbond_public`,
`plan_claim_unbond_public`, and `plan_set_validator_state` never actually failed —
they only formatted strings — but they returned `Result` anyway. They now return
`CreditsCall` directly.

```rust,ignore
// 0.11 — had to unwrap (or ?) a Result that could not be an Err
let call = plan_unbond_public("aleo1...", 1_000_000).unwrap();

// 0.12 — just delete the unwrap
let call = plan_unbond_public("aleo1...", 1_000_000);
```

`plan_transfer`, `plan_join`, and `plan_split` **still** return `Result` (they can
fail on a malformed record), so leave those alone.

## 2. Record scanners return `ScanOutcome`, not `Vec`

`RecordScanner::{scan_blocks, scan_recent}`, `HostedScanner::fetch`, and
`RecordSource::fetch` now return a `ScanOutcome { records, truncated }`. The
truncation flag is the point of the change: a scan used to stop silently at
50 000 records and look like a complete result.

```rust,ignore
// 0.11
let records: Vec<AleoRecord> = scanner.scan_recent(&view_key, 100).await?;

// 0.12 — take .records, and decide what to do when truncated
let outcome = scanner.scan_recent(&view_key, 100).await?;
if outcome.truncated {
    // This is a prefix, not the whole range. Narrow the range or scan in
    // slices and union the results; re-running the same scan hits the same
    // ceiling.
}
let records = outcome.records; // or outcome.into_records() to consume it
```

If you genuinely want the old behaviour — the prefix, ignoring truncation —
use `scanner.scan_recent(&view_key, n).await?.into_records()`.

`RecordManager::scan_recent` still returns `&[AleoRecord]`; it gained a separate
`last_scan_truncated()` accessor for the same flag.

## 3. `CreditsFunction` is `#[non_exhaustive]`

An exhaustive `match` on `CreditsFunction` no longer compiles. Add a wildcard arm:

```rust,ignore
// 0.12
match function {
    CreditsFunction::TransferPublic => { /* ... */ }
    _ => { /* upstream may add functions */ }
}
```

The variant set mirrors one snarkVM release; upstream has added functions before
(`bond_validator`, `unbond_validator`), so an exhaustive match was never safe
across upgrades.

---

## What does *not* require a code change

Everything else is additive or internal, so you can ignore it:

- `ScanOutcome` is new, and `RecordManager` gained `last_scan_truncated()`.
- Two new constants: `record::MAX_SCAN_PAGES` and
  `network::MAX_CONCURRENT_BLOCK_REQUESTS`.
- `ExecutionEngine::deployment_cost_minimum` renamed its `_consensus_version`
  parameter to `consensus_version` (the underscore was a lie — the value is
  used). Parameter names are not part of the call contract, so no call site
  changes.

The three sections above are the only edits a build will force on you. See the
[0.12.0 release
notes](https://github.com/qiaopengjun5162/aleo-rust-sdk/releases/tag/aleo-rust-sdk-v0.12.0)
for the full diff.
