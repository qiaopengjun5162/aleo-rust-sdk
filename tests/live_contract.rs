//! Contract checks against the live testnet REST API.
//!
//! Everything here is `#[ignore]`d: it needs the network, so it cannot run in
//! the PR gate. The offline suite in `network_coverage.rs` mocks the shapes the
//! client *expects*; this file asserts the shapes the node *returns*. Those are
//! different claims, and they have drifted four times — a mock that encodes a
//! wrong expectation stays green forever.
//!
//! Each test names the measured fact it locks down, so a failure reads as
//! "the node changed", not "some assertion broke".
//!
//! Run them:
//!
//! ```bash
//! ALEO_REST_URL=https://api.explorer.provable.com/v2/testnet \
//!   cargo test --test live_contract -- --ignored --nocapture
//! ```
//!
//! **A skipped run looks exactly like a passing one.** Without
//! `ALEO_REST_URL` each test prints `skipping` and returns, which the harness
//! scores as `ok`. That is deliberate: `.github/workflows/slow-tests.yml` runs
//! every ignored test nightly and does not set this variable, so making a
//! missing variable a hard failure would turn that job red. Read the output, not
//! just the summary.

use aleo_rust_sdk::AleoHttpClient;

/// A client for the node under test, or `None` after explaining the skip.
fn live_client() -> Option<AleoHttpClient> {
    match std::env::var("ALEO_REST_URL") {
        Ok(url) if !url.trim().is_empty() => match AleoHttpClient::new(&url) {
            Ok(client) => Some(client),
            Err(e) => {
                eprintln!("skipping: ALEO_REST_URL={url} did not build a client: {e}");
                None
            }
        },
        _ => {
            eprintln!("skipping: set ALEO_REST_URL=https://api.explorer.provable.com/v2/testnet");
            None
        }
    }
}

/// The block to sample for the transaction-shaped tests, from
/// `ALEO_BLOCK_HEIGHT`.
///
/// Most testnet blocks are empty, so finding one is not something the test can
/// do cheaply — walking back from the tip took ~200 requests without a hit.
/// The caller supplies a height known to contain a transaction:
///
/// ```bash
/// H=$(curl -s .../block/height/latest)
/// for d in $(seq 1 60); do
///   n=$(curl -s ".../block/$((H-d))/transactions" | jq length)
///   [ "$n" -gt 0 ] && echo "$((H-d))" && break
/// done
/// ```
fn block_with_a_transaction() -> Option<u32> {
    match std::env::var("ALEO_BLOCK_HEIGHT").ok().and_then(|s| s.trim().parse().ok()) {
        Some(height) => Some(height),
        None => {
            eprintln!("skipping: set ALEO_BLOCK_HEIGHT to a height that has a transaction");
            None
        }
    }
}

/// The three "latest" routes answer in three different shapes, and the client
/// parses each one differently.
///
/// `block/hash/latest` and `stateRoot/latest` are JSON *strings* (quotes
/// included); `block/height/latest` is a bare integer. Reading any of them with
/// the wrong parser yields either a parse error or a value with quotes in it.
#[tokio::test]
#[ignore = "live testnet call; needs ALEO_REST_URL"]
async fn latest_routes_answer_in_three_different_shapes() {
    let Some(client) = live_client() else { return };

    let hash = client
        .fetch_latest_block_hash()
        .await
        .expect("block/hash/latest must return a bare bech32 hash, quotes stripped");
    assert!(
        hash.starts_with("ab1") && !hash.contains('"'),
        "latest block hash came back as {hash:?}; if it now includes quotes or a \
         wrapper object, `fetch_latest_block_hash` needs a different parser"
    );

    let height = client
        .fetch_block_height()
        .await
        .expect("block/height/latest must parse as a u32");
    assert!(height > 0, "block height came back as {height}");

    let (_, root_height) = client
        .fetch_state_root()
        .await
        .expect("stateRoot/latest must parse as a bech32m state root");
    assert!(
        root_height.abs_diff(height) <= 2,
        "the height read before the root ({height}) and the one returned with it \
         ({root_height}) drifted apart; the doc says the pair is read in sequence \
         for exactly this reason"
    );
}

/// `/height/{block_hash}` returns that block's own height — not the next one.
///
/// This is worth pinning because `/stateRoot/{h}` *is* shifted by one (it is the
/// root after executing block `h`, i.e. the next block's `previous_state_root`).
/// The two routes sit next to each other in the docs and behave differently.
#[tokio::test]
#[ignore = "live testnet call; needs ALEO_REST_URL"]
async fn height_lookup_is_exact_not_shifted_by_one() {
    let Some(client) = live_client() else { return };

    let latest = client.fetch_block_height().await.expect("latest height");
    // Stay a few blocks back so the sampled block cannot be reorged mid-test.
    for offset in [5u32, 50] {
        let height = latest.saturating_sub(offset);
        let block = client.fetch_block(&height.to_string()).await.expect("block by height");
        let block_hash = block["block_hash"].as_str().expect("a block has a block_hash string");

        let back = client
            .fetch_block_height_of_hash(block_hash)
            .await
            .expect("height for a block hash");
        assert_eq!(
            back, height,
            "hash of block {height} resolved back to {back}; an off-by-one here \
             would make every hash lookup point at the wrong block"
        );
    }
}

/// A block has no top-level `height`; the number lives in `header.metadata`.
///
/// `block["height"]` is `null` for both the by-height and by-hash forms, which
/// is the first thing a reader tries.
#[tokio::test]
#[ignore = "live testnet call; needs ALEO_REST_URL"]
async fn a_block_keeps_its_height_inside_header_metadata() {
    let Some(client) = live_client() else { return };

    let latest = client.fetch_block_height().await.expect("latest height");
    let height = latest.saturating_sub(5);

    let by_height = client.fetch_block(&height.to_string()).await.expect("block by height");
    assert!(
        by_height.get("height").is_none(),
        "a top-level `height` appeared; if this is intentional, the doc on \
         `fetch_block` is now wrong"
    );
    let reported = by_height["header"]["metadata"]["height"]
        .as_u64()
        .expect("header.metadata.height must be a number");
    assert_eq!(reported as u32, height);

    let block_hash = by_height["block_hash"].as_str().expect("block_hash");
    let by_hash = client.fetch_block(block_hash).await.expect("block by hash");
    assert_eq!(
        by_hash["block_hash"], by_height["block_hash"],
        "fetching one block by height and by hash returned different blocks"
    );
    assert!(
        by_hash.get("height").is_none(),
        "the by-hash form grew a top-level `height` that the by-height form lacks"
    );
}

/// `/transaction/{id}` puts the id at the top level.
///
/// That is *not* how the same transaction looks inside
/// `/block/{h}/transactions`, where the id sits at `element["transaction"]["id"]`
/// and the top level has no `id` at all. Two routes, two shapes.
#[tokio::test]
#[ignore = "live testnet call; needs ALEO_REST_URL"]
async fn a_transaction_has_a_top_level_id_inside_a_block_it_does_not() {
    let Some(client) = live_client() else { return };
    let Some(height) = block_with_a_transaction() else {
        return;
    };

    let txs = client.fetch_block_transactions(height).await.expect("block transactions");
    let Some(element) = txs.as_array().and_then(|a| a.first()) else {
        eprintln!("skipping: block {height} has no transactions");
        return;
    };

    assert!(
        element.get("id").is_none(),
        "block {height}: the transaction element grew a top-level `id`; \
         `fetch_block_transactions` documents it as nested under `transaction`"
    );
    let tx_id = element["transaction"]["id"]
        .as_str()
        .expect("a transaction element carries transaction.id");
    assert!(tx_id.starts_with("at1"), "unexpected id shape: {tx_id}");

    // The single-transaction route does have a top-level `id`.
    let raw = client.fetch_transaction(tx_id).await.expect("transaction by id");
    let parsed: serde_json::Value = serde_json::from_str(&raw).expect("transaction JSON");
    assert_eq!(
        parsed["id"].as_str(),
        Some(tx_id),
        "/transaction/{{id}} lost its top-level `id`, or returned a different one"
    );
}

/// `/transaction/confirmed/{id}` reports a `status` string, and `accepted` means
/// what it says.
///
/// `wait_for_confirmation_with` confirms only on an exact `accepted` status;
/// `rejected` is an error and any other value keeps polling. This pins the two
/// values that were actually observed, so a new status value shows up here
/// before it is mistaken for confirmation in the poll loop.
#[tokio::test]
#[ignore = "live testnet call; needs ALEO_REST_URL"]
async fn a_confirmed_transaction_reports_an_accepted_status() {
    let Some(client) = live_client() else { return };
    let Some(height) = block_with_a_transaction() else {
        return;
    };

    let txs = client.fetch_block_transactions(height).await.expect("block transactions");
    let Some(tx_id) = txs
        .as_array()
        .and_then(|a| a.first())
        .and_then(|e| e["transaction"]["id"].as_str())
    else {
        eprintln!("skipping: block {height} has no transactions");
        return;
    };

    // The client's own poll loop, with a single attempt: it returns Ok only on
    // an exact `accepted` status, which is the fact under test.
    let poll = aleo_rust_sdk::ConfirmationPoll {
        attempts: 1,
        interval: std::time::Duration::from_millis(0),
    };
    client.wait_for_confirmation_with(tx_id, poll).await.unwrap_or_else(|e| {
        panic!(
            "a transaction already inside block {height} did not report a \
                 confirming status: {e}"
        )
    });
}

/// The freeze list ends with the Merkle root, which is the value callers compare
/// against to decide whether a cached exclusion proof is still valid.
#[tokio::test]
#[ignore = "live testnet call; needs ALEO_REST_URL"]
async fn the_freeze_list_ends_with_a_decimal_root() {
    let Some(client) = live_client() else { return };

    let tree = client
        .fetch_stablecoin_merkle_tree("test_usdcx_freezelist.aleo")
        .await
        .expect("freeze list from /programs/{id}/compliance/freeze-list");

    assert!(!tree.is_empty(), "the freeze list came back empty");
    let last = tree.last().expect("non-empty");
    assert!(
        !last.is_empty() && last.chars().all(|c| c.is_ascii_digit()),
        "the last element is documented as the Merkle root, a decimal string; got {last:?}"
    );
}

/// A fresh address has no `credits.aleo/account` entry.
///
/// Measured 2026-11-22: the gateway answers `200` with a bare `null` for this
/// case, not a 404. `fetch_mapping_value_rest` must read both as `None`; an
/// error here breaks the README's second Quick Start snippet, which generates
/// a random account and asks for its balance immediately.
#[tokio::test]
#[ignore = "live testnet call; needs ALEO_REST_URL"]
async fn a_fresh_address_answers_null_not_an_error() {
    let Some(client) = live_client() else { return };

    let mut rng = aleo_rust_sdk::snarkvm::prelude::TestRng::default();
    let account = aleo_rust_sdk::AleoAccount::new_random(&mut rng)
        .expect("generate a fresh address with no on-chain entry");
    let balance = client
        .fetch_mapping_value_rest("credits.aleo", "account", &account.address_str())
        .await
        .expect("a fresh address must read as 'no entry', not a format-change error");
    assert_eq!(
        balance, None,
        "a randomly generated address unexpectedly has an account entry; \
         if this is no longer reliable, use a fixed known-empty address"
    );
}
