//! Tests for the record decryption path in [`aleo_rust_sdk::record`].
//!
//! Before this file existed, `RecordScanner::decrypt_record` had **zero**
//! coverage: no test had ever fed it a ciphertext, because a real one can only
//! be obtained by transacting on chain. Every assertion below builds a genuine
//! snarkVM record, encrypts it with a real randomizer/nonce pair, and serves the
//! resulting ciphertext from a mock JSON-RPC server — so the scanner runs its
//! actual code path, not a stub.
//!
//! The records are real Aleo plaintexts: `Owner::Private(Literal::Address)`
//! plus a private `microcredits` entry, encrypted under the account's view key.

use aleo_rust_sdk::account::AleoAccount;
use aleo_rust_sdk::network::AleoHttpClient;
use aleo_rust_sdk::record::{AleoRecord, RecordManager, RecordScanner};
use indexmap::IndexMap;
use snarkvm::console::program::{Entry, Identifier, Literal, Plaintext, Record};
use snarkvm::prelude::{FromStr, Network, Owner, Scalar, TestRng, TestnetV0, U8};
use snarkvm::utilities::rand::Uniform;
use std::collections::BTreeMap;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PER_PAGE: usize = 500;

/// Encrypt a record for `account` holding a **private** `microcredits` entry,
/// and return its on-chain ciphertext string.
///
/// `literal` is the plaintext form snarkVM accepts for the entry value, e.g.
/// `"1000000u64"` — the visibility suffix is added by `Entry::Private`, not by
/// the plaintext.
fn encrypted_record(account: &AleoAccount, literal: &str, rng: &mut TestRng) -> String {
    encrypted_with_entry(
        account,
        Entry::Private(Plaintext::from_str(literal).unwrap()),
        rng,
    )
}

/// Same, but the entry is marked `public` — legal in Aleo, since visibility is
/// per entry rather than per record.
fn encrypted_record_public(account: &AleoAccount, literal: &str, rng: &mut TestRng) -> String {
    encrypted_with_entry(
        account,
        Entry::Public(Plaintext::from_str(literal).unwrap()),
        rng,
    )
}

fn encrypted_with_entry(
    account: &AleoAccount,
    entry: Entry<TestnetV0, Plaintext<TestnetV0>>,
    rng: &mut TestRng,
) -> String {
    // snarkVM requires `nonce == g_scalar_multiply(randomizer)`, which is how the
    // view key later recovers `(nonce * vk) == (address * randomizer)`.
    let randomizer = Scalar::rand(rng);
    let nonce = TestnetV0::g_scalar_multiply(&randomizer);
    let owner = Owner::Private(Plaintext::from(Literal::Address(account.address)));
    let mut data = IndexMap::new();
    data.insert(Identifier::from_str("microcredits").unwrap(), entry);
    let plaintext =
        Record::<TestnetV0, Plaintext<TestnetV0>>::from_plaintext(owner, data, nonce, U8::new(0))
            .unwrap();
    plaintext.encrypt(randomizer).unwrap().to_string()
}

fn jsonrpc_entry(program_id: &str, ciphertext: &str) -> serde_json::Value {
    serde_json::json!({ "program_id": program_id, "record_ciphertext": ciphertext })
}

/// Mock the `records/all` RPC so that page 0 returns `entries`.
async fn mock_rpc(entries: serde_json::Value) -> Mock {
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("\"page\":0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": entries,
        })))
}

fn client(server: &MockServer) -> AleoHttpClient {
    AleoHttpClient::new_with_rpc(&format!("{}/v2/testnet", server.uri()), &server.uri()).unwrap()
}

fn account(rng: &mut TestRng) -> AleoAccount {
    AleoAccount::new_random(rng).unwrap()
}

/// A record encrypted for the scanning view key must be decrypted, with its
/// amount and program id intact.
#[tokio::test]
async fn scan_decrypts_a_record_owned_by_the_view_key() {
    let rng = &mut TestRng::default();
    let acct = account(rng);
    let ciphertext = encrypted_record(&acct, "1000000u64", rng);

    let server = MockServer::start().await;
    mock_rpc(serde_json::json!([jsonrpc_entry(
        "credits.aleo",
        &ciphertext
    )]))
    .await
    .mount(&server)
    .await;

    let scanner = RecordScanner::new(client(&server));
    let records = scanner.scan_blocks(&acct.view_key.to_string(), 1, 2).await.unwrap();

    assert_eq!(records.len(), 1, "own record must be discovered");
    assert_eq!(records[0].microcredits, 1_000_000);
    assert_eq!(records[0].program_id, "credits.aleo");
    assert_eq!(records[0].owner, acct.address);
    assert_eq!(records[0].ciphertext, ciphertext);
    assert!(!records[0].spent, "freshly scanned records start unspent");
    assert_eq!(
        records[0].data.get("microcredits").map(String::as_str),
        Some("1000000u64.private"),
        "raw entry text is preserved verbatim, visibility suffix included"
    );
}

/// A record encrypted for someone else must be silently skipped, not decrypted
/// and not turned into an error.
///
/// This is the invariant the deleted `expected_owner` check used to *claim* to
/// enforce. It is enforced by `Record::decrypt` instead, and this test is what
/// now keeps that guarantee honest: if a future snarkVM stops checking the owner
/// during decryption, this test fails.
#[tokio::test]
async fn scan_rejects_a_record_encrypted_for_another_account() {
    let rng = &mut TestRng::default();
    let me = account(rng);
    let someone_else = account(rng);
    let foreign = encrypted_record(&someone_else, "9999999u64", rng);

    let server = MockServer::start().await;
    mock_rpc(serde_json::json!([jsonrpc_entry("credits.aleo", &foreign)]))
        .await
        .mount(&server)
        .await;

    let scanner = RecordScanner::new(client(&server));
    let records = scanner.scan_blocks(&me.view_key.to_string(), 1, 2).await.unwrap();

    assert!(
        records.is_empty(),
        "another account's record must never be reported as ours"
    );
}

/// A garbage ciphertext (a non-record string from a broken indexer) must be
/// skipped rather than aborting the whole scan.
#[tokio::test]
async fn scan_skips_unparsable_ciphertext() {
    let rng = &mut TestRng::default();
    let acct = account(rng);
    let good = encrypted_record(&acct, "42u64", rng);

    let server = MockServer::start().await;
    mock_rpc(serde_json::json!([
        jsonrpc_entry("credits.aleo", "record1not-a-valid-bech32-string"),
        jsonrpc_entry("credits.aleo", &good),
    ]))
    .await
    .mount(&server)
    .await;

    let scanner = RecordScanner::new(client(&server));
    let records = scanner.scan_blocks(&acct.view_key.to_string(), 1, 2).await.unwrap();

    assert_eq!(records.len(), 1, "one bad entry must not hide the good one");
    assert_eq!(records[0].microcredits, 42);
}

/// Entries with no `record_ciphertext` field (transition outputs, other record
/// kinds) must be skipped without attempting decryption.
#[tokio::test]
async fn scan_skips_entries_without_ciphertext() {
    let rng = &mut TestRng::default();
    let acct = account(rng);

    let server = MockServer::start().await;
    mock_rpc(serde_json::json!([
        { "program_id": "credits.aleo" },
        { "program_id": "credits.aleo", "record_ciphertext": "" },
        jsonrpc_entry("credits.aleo", &encrypted_record(&acct, "7u64", rng)),
    ]))
    .await
    .mount(&server)
    .await;

    let scanner = RecordScanner::new(client(&server));
    let records = scanner.scan_blocks(&acct.view_key.to_string(), 1, 2).await.unwrap();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].microcredits, 7);
}

/// A record whose `microcredits` value is not a `u64` must be reported with
/// amount 0 instead of panicking or being dropped silently — the caller still
/// gets the ciphertext and the raw data.
#[tokio::test]
async fn scan_reports_zero_amount_for_non_u64_microcredits() {
    let rng = &mut TestRng::default();
    let acct = account(rng);
    let weird = encrypted_record(&acct, "1u8", rng);

    let server = MockServer::start().await;
    mock_rpc(serde_json::json!([jsonrpc_entry("credits.aleo", &weird)]))
        .await
        .mount(&server)
        .await;

    let scanner = RecordScanner::new(client(&server));
    let records = scanner.scan_blocks(&acct.view_key.to_string(), 1, 2).await.unwrap();

    assert_eq!(records.len(), 1, "record is still returned");
    assert_eq!(records[0].microcredits, 0, "unparsable amount becomes 0");
    assert!(
        records[0].data.contains_key("microcredits"),
        "raw entry is still exposed so the caller can inspect it"
    );
}

/// Results are sorted largest-first, because coin selection walks the list in
/// order and expects the biggest usable record first.
#[tokio::test]
async fn scan_sorts_records_largest_first() {
    let rng = &mut TestRng::default();
    let acct = account(rng);

    let server = MockServer::start().await;
    mock_rpc(serde_json::json!([
        jsonrpc_entry("credits.aleo", &encrypted_record(&acct, "5u64", rng)),
        jsonrpc_entry("credits.aleo", &encrypted_record(&acct, "900u64", rng)),
        jsonrpc_entry("credits.aleo", &encrypted_record(&acct, "70u64", rng)),
    ]))
    .await
    .mount(&server)
    .await;

    let scanner = RecordScanner::new(client(&server));
    let records = scanner.scan_blocks(&acct.view_key.to_string(), 1, 2).await.unwrap();

    let amounts: Vec<u64> = records.iter().map(|r| r.microcredits).collect();
    assert_eq!(amounts, vec![900, 70, 5]);
}

/// A page shorter than `recordsPerRequest` is the last page: scanning must stop
/// after exactly one request instead of probing until the page cap.
#[tokio::test]
async fn scan_stops_after_a_short_page() {
    let rng = &mut TestRng::default();
    let acct = account(rng);

    let server = MockServer::start().await;
    mock_rpc(serde_json::json!([jsonrpc_entry(
        "credits.aleo",
        &encrypted_record(&acct, "1u64", rng)
    )]))
    .await
    .expect(1) // exact: a second request would mean pagination never terminates
    .mount(&server)
    .await;

    let scanner = RecordScanner::new(client(&server));
    let records = scanner.scan_blocks(&acct.view_key.to_string(), 1, 2).await.unwrap();

    assert_eq!(records.len(), 1);
    assert!(PER_PAGE > records.len());
}

// ── RecordManager: caching, dedupe, balance ─────────────────────────────

fn fake_record(amount: u64, program: &str, ciphertext: &str, spent: bool) -> AleoRecord {
    let rng = &mut TestRng::default();
    AleoRecord {
        program_id: program.to_string(),
        owner: account(rng).address,
        microcredits: amount,
        data: BTreeMap::new(),
        ciphertext: ciphertext.to_string(),
        spent,
    }
}

/// `balance()` counts only unspent `credits.aleo` records — a spent record or a
/// record from another program must not inflate the spendable balance.
#[test]
fn balance_counts_only_unspent_credits_records() {
    let rng = &mut TestRng::default();
    let acct = account(rng);
    let mut mgr = RecordManager::new(client_stub(), &acct.view_key.to_string()).unwrap();

    mgr.merge_records(vec![
        fake_record(100, "credits.aleo", "c1", false),
        fake_record(999, "credits.aleo", "c2", true),
        fake_record(5000, "token.aleo", "c3", false),
        fake_record(23, "credits.aleo", "c4", false),
    ]);

    assert_eq!(mgr.balance(), 123);
}

/// Re-scanning an overlapping range must not duplicate records: the cache is
/// keyed by ciphertext, and the newer copy replaces the older one.
///
/// The assertion is on `balance()` rather than a record count because it
/// distinguishes both failure modes at once: appending would leave the older
/// *unspent* copy behind (balance 10), and failing to update would keep the
/// record unspent (balance 10). Only "replaced, once" gives 0.
#[test]
fn merge_records_dedupes_by_ciphertext_and_keeps_the_latest() {
    let rng = &mut TestRng::default();
    let acct = account(rng);
    let mut mgr = RecordManager::new(client_stub(), &acct.view_key.to_string()).unwrap();

    mgr.merge_records(vec![fake_record(10, "credits.aleo", "same", false)]);
    mgr.merge_records(vec![fake_record(10, "credits.aleo", "same", true)]);

    assert_eq!(
        mgr.balance(),
        0,
        "the cached record must have been replaced by its spent copy, not duplicated"
    );
}

/// A `u64` entry marked `public` must still be read.
///
/// The old parser stripped the literal string `"u64.private"` then `"u64"`, so
/// `5u64.public` became `5.public` and failed to parse — reporting a zero
/// balance for a record that holds 5. Records with a public `microcredits` entry
/// are legal (visibility is per-entry), so this was a real, if narrow, hole.
#[tokio::test]
async fn scan_reads_a_public_u64_entry() {
    let rng = &mut TestRng::default();
    let acct = account(rng);
    let public = encrypted_record_public(&acct, "5u64", rng);

    let server = MockServer::start().await;
    mock_rpc(serde_json::json!([jsonrpc_entry("credits.aleo", &public)]))
        .await
        .mount(&server)
        .await;

    let scanner = RecordScanner::new(client(&server));
    let records = scanner.scan_blocks(&acct.view_key.to_string(), 1, 2).await.unwrap();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].microcredits, 5);
}

/// `get_balance()` scans only when the cache is empty — a second call must use
/// the cache instead of hitting the network again.
#[tokio::test]
async fn get_balance_scans_once_then_serves_from_cache() {
    let rng = &mut TestRng::default();
    let acct = account(rng);

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/testnet/block/height/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"1000", "text/plain"))
        .mount(&server)
        .await;
    mock_rpc(serde_json::json!([jsonrpc_entry(
        "credits.aleo",
        &encrypted_record(&acct, "750u64", rng)
    )]))
    .await
    .expect(1) // exact: the second get_balance must not re-scan
    .mount(&server)
    .await;

    let mut mgr = RecordManager::new(client(&server), &acct.view_key.to_string()).unwrap();
    assert_eq!(mgr.get_balance().await.unwrap(), 750);
    assert_eq!(mgr.get_balance().await.unwrap(), 750);
}

/// `scan_range` refreshes the cache through the same dedupe path, so a record
/// already cached keeps its single entry.
#[tokio::test]
async fn scan_range_merges_instead_of_replacing_the_cache() {
    let rng = &mut TestRng::default();
    let acct = account(rng);
    let ct = encrypted_record(&acct, "300u64", rng);

    let server = MockServer::start().await;
    mock_rpc(serde_json::json!([jsonrpc_entry("credits.aleo", &ct)]))
        .await
        .mount(&server)
        .await;

    let mut mgr = RecordManager::new(client(&server), &acct.view_key.to_string()).unwrap();
    assert_eq!(mgr.scan_range(1, 2).await.unwrap().len(), 1);
    assert_eq!(mgr.scan_range(1, 2).await.unwrap().len(), 1);
    assert_eq!(mgr.balance(), 300);
}

/// Invalid view keys must be rejected at construction, not at scan time.
#[test]
fn manager_rejects_an_invalid_view_key() {
    match RecordManager::new(client_stub(), "AViewKey1notaviewkey") {
        Ok(_) => panic!("a bogus view key must not construct a manager"),
        Err(e) => assert!(
            e.to_string().contains("Invalid view key"),
            "unexpected error: {e}"
        ),
    }
}

fn client_stub() -> AleoHttpClient {
    // Never contacted by the synchronous tests above.
    AleoHttpClient::new_with_rpc("http://127.0.0.1:1/v2/testnet", "http://127.0.0.1:1").unwrap()
}

/// Mock the block-height REST endpoint used by `scan_recent`.
async fn mock_height(server: &MockServer, height: u32) {
    Mock::given(method("GET"))
        .and(path("/v2/testnet/block/height/latest"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(height.to_string().into_bytes(), "text/plain"),
        )
        .mount(server)
        .await;
}

/// `scan()` looks back a fixed 100_000 blocks. The window itself is the contract:
/// if it were computed wrongly, a scan would silently miss older records.
#[tokio::test]
async fn manager_scan_looks_back_100k_blocks() {
    let rng = &mut TestRng::default();
    let acct = account(rng);

    let server = MockServer::start().await;
    mock_height(&server, 5_000_000).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("\"start\":4900000"))
        .and(body_string_contains("\"end\":5000000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": [jsonrpc_entry(
                "credits.aleo",
                &encrypted_record(&acct, "12u64", rng)
            )],
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut mgr = RecordManager::new(client(&server), &acct.view_key.to_string()).unwrap();
    assert_eq!(mgr.scan().await.unwrap().len(), 1);
}

/// `scan_recent(n)` must ask the node for `[height - n, height]`, and must clamp
/// at zero rather than underflowing when the chain is younger than the window.
#[tokio::test]
async fn manager_scan_recent_clamps_the_window_at_zero() {
    let rng = &mut TestRng::default();
    let acct = account(rng);

    let server = MockServer::start().await;
    mock_height(&server, 30).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("\"start\":0"))
        .and(body_string_contains("\"end\":30"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": [],
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut mgr = RecordManager::new(client(&server), &acct.view_key.to_string()).unwrap();
    // 1000 > height, so `saturating_sub` must land on 0 instead of panicking.
    assert!(mgr.scan_recent(1000).await.unwrap().is_empty());
}

/// Coin selection reports what the caller can actually spend, and fails when the
/// cache cannot cover the target — the failure mode a transfer depends on.
#[test]
fn select_records_reports_total_and_fails_when_short() {
    let rng = &mut TestRng::default();
    let acct = account(rng);
    let mut mgr = RecordManager::new(client_stub(), &acct.view_key.to_string()).unwrap();
    mgr.merge_records(vec![
        fake_record(100, "credits.aleo", "a", false),
        fake_record(50, "credits.aleo", "b", false),
        fake_record(10_000, "token.aleo", "c", false),
    ]);

    let picked = mgr.select_records(120).unwrap();
    assert_eq!(picked.total_microcredits, 150);
    assert_eq!(
        picked.records.len(),
        2,
        "largest-first until the target is met"
    );

    let err = mgr.select_records(151).unwrap_err();
    assert!(
        err.to_string().contains("Insufficient"),
        "unexpected error: {err}"
    );
}

/// A record marked spent must drop out of both the balance and coin selection —
/// that is the whole point of marking it.
#[test]
fn mark_spent_removes_a_record_from_balance_and_selection() {
    let rng = &mut TestRng::default();
    let acct = account(rng);
    let mut mgr = RecordManager::new(client_stub(), &acct.view_key.to_string()).unwrap();
    mgr.merge_records(vec![
        fake_record(100, "credits.aleo", "a", false),
        fake_record(100, "credits.aleo", "b", false),
    ]);
    assert_eq!(mgr.balance(), 200);

    mgr.mark_spent("a");
    assert_eq!(mgr.balance(), 100, "spent record must leave the balance");
    assert_eq!(
        mgr.select_records(100).unwrap().records[0].ciphertext,
        "b",
        "coin selection must skip the spent record"
    );

    // Marking an unknown ciphertext is a no-op, not a panic.
    mgr.mark_spent("does-not-exist");
    assert_eq!(mgr.balance(), 100);
}

/// The manager exposes the key material it was built from.
#[test]
fn manager_exposes_its_view_key_and_address() {
    let rng = &mut TestRng::default();
    let acct = account(rng);
    let mgr = RecordManager::new(client_stub(), &acct.view_key.to_string()).unwrap();
    assert_eq!(mgr.view_key().to_string(), acct.view_key.to_string());
    assert_eq!(*mgr.address(), acct.address);
}
