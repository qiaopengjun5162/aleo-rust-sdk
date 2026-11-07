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

// ── Hosted source: the same manager, backed by the Record Scanning Service ──

/// These tests exist because the two sources are *not* interchangeable in the
/// small print: the hosted one registers a view key, reuses a uuid across
/// scans, filters by a height the service reports, and is the only source that
/// can tell you a record is spent. Every one of those is a place the manager
/// could silently report the wrong balance.
mod hosted_source {
    use super::*;
    use aleo_rust_sdk::hosted::ApiAuth;
    use aleo_rust_sdk::record::{BlockRange, HostedScanner, RecordSource, ScanWindow};
    use aleo_rust_sdk::scanner::RecordScanService;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use crypto_box::SecretKey;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::{Request, Respond};

    fn service(server: &MockServer) -> RecordScanService {
        RecordScanService::with_endpoints(server.uri(), server.uri(), ApiAuth::None).unwrap()
    }

    /// `/pubkey` answered `times` times — the count is the assertion that a
    /// second scan does not re-register.
    async fn mock_pubkey(server: &MockServer, times: u64) {
        Mock::given(method("GET"))
            .and(path("/pubkey"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "key_id": "key-1",
                "public_key": BASE64.encode(SecretKey::from([7u8; 32]).public_key().to_bytes()),
            })))
            .expect(times)
            .mount(server)
            .await;
    }

    /// `/register/encrypted` answering with `uuids` in order, then repeating
    /// the last. Two mocks on the same matcher would leave the winner up to
    /// wiremock's ordering, which is not something a test should depend on.
    async fn mock_register(server: &MockServer, uuids: &[&str], times: u64) {
        let responses: Vec<ResponseTemplate> = uuids
            .iter()
            .map(|uuid| {
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "uuid": uuid, "status": "pending" }))
            })
            .collect();

        Mock::given(method("POST"))
            .and(path("/register/encrypted"))
            .respond_with(Sequence {
                responses,
                calls: Arc::new(AtomicUsize::new(0)),
            })
            .expect(times)
            .mount(server)
            .await;
    }

    fn owned_record(
        program: &str,
        ciphertext: &str,
        height: Option<u32>,
        spent: bool,
    ) -> serde_json::Value {
        let mut value = serde_json::json!({
            "program_name": program,
            "record_name": "credits",
            "record_ciphertext": ciphertext,
            "spent": spent,
        });
        if let Some(height) = height {
            value["block_height"] = height.into();
        }
        value
    }

    /// `/records/owned` that answers with `responses` in order, repeating the
    /// last one. A plain `Mock` cannot express "422 first, then 200", and
    /// mounting two mocks leaves the winner up to wiremock's ordering.
    struct Sequence {
        responses: Vec<ResponseTemplate>,
        calls: Arc<AtomicUsize>,
    }

    impl Respond for Sequence {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            let index = self.calls.fetch_add(1, Ordering::SeqCst);
            self.responses
                .get(index)
                .unwrap_or_else(|| self.responses.last().expect("non-empty"))
                .clone()
        }
    }

    /// Mount `Sequence` and return the shared call counter.
    async fn mock_owned(server: &MockServer, responses: Vec<ResponseTemplate>) -> Arc<AtomicUsize> {
        let calls = Arc::new(AtomicUsize::new(0));
        Mock::given(method("POST"))
            .and(path("/records/owned"))
            .respond_with(Sequence {
                responses,
                calls: Arc::clone(&calls),
            })
            .mount(server)
            .await;
        calls
    }

    fn array(body: serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(body)
    }

    /// One registration, two scans. The second scan must reuse the uuid instead
    /// of minting a new one, and the record must be decrypted locally even
    /// though the service already claims a plaintext.
    #[tokio::test]
    async fn hosted_source_registers_once_and_decrypts_locally() {
        let rng = &mut TestRng::default();
        let acct = account(rng);
        let ciphertext = encrypted_record(&acct, "750u64", rng);

        let server = MockServer::start().await;
        mock_pubkey(&server, 1).await;
        mock_register(&server, &["uuid-1"], 1).await;
        let calls = mock_owned(
            &server,
            vec![array(serde_json::json!([owned_record(
                "credits.aleo",
                &ciphertext,
                Some(10),
                false
            )]))],
        )
        .await;

        let mut mgr = RecordManager::with_source(
            RecordSource::Hosted(HostedScanner::new(service(&server), 0)),
            &acct.view_key.to_string(),
        )
        .unwrap();

        let records = mgr.scan_range(0, 100).await.unwrap().to_vec();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].microcredits, 750,
            "the amount must come from local decryption"
        );
        assert_eq!(mgr.balance(), 750);

        // Same uuid, no new registration.
        assert_eq!(mgr.scan_range(0, 100).await.unwrap().len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// A 422 means the uuid is gone. Re-registering once is the prescribed
    /// recovery; retrying the same uuid, or looping, is not.
    #[tokio::test]
    async fn hosted_source_reregisters_once_when_the_uuid_goes_stale() {
        let rng = &mut TestRng::default();
        let acct = account(rng);
        let ciphertext = encrypted_record(&acct, "42u64", rng);

        let server = MockServer::start().await;
        mock_pubkey(&server, 2).await;
        // Two registrations, in order: the first uuid goes stale.
        mock_register(&server, &["uuid-1", "uuid-2"], 2).await;
        let calls = mock_owned(
            &server,
            vec![
                ResponseTemplate::new(422).set_body_string("uuid not found"),
                array(serde_json::json!([owned_record(
                    "credits.aleo",
                    &ciphertext,
                    Some(3),
                    false
                )])),
            ],
        )
        .await;

        let mut source = RecordSource::Hosted(HostedScanner::new(service(&server), 0));
        let records = source
            .fetch(&acct.view_key, ScanWindow::All)
            .await
            .expect("the retry after re-registration must succeed");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].microcredits, 42);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "one stale response, one retry — no loop"
        );

        // The retry must carry the *new* uuid: re-registering but then querying
        // the dead one would look identical from the outside.
        let received = server.received_requests().await.unwrap();
        let last = received
            .iter()
            .rfind(|r| r.url.path() == "/records/owned")
            .expect("two /records/owned calls");
        assert!(
            String::from_utf8_lossy(&last.body).contains("uuid-2"),
            "the retry used the stale uuid: {}",
            String::from_utf8_lossy(&last.body)
        );
    }

    /// Ranges are applied on the height the service reports, because the
    /// service filters by its registration window rather than per request.
    /// A record with no reported height is kept: dropping it would under-report.
    #[tokio::test]
    async fn hosted_source_filters_by_the_reported_block_height() {
        let rng = &mut TestRng::default();
        let acct = account(rng);
        let in_range = encrypted_record(&acct, "10u64", rng);
        let too_old = encrypted_record(&acct, "20u64", rng);
        let unknown = encrypted_record(&acct, "40u64", rng);

        let server = MockServer::start().await;
        mock_pubkey(&server, 1).await;
        mock_register(&server, &["uuid-1"], 1).await;
        mock_owned(
            &server,
            vec![array(serde_json::json!([
                owned_record("credits.aleo", &in_range, Some(5), false),
                owned_record("credits.aleo", &too_old, Some(500), false),
                owned_record("credits.aleo", &unknown, None, false),
            ]))],
        )
        .await;

        let mut source = RecordSource::Hosted(HostedScanner::new(service(&server), 0));
        let records = source
            .fetch(&acct.view_key, ScanWindow::Range(BlockRange::new(1, 100)))
            .await
            .unwrap();
        let amounts: Vec<u64> = records.iter().map(|r| r.microcredits).collect();
        assert_eq!(
            amounts,
            vec![40, 10],
            "height 500 is out of range; the heightless record stays; largest first"
        );
    }

    /// Records that decrypt but were since spent must drop out of the balance.
    /// This is why the default filter is "everything": `unspent()` would stop
    /// the second scan from ever learning about the spend.
    #[tokio::test]
    async fn hosted_source_refreshes_spent_status_on_rescan() {
        let rng = &mut TestRng::default();
        let acct = account(rng);
        let ciphertext = encrypted_record(&acct, "100u64", rng);

        let server = MockServer::start().await;
        mock_pubkey(&server, 1).await;
        mock_register(&server, &["uuid-1"], 1).await;
        mock_owned(
            &server,
            vec![
                array(serde_json::json!([owned_record(
                    "credits.aleo",
                    &ciphertext,
                    Some(1),
                    false
                )])),
                array(serde_json::json!([owned_record(
                    "credits.aleo",
                    &ciphertext,
                    Some(1),
                    true
                )])),
            ],
        )
        .await;

        let mut mgr = RecordManager::with_source(
            RecordSource::Hosted(HostedScanner::new(service(&server), 0)),
            &acct.view_key.to_string(),
        )
        .unwrap();

        assert_eq!(mgr.get_balance().await.unwrap(), 100);
        assert_eq!(mgr.scan().await.unwrap().len(), 1);
        assert_eq!(mgr.balance(), 0, "the rescan must overwrite spent status");
    }

    /// A response whose records do not decrypt is a protocol break, not an
    /// empty wallet. Returning zero here is the failure mode that makes a
    /// funded account look drained.
    #[tokio::test]
    async fn hosted_source_refuses_to_report_an_empty_balance_on_undecryptable_records() {
        let rng = &mut TestRng::default();
        let acct = account(rng);
        let someone_else = account(rng);
        let foreign = encrypted_record(&someone_else, "999u64", rng);

        let server = MockServer::start().await;
        mock_pubkey(&server, 1).await;
        mock_register(&server, &["uuid-1"], 1).await;
        mock_owned(
            &server,
            vec![array(serde_json::json!([owned_record(
                "credits.aleo",
                &foreign,
                Some(1),
                false
            )]))],
        )
        .await;

        let mut mgr = RecordManager::with_source(
            RecordSource::Hosted(HostedScanner::new(service(&server), 0)),
            &acct.view_key.to_string(),
        )
        .unwrap();

        let err = mgr.get_balance().await.unwrap_err();
        assert!(
            err.to_string().contains("none decrypted"),
            "expected a refusal, got: {err}"
        );
    }

    /// Only the hosted source knows about spends; the local one must not
    /// pretend otherwise.
    #[test]
    fn only_the_hosted_source_reports_spent_status() {
        let rng = &mut TestRng::default();
        let acct = account(rng);
        let mgr = RecordManager::new(client_stub(), &acct.view_key.to_string()).unwrap();
        assert!(!mgr.reports_spent());
        assert!(matches!(mgr.source(), RecordSource::Local(_)));
    }
}
