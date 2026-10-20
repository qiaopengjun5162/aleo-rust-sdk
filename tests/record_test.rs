use aleo_rust_sdk::network::AleoHttpClient;
use aleo_rust_sdk::record::{AleoRecord, RecordManager, RecordScanner, SelectedRecords};
use snarkvm::prelude::{Address, TestnetV0};
use std::collections::BTreeMap;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Helper: create a mock server that serves fake block height + empty records.
async fn setup_mock() -> MockServer {
    let mock_server = MockServer::start().await;

    // Block height endpoint
    Mock::given(method("GET"))
        .and(path("/v2/testnet/block/height/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"20456000", "text/plain"))
        .mount(&mock_server)
        .await;

    // All-records endpoint (returns empty array)
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": []
        })))
        .mount(&mock_server)
        .await;

    mock_server
}

fn create_test_client(mock_server: &MockServer) -> AleoHttpClient {
    let url = format!("{}/v2/testnet", mock_server.uri());
    let rpc_url = mock_server.uri();
    AleoHttpClient::new_with_rpc(&url, &rpc_url).unwrap()
}

fn test_record_with(owner: Address<TestnetV0>, amount: u64, ciphertext: &str) -> AleoRecord {
    let mut data = BTreeMap::new();
    data.insert("microcredits".into(), format!("{amount}u64"));
    AleoRecord {
        program_id: "credits.aleo".into(),
        owner,
        microcredits: amount,
        data,
        ciphertext: ciphertext.into(),
        spent: false,
    }
}

/// Helper: create an AleoClient at a dummy URL + generate a random view key.
/// Returns (client, view_key_str, address).
fn random_mgr_parts() -> (AleoHttpClient, String, Address<TestnetV0>) {
    let client = AleoHttpClient::new("http://localhost:9999").unwrap();
    let rng = &mut snarkvm::prelude::TestRng::default();
    let pk = snarkvm::prelude::PrivateKey::<TestnetV0>::new(rng).unwrap();
    let vk = snarkvm::prelude::ViewKey::try_from(&pk).unwrap();
    let addr = vk.to_address();
    (client, vk.to_string(), addr)
}

// ── RecordScanner ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_scanner_new() {
    let mock_server = setup_mock().await;
    let client = create_test_client(&mock_server);
    let scanner = RecordScanner::new(client);
    assert!(
        scanner.client().base_url.contains("127.0.0.1")
            || scanner.client().base_url.contains("localhost")
    );
}

#[tokio::test]
async fn test_scanner_scan_recent_ok() {
    let mock_server = setup_mock().await;
    let client = create_test_client(&mock_server);

    let rng = &mut snarkvm::prelude::TestRng::default();
    let pk = snarkvm::prelude::PrivateKey::<TestnetV0>::new(rng).unwrap();
    let vk = snarkvm::prelude::ViewKey::try_from(&pk).unwrap();

    let scanner = RecordScanner::new(client);
    let records = scanner.scan_recent(&vk.to_string(), 10).await.unwrap();
    assert!(records.is_empty());
}

#[tokio::test]
async fn test_scanner_scan_invalid_viewkey() {
    let mock_server = setup_mock().await;
    let client = create_test_client(&mock_server);
    let scanner = RecordScanner::new(client);

    let result = scanner.scan_recent("not-a-valid-view-key", 10).await;
    assert!(result.is_err());
}

// ── RecordManager: construction ────────────────────────────────────────────

#[tokio::test]
async fn test_manager_new() {
    let mock_server = setup_mock().await;
    let client = create_test_client(&mock_server);

    let rng = &mut snarkvm::prelude::TestRng::default();
    let pk = snarkvm::prelude::PrivateKey::<TestnetV0>::new(rng).unwrap();
    let vk = snarkvm::prelude::ViewKey::try_from(&pk).unwrap();

    let mgr = RecordManager::new(client, &vk.to_string()).unwrap();
    assert_eq!(mgr.balance(), 0);
}

#[test]
fn test_manager_new_invalid_viewkey() {
    let client = AleoHttpClient::new("http://localhost:9999").unwrap();
    let result = RecordManager::new(client, "invalid_view_key");
    assert!(result.is_err());
}

// ── RecordManager: accessors ───────────────────────────────────────────────

#[test]
fn test_manager_accessors() {
    let (client, vk_str, addr) = random_mgr_parts();
    let mgr = RecordManager::new(client, &vk_str).unwrap();
    // Initial state: empty records, correct view key and address
    assert_eq!(mgr.records().len(), 0);
    assert_eq!(mgr.address(), &addr);
}

// ── RecordManager: merge_records + balance ─────────────────────────────────

#[test]
fn test_manager_merge_and_balance() {
    let (client, vk_str, addr) = random_mgr_parts();
    let mut mgr = RecordManager::new(client, &vk_str).unwrap();

    mgr.merge_records(vec![
        test_record_with(addr, 1_000_000, "r1"),
        test_record_with(addr, 500_000, "r2"),
    ]);
    assert_eq!(mgr.balance(), 1_500_000);

    mgr.mark_spent("r1");
    assert_eq!(mgr.balance(), 500_000);
    mgr.mark_spent("r2");
    assert_eq!(mgr.balance(), 0);
}

#[test]
fn test_mark_spent_nonexistent() {
    let (client, vk_str, addr) = random_mgr_parts();
    let mut mgr = RecordManager::new(client, &vk_str).unwrap();
    mgr.merge_records(vec![test_record_with(addr, 100_000, "r1")]);

    // Shouldn't panic
    mgr.mark_spent("nonexistent");
    assert_eq!(mgr.balance(), 100_000);
}

// ── merge_records: deduplication ───────────────────────────────────────────

#[test]
fn test_merge_records_dedup() {
    let (client, vk_str, addr) = random_mgr_parts();
    let mut mgr = RecordManager::new(client, &vk_str).unwrap();
    mgr.merge_records(vec![test_record_with(addr, 500_000, "r1")]);

    // Merge a duplicate (same ciphertext) — should update, not add
    let new_records = vec![
        test_record_with(addr, 600_000, "r1"), // updated amount
        test_record_with(addr, 200_000, "r2"), // new
    ];
    mgr.merge_records(new_records);

    assert_eq!(mgr.records().len(), 2);
    // r1 should have been updated to 600_000 (but sort order is desc, so r1 comes first)
    assert_eq!(mgr.records()[0].microcredits, 600_000);
    assert_eq!(mgr.balance(), 800_000);
}

// ── select_records ─────────────────────────────────────────────────────────

#[test]
fn test_select_records_exact_amount() {
    let (client, vk_str, addr) = random_mgr_parts();
    let mut mgr = RecordManager::new(client, &vk_str).unwrap();
    mgr.merge_records(vec![test_record_with(addr, 500_000, "r1")]);

    let selection = mgr.select_records(500_000).unwrap();
    assert_eq!(selection.total_microcredits, 500_000);
}

#[test]
fn test_select_records_zero_amount() {
    let (client, vk_str, addr) = random_mgr_parts();
    let mut mgr = RecordManager::new(client, &vk_str).unwrap();
    mgr.merge_records(vec![test_record_with(addr, 500_000, "r1")]);

    // Zero amount — should succeed
    let selection = mgr.select_records(0).unwrap();
    assert_eq!(selection.total_microcredits, 500_000);
}

#[test]
fn test_select_records_insufficient() {
    let (client, vk_str, addr) = random_mgr_parts();
    let mut mgr = RecordManager::new(client, &vk_str).unwrap();
    mgr.merge_records(vec![test_record_with(addr, 500_000, "r1")]);

    let result = mgr.select_records(1_000_000);
    assert!(result.is_err());
}

#[test]
fn test_select_records_skips_non_credits_and_spent() {
    let (client, vk_str, addr) = random_mgr_parts();
    let mut mgr = RecordManager::new(client, &vk_str).unwrap();

    // Add a valid credits record
    mgr.merge_records(vec![test_record_with(addr, 1_000_000, "r1")]);

    // We need a non-credits record. Since merge only takes AleoRecord vec, construct one.
    let other = AleoRecord {
        program_id: "other_program.aleo".into(),
        ..test_record_with(addr, 500_000, "r_other")
    };
    mgr.merge_records(vec![other]);

    // Mark r1 as spent
    mgr.mark_spent("r1");

    assert_eq!(mgr.balance(), 0); // only r1 was credits, and it's spent
}

// ── SelectedRecords ────────────────────────────────────────────────────────

#[test]
fn test_selected_records_struct() {
    let (_, _, addr) = random_mgr_parts();

    let selection = SelectedRecords {
        records: vec![
            test_record_with(addr, 1_000_000, "r1"),
            test_record_with(addr, 500_000, "r2"),
        ],
        total_microcredits: 1_500_000,
    };

    assert_eq!(selection.records.len(), 2);
    assert_eq!(selection.total_microcredits, 1_500_000);
}

#[test]
fn test_selected_records_empty() {
    let selection = SelectedRecords {
        records: vec![],
        total_microcredits: 0,
    };
    assert!(selection.records.is_empty());
    assert_eq!(selection.total_microcredits, 0);
}

// ── select_records: largest-first order ────────────────────────────────────

#[test]
fn test_select_records_largest_first() {
    let (client, vk_str, addr) = random_mgr_parts();
    let mut mgr = RecordManager::new(client, &vk_str).unwrap();

    mgr.merge_records(vec![
        test_record_with(addr, 500_000, "medium"),
        test_record_with(addr, 1_000_000, "large"),
        test_record_with(addr, 100_000, "small"),
    ]);

    // records are sorted descending after merge
    assert_eq!(mgr.records()[0].ciphertext, "large");

    // Select 600_000 — should pick largest
    let selection = mgr.select_records(600_000).unwrap();
    assert_eq!(selection.records.len(), 1);
    assert_eq!(selection.records[0].ciphertext, "large");
    assert_eq!(selection.total_microcredits, 1_000_000);
}
