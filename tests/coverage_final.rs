use aleo_rust_sdk::{AleoHttpClient, FixedStateRootQuery};
use snarkvm::console::types::Field;
use snarkvm::ledger::query::QueryTrait;
use snarkvm::prelude::{FromStr as _, Network, TestnetV0};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path_regex},
};

/// Cover async FixedStateRootQuery methods (network.rs 234-245)
#[tokio::test]
async fn test_fixed_state_root_query_async_methods() {
    let sr = <TestnetV0 as Network>::StateRoot::from_str(
        "sr1lkr8fzg8mk69qrtycxjvtrg8rvh77puaq7fm56cjkh04xhprdqzq3a355s",
    )
    .unwrap();
    let q: FixedStateRootQuery<TestnetV0> = FixedStateRootQuery {
        state_root: sr,
        block_height: 42,
    };

    let async_root = q.current_state_root_async().await.unwrap();
    assert_eq!(async_root, sr);

    let async_height = q.current_block_height_async().await.unwrap();
    assert_eq!(async_height, 42);

    let f = Field::from_str("1field").unwrap();
    let async_path = q.get_state_path_for_commitment_async(&f).await;
    assert!(async_path.is_err());

    let async_paths = q.get_state_paths_for_commitments_async(&[f]).await.unwrap();
    assert!(async_paths.is_empty());
}

/// Cover wait_for_confirmation success path: V2 API returns txn with block_hash
#[tokio::test]
async fn test_wait_for_confirmation_success() {
    let mock_server = MockServer::start().await;
    let base_url = mock_server.uri();

    // V2 API returns JSON with block_hash when confirmed
    Mock::given(method("GET"))
        .and(path_regex(r"/transaction/.+"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "execute",
            "id": "at1mock",
            "execution": {},
            "fee": {},
            "block_hash": "ab1blockhash"
        })))
        .mount(&mock_server)
        .await;

    let client = AleoHttpClient::new_with_rpc(&base_url, &format!("{}/jsonrpc", base_url)).unwrap();
    client.wait_for_confirmation("tx_abc123").await.unwrap();
}

// The timeout path used to live here as `#[ignore]`d — 30 attempts x 5 s, i.e.
// 150 seconds that no CI run ever paid and no developer ever waited for, so the
// branch was exercised exactly never. `ConfirmationPoll` makes the schedule a
// parameter, and `tests/query_and_confirmation_test.rs` now covers the timeout
// path in milliseconds. Deleted rather than un-ignored: keeping it would only
// re-add the 150-second stall to every full test run.

/// Cover wait_for_confirmation retry path (network.rs 141-144): first call 404, second call 200
#[tokio::test]
async fn test_wait_for_confirmation_retry() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use wiremock::Request;

    let mock_server = MockServer::start().await;
    let base_url = mock_server.uri();

    let call_count = Arc::new(AtomicU32::new(0));
    let count = call_count.clone();

    // Closure responder: first call 404, subsequent calls 200 with block_hash
    Mock::given(method("GET"))
        .and(path_regex(r"/transaction/.+"))
        .respond_with(move |_: &Request| {
            let c = count.fetch_add(1, Ordering::SeqCst);
            if c == 0 {
                ResponseTemplate::new(404)
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "type": "execute",
                    "id": "at1retry",
                    "execution": {},
                    "fee": {},
                    "block_hash": "ab1retryhash"
                }))
            }
        })
        .mount(&mock_server)
        .await;

    let client = AleoHttpClient::new_with_rpc(&base_url, &format!("{}/jsonrpc", base_url)).unwrap();
    client.wait_for_confirmation("tx_abc123").await.unwrap();
}
