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

/// Cover wait_for_confirmation success path (network.rs 137-139)
#[tokio::test]
async fn test_wait_for_confirmation_success() {
    let mock_server = MockServer::start().await;
    let base_url = mock_server.uri();

    Mock::given(method("GET"))
        .and(path_regex(r"/transaction/.+"))
        .respond_with(ResponseTemplate::new(200).set_body_string("confirmed"))
        .mount(&mock_server)
        .await;

    let client = AleoHttpClient::new_with_rpc(&base_url, &format!("{}/jsonrpc", base_url)).unwrap();
    client.wait_for_confirmation("tx_abc123").await.unwrap();
}

/// Cover wait_for_confirmation timeout path (network.rs 147): 30 retries all fail → bail
/// Takes ~150s. Only run explicitly.
#[tokio::test]
#[ignore]
async fn test_wait_for_confirmation_timeout_isolated() {
    let mock_server = MockServer::start().await;
    let base_url = mock_server.uri();

    Mock::given(method("GET"))
        .and(path_regex(r"/transaction/.+"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let client = AleoHttpClient::new_with_rpc(&base_url, &format!("{}/jsonrpc", base_url)).unwrap();
    let err = client.wait_for_confirmation("tx_timeout").await.unwrap_err();
    assert!(err.to_string().contains("Timed out"));
}

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

    // Closure responder: first call 404, subsequent calls 200
    Mock::given(method("GET"))
        .and(path_regex(r"/transaction/.+"))
        .respond_with(move |_: &Request| {
            let c = count.fetch_add(1, Ordering::SeqCst);
            if c == 0 {
                ResponseTemplate::new(404)
            } else {
                ResponseTemplate::new(200).set_body_string("confirmed")
            }
        })
        .mount(&mock_server)
        .await;

    let client = AleoHttpClient::new_with_rpc(&base_url, &format!("{}/jsonrpc", base_url)).unwrap();
    client.wait_for_confirmation("tx_abc123").await.unwrap();
}
