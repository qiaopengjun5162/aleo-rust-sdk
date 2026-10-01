use aleo_rust_sdk::AleoClient;
use snarkvm::prelude::{PrivateKey, TestRng, TestnetV0};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{method, path}};

#[tokio::test]
async fn test_client_get_block_height() {
    let mock_server = MockServer::start().await;
    let base_url = mock_server.uri();

    Mock::given(method("GET"))
        .and(path("/block/height/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_string("42"))
        .mount(&mock_server)
        .await;

    let client = AleoClient::new(&base_url).unwrap();
    let height = client.get_block_height().await.unwrap();
    assert_eq!(height, 42);
}

#[tokio::test]
async fn test_client_get_state_root_from_client() {
    let mock_server = MockServer::start().await;
    let base_url = mock_server.uri();

    Mock::given(method("GET"))
        .and(path("/stateRoot/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_string("\"sr1lkr8fzg8mk69qrtycxjvtrg8rvh77puaq7fm56cjkh04xhprdqzq3a355s\""))
        .mount(&mock_server)
        .await;

    let client = AleoClient::new(&base_url).unwrap();
    let root = client.get_state_root().await.unwrap();
    assert_eq!(root.to_string(), "sr1lkr8fzg8mk69qrtycxjvtrg8rvh77puaq7fm56cjkh04xhprdqzq3a355s");
}

#[tokio::test]
async fn test_client_get_balance_none() {
    let mock_server = MockServer::start().await;
    let base_url = mock_server.uri();

    // Mock POST /jsonrpc returns null → fetch_mapping_value returns None
    let json_resp = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "result": null
    });
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json_resp))
        .mount(&mock_server)
        .await;

    let mut client = AleoClient::new(&base_url).unwrap();
    // set_account using generated private key string
    let mut rng = TestRng::default();
    let pk: PrivateKey<TestnetV0> = PrivateKey::new(&mut rng).unwrap();
    let pk_str = pk.to_string();
    let _ = client.set_account_from_private_key_str(&pk_str);

    let balance = client.get_balance().await.unwrap();
    assert!(balance.is_none());
}

