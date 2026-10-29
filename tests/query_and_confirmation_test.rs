//! Coverage for the two places where "it compiled" used to be mistaken for
//! "it works":
//!
//! 1. `ProvableQuery` — the object the prover uses to fetch Merkle state paths.
//!    None of its state-root bookkeeping had ever been executed by a test.
//! 2. `wait_for_confirmation` — the gate that decides whether a broadcast
//!    transaction is on chain. Its timeout path was `#[ignore]`d (150 s), so it
//!    never ran in CI, and its "confirmed" test was a substring search.
//!
//! Everything here is offline: mock servers for HTTP, unreachable loopback
//! ports for the failure paths that need a real transport.

use aleo_rust_sdk::{AleoHttpClient, ConfirmationPoll, FixedStateRootQuery, ProvableQuery};
use snarkvm::console::types::Field;
use snarkvm::ledger::query::QueryTrait;
use snarkvm::prelude::{FromStr as _, Network, TestnetV0};
use std::time::{Duration, Instant};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ROOT: &str = "sr1lkr8fzg8mk69qrtycxjvtrg8rvh77puaq7fm56cjkh04xhprdqzq3a355s";
/// Nothing listens here, so connections fail immediately instead of timing out.
const DEAD_BASE: &str = "http://127.0.0.1:9";

fn root() -> <TestnetV0 as Network>::StateRoot {
    <TestnetV0 as Network>::StateRoot::from_str(ROOT).unwrap()
}

fn field() -> Field<TestnetV0> {
    Field::from_str("1field").unwrap()
}

/// Short schedule so the timeout path finishes in milliseconds.
fn fast_poll(attempts: u32) -> ConfirmationPoll {
    ConfirmationPoll {
        attempts,
        interval: Duration::from_millis(1),
    }
}

// ── ProvableQuery: state-root bookkeeping ─────────────────────────────

#[test]
fn provable_query_reports_configured_root_before_any_fetch() {
    let q = ProvableQuery::new(root(), 42, "https://api.example.invalid");
    // With no cached path, the pinned root is what the prover must verify against.
    assert_eq!(q.current_state_root().unwrap(), root());
    assert_eq!(q.current_block_height().unwrap(), 42);
}

#[tokio::test]
async fn provable_query_async_root_matches_sync_root() {
    let q = ProvableQuery::new(root(), 7, "https://api.example.invalid");
    assert_eq!(
        q.current_state_root_async().await.unwrap(),
        q.current_state_root().unwrap()
    );
    assert_eq!(q.current_block_height_async().await.unwrap(), 7);
}

#[test]
fn provable_query_clone_does_not_inherit_a_root_cache() {
    // The clone is documented to start with a fresh cache; if it ever shared one,
    // a clone made mid-proof would report another transition's root.
    let q = ProvableQuery::new(root(), 42, "https://api.example.invalid");
    let cloned = q.clone();
    assert_eq!(cloned.current_state_root().unwrap(), root());
    assert_eq!(cloned.block_height, 42);
    assert_eq!(cloned.api_base_url, q.api_base_url);
}

#[test]
fn provable_query_normalises_trailing_slash_in_base_url() {
    let q = ProvableQuery::new(root(), 1, "https://api.example.invalid/");
    assert_eq!(q.api_base_url, "https://api.example.invalid");
}

#[test]
fn empty_commitments_do_not_touch_the_network() {
    // Base URL is unreachable: if the empty-slice short circuit were ever removed,
    // this would fail with a connection error instead of returning an empty vec.
    let q = ProvableQuery::new(root(), 1, DEAD_BASE);
    assert!(q.get_state_paths_for_commitments(&[]).unwrap().is_empty());
}

#[tokio::test]
async fn empty_commitments_do_not_touch_the_network_async() {
    let q = ProvableQuery::new(root(), 1, DEAD_BASE);
    assert!(q.get_state_paths_for_commitments_async(&[]).await.unwrap().is_empty());
}

#[test]
fn state_path_error_names_the_endpoint_and_base() {
    let q = ProvableQuery::new(root(), 1, DEAD_BASE);
    let err = q.get_state_path_for_commitment(&field()).unwrap_err().to_string();
    // The label and URL are what make a prover failure diagnosable at all.
    assert!(err.contains("statePath"), "missing endpoint label: {err}");
    assert!(err.contains(DEAD_BASE), "missing base URL: {err}");
    assert!(err.contains("/statePath/"), "missing route: {err}");
    // The base URL ends with no slash, so joining must not produce `//statePath`.
    assert!(!err.contains("//statePath"), "double slash in URL: {err}");
}

#[tokio::test]
async fn state_path_error_is_propagated_through_async_trait() {
    let q = ProvableQuery::new(root(), 1, DEAD_BASE);
    let err = q.get_state_path_for_commitment_async(&field()).await.unwrap_err().to_string();
    assert!(err.contains("statePath"), "{err}");
}

#[tokio::test]
async fn batched_state_path_error_names_the_endpoint() {
    let q = ProvableQuery::new(root(), 1, DEAD_BASE);
    let err = q.get_state_paths_for_commitments(&[field()]).unwrap_err().to_string();
    assert!(err.contains("statePaths"), "{err}");
}

// ── FixedStateRootQuery: the error must point at the right type ───────

#[test]
fn fixed_query_refuses_paths_and_names_the_alternative() {
    let q: FixedStateRootQuery<TestnetV0> = FixedStateRootQuery {
        state_root: root(),
        block_height: 1,
    };
    let err = q.get_state_path_for_commitment(&field()).unwrap_err().to_string();
    // A caller that hits this is using the wrong query type; saying so is the
    // whole value of the message.
    assert!(err.contains("ProvableQuery"), "{err}");
}

#[tokio::test]
async fn fixed_query_refuses_paths_async_and_names_the_alternative() {
    let q: FixedStateRootQuery<TestnetV0> = FixedStateRootQuery {
        state_root: root(),
        block_height: 1,
    };
    let err = q.get_state_path_for_commitment_async(&field()).await.unwrap_err().to_string();
    assert!(err.contains("ProvableQuery"), "{err}");
}

// ── wait_for_confirmation: what counts as "on chain" ──────────────────

/// Mount a `transaction/*` mock that always answers `body`.
async fn mount_tx(server: &MockServer, status: u16, body: &str) {
    Mock::given(method("GET"))
        .and(path_regex(r"/transaction/.+"))
        .respond_with(ResponseTemplate::new(status).set_body_string(body))
        .mount(server)
        .await;
}

#[tokio::test]
async fn null_block_hash_is_not_confirmation() {
    // The old substring check (`body.contains("\"block_hash\"")`) matched this
    // body and reported success for a transaction that is still in the mempool.
    let server = MockServer::start().await;
    mount_tx(&server, 200, r#"{"type":"execute","block_hash":null}"#).await;
    let c = AleoHttpClient::new_with_rpc(&server.uri(), &server.uri()).unwrap();

    let err = c.wait_for_confirmation_with("tx1", fast_poll(2)).await.unwrap_err();
    assert!(err.to_string().contains("Timed out"), "{err}");
}

#[tokio::test]
async fn empty_block_hash_is_not_confirmation() {
    let server = MockServer::start().await;
    mount_tx(&server, 200, r#"{"type":"execute","block_hash":""}"#).await;
    let c = AleoHttpClient::new_with_rpc(&server.uri(), &server.uri()).unwrap();

    let err = c.wait_for_confirmation_with("tx1", fast_poll(2)).await.unwrap_err();
    assert!(err.to_string().contains("Timed out"), "{err}");
}

#[tokio::test]
async fn mentioning_block_hash_in_non_json_is_not_confirmation() {
    // A proxy error page quoting the field name used to count as mined.
    let server = MockServer::start().await;
    mount_tx(&server, 200, "gateway note: \"block_hash\" unavailable").await;
    let c = AleoHttpClient::new_with_rpc(&server.uri(), &server.uri()).unwrap();

    let err = c.wait_for_confirmation_with("tx1", fast_poll(2)).await.unwrap_err();
    assert!(err.to_string().contains("Timed out"), "{err}");
}

#[tokio::test]
async fn non_string_block_hash_is_not_confirmation() {
    let server = MockServer::start().await;
    mount_tx(&server, 200, r#"{"block_hash":123}"#).await;
    let c = AleoHttpClient::new_with_rpc(&server.uri(), &server.uri()).unwrap();

    let err = c.wait_for_confirmation_with("tx1", fast_poll(1)).await.unwrap_err();
    assert!(err.to_string().contains("Timed out"), "{err}");
}

#[tokio::test]
async fn string_block_hash_is_confirmation() {
    let server = MockServer::start().await;
    mount_tx(&server, 200, r#"{"type":"execute","block_hash":"ab1abc"}"#).await;
    let c = AleoHttpClient::new_with_rpc(&server.uri(), &server.uri()).unwrap();

    c.wait_for_confirmation_with("tx1", fast_poll(3))
        .await
        .expect("a populated block_hash means mined");
}

#[tokio::test]
async fn one_attempt_means_one_request_and_no_trailing_sleep() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"/transaction/.+"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;
    let c = AleoHttpClient::new_with_rpc(&server.uri(), &server.uri()).unwrap();

    let err = c.wait_for_confirmation_with("tx1", fast_poll(1)).await.unwrap_err();
    assert!(err.to_string().contains("Timed out"), "{err}");
    // `expect(1)` is only enforced on drop/verify; asserting it here keeps the
    // failure attributed to this test.
    server.verify().await;
}

#[tokio::test]
async fn first_check_happens_before_any_sleep() {
    // Production used to sleep 5 s *before* the first request, so an already-mined
    // transaction still blocked for 5 s. The interval must separate attempts, not
    // precede them.
    let server = MockServer::start().await;
    mount_tx(&server, 200, r#"{"block_hash":"ab1abc"}"#).await;
    let c = AleoHttpClient::new_with_rpc(&server.uri(), &server.uri()).unwrap();

    let poll = ConfirmationPoll {
        attempts: 3,
        interval: Duration::from_secs(30),
    };
    let started = Instant::now();
    c.wait_for_confirmation_with("tx1", poll).await.unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "an immediate confirmation waited {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn timeout_error_names_the_transaction() {
    let server = MockServer::start().await;
    mount_tx(&server, 200, "{}").await;
    let c = AleoHttpClient::new_with_rpc(&server.uri(), &server.uri()).unwrap();

    let err = c
        .wait_for_confirmation_with("at1distinctive", fast_poll(1))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("at1distinctive"), "tx id not in error: {err}");
}
