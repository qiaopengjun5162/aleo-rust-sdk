//! Coverage for the two places where "it compiled" used to be mistaken for
//! "it works":
//!
//! 1. `ProvableQuery` — the object the prover uses to fetch Merkle state paths.
//!    None of its state-root bookkeeping had ever been executed by a test.
//! 2. `wait_for_confirmation` — the gate that decides whether a broadcast
//!    transaction is on chain. Its timeout path was `#[ignore]`d (150 s), so it
//!    never ran in CI, and its "confirmed" test was a substring search.
//!
//! Both of those were fixed, and then the confirmation *endpoint* turned out to
//! be wrong too: it polled `/transaction/{id}` for a `block_hash` field that the
//! live v2 API does not return, so every real transaction timed out while the
//! mocks stayed green. The cases below are written against the contract of
//! `/transaction/confirmed/{id}` — 200 + a `status` string once mined, 404
//! while pending.
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

/// Mount a `/transaction/confirmed/{id}` mock that always answers `body`.
async fn mount_confirmed(server: &MockServer, status: u16, body: &str) {
    Mock::given(method("GET"))
        .and(path_regex(r"/transaction/confirmed/.+"))
        .respond_with(ResponseTemplate::new(status).set_body_string(body))
        .mount(server)
        .await;
}

#[tokio::test]
async fn pending_transaction_is_not_confirmation() {
    // 404 is the normal "still in the mempool" answer from this route.
    let server = MockServer::start().await;
    mount_confirmed(&server, 404, r#"{"message":"transaction not found"}"#).await;
    let c = AleoHttpClient::new_with_rpc(&server.uri(), &server.uri()).unwrap();

    let err = c.wait_for_confirmation_with("tx1", fast_poll(2)).await.unwrap_err();
    assert!(err.to_string().contains("Timed out"), "{err}");
}

#[tokio::test]
async fn accepted_without_a_status_is_not_confirmation() {
    // A 200 alone is not enough: a proxy error page must not be read as a mined
    // transaction, and reporting success is the one failure that cannot be
    // recovered from by waiting.
    let server = MockServer::start().await;
    mount_confirmed(&server, 200, r#"{"type":"execute","id":"tx1"}"#).await;
    let c = AleoHttpClient::new_with_rpc(&server.uri(), &server.uri()).unwrap();

    let err = c.wait_for_confirmation_with("tx1", fast_poll(2)).await.unwrap_err();
    assert!(err.to_string().contains("Timed out"), "{err}");
}

#[tokio::test]
async fn null_status_is_not_confirmation() {
    let server = MockServer::start().await;
    mount_confirmed(&server, 200, r#"{"status":null}"#).await;
    let c = AleoHttpClient::new_with_rpc(&server.uri(), &server.uri()).unwrap();

    let err = c.wait_for_confirmation_with("tx1", fast_poll(2)).await.unwrap_err();
    assert!(err.to_string().contains("Timed out"), "{err}");
}

#[tokio::test]
async fn non_json_200_is_not_confirmation() {
    let server = MockServer::start().await;
    mount_confirmed(&server, 200, "gateway note: transaction confirmed").await;
    let c = AleoHttpClient::new_with_rpc(&server.uri(), &server.uri()).unwrap();

    let err = c.wait_for_confirmation_with("tx1", fast_poll(2)).await.unwrap_err();
    assert!(err.to_string().contains("Timed out"), "{err}");
}

#[tokio::test]
async fn accepted_status_is_confirmation() {
    // The live wrapper is `status/type/index/transaction/finalize`.
    let server = MockServer::start().await;
    mount_confirmed(
        &server,
        200,
        r#"{"status":"accepted","type":"execute","index":0,"transaction":{},"finalize":[]}"#,
    )
    .await;
    let c = AleoHttpClient::new_with_rpc(&server.uri(), &server.uri()).unwrap();

    c.wait_for_confirmation_with("tx1", fast_poll(3))
        .await
        .expect("an accepted transaction is on chain");
}

#[tokio::test]
async fn rejected_status_is_an_error_not_a_success() {
    // On chain, but the transfer did not happen. Reporting Ok here would send
    // the caller on to spend records that were never created.
    let server = MockServer::start().await;
    mount_confirmed(&server, 200, r#"{"status":"rejected","type":"execute"}"#).await;
    let c = AleoHttpClient::new_with_rpc(&server.uri(), &server.uri()).unwrap();

    let err = c.wait_for_confirmation_with("tx1", fast_poll(3)).await.unwrap_err().to_string();
    assert!(err.contains("rejected"), "{err}");
    assert!(
        !err.contains("Timed out"),
        "should fail fast, not poll: {err}"
    );
}

#[tokio::test]
async fn unrecognised_status_keeps_polling_instead_of_confirming() {
    // `ConfirmedTransaction` serialises only `accepted`/`rejected` and its
    // deserialiser rejects every other value, so a healthy node cannot emit a
    // third status. If one ever does, "not rejected" must not be read as
    // success: a false positive cannot be undone by waiting.
    let server = MockServer::start().await;
    mount_confirmed(&server, 200, r#"{"status":"aborted","type":"execute"}"#).await;
    let c = AleoHttpClient::new_with_rpc(&server.uri(), &server.uri()).unwrap();

    let err = c.wait_for_confirmation_with("tx1", fast_poll(2)).await.unwrap_err().to_string();
    assert!(err.contains("Timed out"), "{err}");
}

#[tokio::test]
async fn one_attempt_means_one_request_and_no_trailing_sleep() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"/transaction/confirmed/.+"))
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
    mount_confirmed(&server, 200, r#"{"status":"accepted"}"#).await;
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
    mount_confirmed(&server, 200, "{}").await;
    let c = AleoHttpClient::new_with_rpc(&server.uri(), &server.uri()).unwrap();

    let err = c
        .wait_for_confirmation_with("at1distinctive", fast_poll(1))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("at1distinctive"), "tx id not in error: {err}");
}

#[tokio::test]
async fn unreachable_endpoint_error_names_the_transport_cause() {
    // When every poll fails at `send()` (nothing listening on DEAD_BASE), the
    // terminal error must say the endpoint could not be reached. It used to
    // report only "Timed out", which reads as "the tx is not mined yet" and
    // hides a dead node from the caller.
    // Inject a no-proxy client so the loopback request cannot be captured by a
    // proxy in the environment and turned into a 2xx error page.
    let inner = reqwest::Client::builder().no_proxy().build().unwrap();
    let c = AleoHttpClient::with_http(DEAD_BASE, DEAD_BASE, inner);

    let err = c
        .wait_for_confirmation_with("tx_unreachable", fast_poll(2))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("Timed out"), "still a timeout at heart: {err}");
    assert!(
        err.contains("could not be reached"),
        "transport cause missing from error: {err}"
    );
    assert!(
        !err.contains("body could not be read"),
        "no response ever arrived, so no body was read: {err}"
    );
}

#[tokio::test]
async fn unreadable_body_error_still_names_the_body_cause() {
    // The other branch must keep its existing wording: a 2xx whose body is
    // cut off is a different fault from an unreachable node, and callers may
    // dispatch on the two messages. wiremock always sends a complete body, so
    // a raw socket announces a longer body than it writes and closes early —
    // `reqwest::text()` then fails while reading the response.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        // Read the request so the peer's write completes, then reply with a
        // truncated body: Content-Length promises 32 bytes, only 2 arrive.
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await;
        let response =
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 32\r\n\r\n{}";
        socket.write_all(response).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let inner = reqwest::Client::builder().no_proxy().build().unwrap();
    let c = AleoHttpClient::with_http(&format!("http://{addr}"), &format!("http://{addr}"), inner);

    // One attempt only: a second request would hit a closed listener and set
    // a transport failure, overwriting the body failure under test.
    let err = c
        .wait_for_confirmation_with("tx_bad_body", fast_poll(1))
        .await
        .unwrap_err()
        .to_string();
    server.await.unwrap();
    assert!(
        err.contains("body could not be read"),
        "body cause missing from error: {err}"
    );
    assert!(
        !err.contains("could not be reached"),
        "the node was reached; this is not a transport failure: {err}"
    );
}
