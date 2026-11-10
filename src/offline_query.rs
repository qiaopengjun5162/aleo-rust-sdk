//! Aleo `OfflineQuery` — parity with the JS SDK's wasm `OfflineQuery` class.
//!
//! Unlike the type-shell modules ([`crate::field`], [`crate::group`]), snarkVM
//! has **no** native offline-query type: it only has the [`QueryTrait`] that a
//! query must satisfy. The wasm class exists to bundle a state root, a block
//! height and a commitment → state-path map so that inclusion proofs can be
//! built **without a network connection**. This module adds the same container,
//! [`OfflineQuery<N>`], and implements [`QueryTrait`] for it — which is the
//! whole point of the type: hand it to a deploy/execute call in place of a
//! REST query.
//!
//! ## JS `OfflineQuery` → Rust mapping
//!
//! | # | JS `OfflineQuery` | Rust equivalent | Where |
//! |---|-------------------|-----------------|-------|
//! | 1 | `new OfflineQuery(block_height, state_root)` | [`OfflineQuery::new`] — strict `StateRoot::from_str` | **this module** |
//! | 2 | `q.addBlockHeight(h)` | [`OfflineQuery::set_block_height`] — 🔴 an **overwrite**, see below | **this module** |
//! | 3 | `q.addStatePath(commitment, state_path)` | [`OfflineQuery::add_state_path`] — strict parsers | **this module** |
//! | 4 | `q.toString()` | [`OfflineQuery::to_json`] — serde JSON, see below | **this module** |
//! | 5 | `OfflineQuery.fromString(s)` | [`OfflineQuery::from_json`] | **this module** |
//! | — | (implicit) | `impl QueryTrait<N>` — the reason the type exists | snarkVM (`snarkvm::ledger::query`) |
//!
//! ## The semantics, pinned
//!
//! 1. 🔴 **`addBlockHeight` does not add.** Despite the name it assigns
//!    `self.block_height = block_height` — an overwrite of the single height
//!    field. Rust names it [`set_block_height`](OfflineQuery::set_block_height)
//!    so the lie cannot leak into the API.
//! 2. 🔴 **`toString`/`fromString` are serde JSON** — unlike every other wasm
//!    type, whose `toString` is the canonical literal form (`"1field"`,
//!    `"0group"`, …). The JSON shape is field-order-sensitive and pinned by the
//!    upstream test vector:
//!    `{"block_height":0,"state_paths":{},"state_root":"sr1…"}`. Map keys are
//!    commitment strings (`"42field":"path1…"`), because `Field` serializes
//!    via `collect_str`. Rust therefore gets honest
//!    [`to_json`](OfflineQuery::to_json) /
//!    [`from_json`](OfflineQuery::from_json) names instead of `Display`/`FromStr`.
//! 3. **`new` and `addStatePath` are strict parsers.** A malformed state root,
//!    commitment or state path is an error, never a silent insertion.
//! 4. **`QueryTrait` error strings are pinned verbatim** — including the long
//!    batch message — because callers match on them:
//!    `"State path not found for commitment"` and
//!    `"Not all commitments found in stored state paths, please ensure the
//!    offline query object contains all commitments and statepaths required"`.
//!    The batch lookup drops missing commitments (`filter_map`) and *then*
//!    errors on the length mismatch — all-or-nothing, preserving input order.
//! 5. [`state_paths`](OfflineQuery::add_state_path) is an [`IndexMap`]: JSON
//!    output preserves insertion order, matching upstream byte-for-byte.
//!
//! [`QueryTrait`]: snarkvm::ledger::query::QueryTrait

use anyhow::{Result, anyhow, ensure};
use async_trait::async_trait;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use snarkvm::ledger::query::QueryTrait;
use snarkvm::prelude::{Field, Network, StatePath};

use std::str::FromStr;

/// An offline query object used to insert the global state root and state
/// paths needed to create a valid inclusion proof offline.
///
/// This is the JS `OfflineQuery` class. Field order matters: it is the
/// serialization order of [`OfflineQuery::to_json`], matching upstream.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound(
    serialize = "N::StateRoot: Serialize",
    deserialize = "N::StateRoot: Deserialize<'de>"
))]
pub struct OfflineQuery<N: Network> {
    block_height: u32,
    state_paths: IndexMap<Field<N>, StatePath<N>>,
    state_root: N::StateRoot,
}

impl<N: Network> OfflineQuery<N> {
    /// Creates a new offline query object from a block height and the state
    /// root string — the JS `new OfflineQuery(block_height, state_root)`.
    ///
    /// `state_root` is parsed strictly (an `"sr1…"` bech32 identifier).
    ///
    /// # Examples
    ///
    /// ```
    /// use aleo_rust_sdk::offline_query::OfflineQuery;
    /// use snarkvm::ledger::query::QueryTrait;
    /// use snarkvm::prelude::TestnetV0;
    ///
    /// let query = OfflineQuery::<TestnetV0>::new(
    ///     0,
    ///     "sr1wjueje6hy86yw9j4lhl7jwvhjxwunw34paj4k3cn2wm5h5r2syfqd83yw4",
    /// )?;
    /// assert_eq!(query.current_block_height()?, 0);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn new(block_height: u32, state_root: &str) -> Result<Self> {
        // `N::StateRoot::from_str`'s error type is an unbounded associated
        // type, so it cannot flow into `anyhow` with `?`; echo the input.
        let state_root = N::StateRoot::from_str(state_root)
            .map_err(|_| anyhow!("failed to parse state root: {state_root}"))?;
        Ok(Self {
            block_height,
            state_paths: IndexMap::new(),
            state_root,
        })
    }

    /// Sets the block height — the JS `q.addBlockHeight(h)`.
    ///
    /// 🔴 The JS name says "add", but the implementation **overwrites** the
    /// single `block_height` field; nothing accumulates. The Rust name is
    /// honest about it.
    pub fn set_block_height(&mut self, block_height: u32) {
        self.block_height = block_height;
    }

    /// Inserts the state path for a record commitment — the JS
    /// `q.addStatePath(commitment, state_path)`.
    ///
    /// Both arguments are parsed strictly: `commitment` is a field string
    /// (`"42field"`), `state_path` a `"path1…"` identifier. Re-inserting an
    /// existing commitment overwrites its path (`IndexMap::insert`).
    pub fn add_state_path(&mut self, commitment: &str, state_path: &str) -> Result<()> {
        let commitment = Field::<N>::from_str(commitment)?;
        let state_path = StatePath::<N>::from_str(state_path)?;
        self.state_paths.insert(commitment, state_path);
        Ok(())
    }

    /// Returns the JSON representation — the JS `q.toString()`.
    ///
    /// 🔴 In JS this is a **serde JSON document**, not the literal form every
    /// other wasm `toString` produces. The output is deterministic: struct
    /// fields serialize in declaration order and the map preserves insertion
    /// order.
    ///
    /// # Examples
    ///
    /// ```
    /// use aleo_rust_sdk::offline_query::OfflineQuery;
    /// use snarkvm::prelude::TestnetV0;
    ///
    /// let query = OfflineQuery::<TestnetV0>::new(
    ///     0,
    ///     "sr1wjueje6hy86yw9j4lhl7jwvhjxwunw34paj4k3cn2wm5h5r2syfqd83yw4",
    /// )?;
    /// // The exact upstream test vector.
    /// assert_eq!(
    ///     query.to_json(),
    ///     r#"{"block_height":0,"state_paths":{},"state_root":"sr1wjueje6hy86yw9j4lhl7jwvhjxwunw34paj4k3cn2wm5h5r2syfqd83yw4"}"#,
    /// );
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self).expect("OfflineQuery serialization cannot fail")
    }

    /// Parses the JSON representation — the JS `OfflineQuery.fromString(s)`.
    ///
    /// The inverse of [`OfflineQuery::to_json`]; malformed JSON is an error.
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    /// Returns the block height carried by this query.
    pub fn block_height(&self) -> u32 {
        self.block_height
    }

    /// Returns the state root carried by this query.
    pub fn state_root(&self) -> N::StateRoot {
        self.state_root
    }
}

#[async_trait(?Send)]
impl<N: Network> QueryTrait<N> for OfflineQuery<N> {
    fn current_state_root(&self) -> Result<N::StateRoot> {
        Ok(self.state_root)
    }

    async fn current_state_root_async(&self) -> Result<N::StateRoot> {
        Ok(self.state_root)
    }

    fn get_state_path_for_commitment(&self, commitment: &Field<N>) -> Result<StatePath<N>> {
        self.state_paths
            .get(commitment)
            .cloned()
            .ok_or(anyhow!("State path not found for commitment"))
    }

    async fn get_state_path_for_commitment_async(
        &self,
        commitment: &Field<N>,
    ) -> Result<StatePath<N>> {
        self.get_state_path_for_commitment(commitment)
    }

    fn get_state_paths_for_commitments(
        &self,
        commitments: &[Field<N>],
    ) -> Result<Vec<StatePath<N>>> {
        let state_paths = commitments
            .iter()
            .filter_map(|commitment| self.state_paths.get(commitment).cloned())
            .collect::<Vec<StatePath<N>>>();
        ensure!(
            state_paths.len() == commitments.len(),
            "Not all commitments found in stored state paths, please ensure the offline query object contains all commitments and statepaths required"
        );
        Ok(state_paths)
    }

    async fn get_state_paths_for_commitments_async(
        &self,
        commitments: &[Field<N>],
    ) -> Result<Vec<StatePath<N>>> {
        self.get_state_paths_for_commitments(commitments)
    }

    fn current_block_height(&self) -> Result<u32> {
        Ok(self.block_height)
    }

    async fn current_block_height_async(&self) -> Result<u32> {
        Ok(self.block_height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use snarkvm::prelude::{
        Network, TestnetV0, TransactionLeaf, TransactionPath, TransitionLeaf, TransitionPath, U64,
        Zero,
    };

    type CurrentNetwork = TestnetV0;

    /// The exact upstream test vector (`wasm/src/programs/offline_query.rs`).
    const OFFLINE_QUERY: &str = r#"{"block_height":0,"state_paths":{},"state_root":"sr1wjueje6hy86yw9j4lhl7jwvhjxwunw34paj4k3cn2wm5h5r2syfqd83yw4"}"#;
    const STATE_ROOT: &str = "sr1wjueje6hy86yw9j4lhl7jwvhjxwunw34paj4k3cn2wm5h5r2syfqd83yw4";

    fn query() -> OfflineQuery<CurrentNetwork> {
        OfflineQuery::new(0, STATE_ROOT).expect("STATE_ROOT parses")
    }

    fn commitment(value: u128) -> Field<CurrentNetwork> {
        Field::<CurrentNetwork>::from_str(&format!("{value}field")).expect("literal field parses")
    }

    /// Builds a well-formed [`StatePath`] on the fly.
    ///
    /// The upstream test's `"path1…"` literal is commented out in the SDK
    /// source and no longer parses on snarkVM 4.12 — the byte layout moved, so
    /// there is no live cross-language vector to pin for paths. Construct one
    /// instead: `new_local` builds the surrounding Merkle trees itself and
    /// accepts the zeroed transaction/transition witnesses as opaque data.
    fn state_path() -> StatePath<CurrentNetwork> {
        type TxId = <CurrentNetwork as Network>::TransactionID;
        let transaction_path =
            TransactionPath::try_from((U64::new(0), vec![Field::<CurrentNetwork>::zero(); 5]))
                .expect("depth matches");
        let transition_path =
            TransitionPath::try_from((U64::new(0), vec![Field::<CurrentNetwork>::zero(); 5]))
                .expect("depth matches");
        StatePath::new_local(
            <CurrentNetwork as Network>::StateRoot::from_str(STATE_ROOT)
                .expect("STATE_ROOT parses"),
            TxId::from(Field::zero()),
            transaction_path,
            TransactionLeaf::new_execution(0, Field::zero()),
            Field::zero(),
            Field::zero(),
            transition_path,
            TransitionLeaf::new_record_with_dynamic_id(0, Field::zero()),
        )
        .expect("new_local accepts zeroed witnesses")
    }

    /// Polls a future to completion without pulling in a runtime. The query's
    /// async methods resolve immediately, so a no-op waker suffices.
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        use std::task::{Context, Poll, Waker};

        let mut context = Context::from_waker(Waker::noop());
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn block_on_waits_through_pending() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::Poll;

        // A future that pends exactly once, to cover the yield arm.
        let polled = AtomicBool::new(false);
        let future = std::future::poll_fn(|cx| {
            if polled.swap(true, Ordering::SeqCst) {
                Poll::Ready(42)
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        });
        assert_eq!(block_on(future), 42);
    }

    // ── serialization: the upstream literal vector ─────────────────────

    #[test]
    fn to_json_matches_upstream_literal() {
        // The exact string the wasm test asserts — byte-for-byte.
        assert_eq!(query().to_json(), OFFLINE_QUERY);
    }

    #[test]
    fn from_json_round_trips_upstream_literal() {
        let parsed = OfflineQuery::<CurrentNetwork>::from_json(OFFLINE_QUERY)
            .expect("upstream vector parses");
        assert_eq!(parsed, query());
        assert_eq!(parsed.to_json(), OFFLINE_QUERY);
    }

    #[test]
    fn from_json_rejects_garbage() {
        assert!(OfflineQuery::<CurrentNetwork>::from_json("not json").is_err());
        assert!(OfflineQuery::<CurrentNetwork>::from_json(r#"{"block_height":0}"#).is_err());
    }

    #[test]
    fn json_map_keys_are_commitment_strings() {
        // `Field` serializes via collect_str, so the map key is "42field".
        let sp = state_path();
        let mut q = query();
        q.add_state_path("42field", &sp.to_string()).expect("constructed path parses");
        let json = q.to_json();
        assert!(
            json.contains(r#""42field":"path1"#),
            "map key must be the commitment string: {json}"
        );

        // …and the whole thing round-trips, path included.
        let parsed = OfflineQuery::<CurrentNetwork>::from_json(&json).expect("round-trips");
        assert_eq!(parsed, q);
        assert_eq!(
            parsed.get_state_path_for_commitment(&commitment(42)).expect("inserted"),
            sp
        );
    }

    // ── addBlockHeight is a setter ─────────────────────────────────────

    #[test]
    fn set_block_height_overwrites_not_accumulates() {
        // JS calls it "add", but it assigns. 5 + 9 is not 14.
        let mut q = OfflineQuery::<CurrentNetwork>::new(5, STATE_ROOT).expect("STATE_ROOT parses");
        q.set_block_height(9);
        assert_eq!(q.block_height(), 9);
        assert_eq!(q.current_block_height().expect("infallible"), 9);

        // Another "add" replaces, again.
        q.set_block_height(2);
        assert_eq!(q.block_height(), 2);
    }

    // ── strict parsing ─────────────────────────────────────────────────

    #[test]
    fn new_rejects_bad_state_root() {
        assert!(OfflineQuery::<CurrentNetwork>::new(0, "not a state root").is_err());
    }

    #[test]
    fn add_state_path_is_strict_on_both_arguments() {
        let mut q = query();
        let sp = state_path().to_string();
        assert!(q.add_state_path("not a field", &sp).is_err());
        assert!(q.add_state_path("42field", "not a state path").is_err());
        q.add_state_path("42field", &sp).expect("constructed path parses");
    }

    // ── QueryTrait: error strings pinned verbatim ──────────────────────

    #[test]
    fn get_state_path_missing_error_is_pinned() {
        let q = query();
        let err = q.get_state_path_for_commitment(&commitment(42)).expect_err("nothing inserted");
        assert_eq!(err.to_string(), "State path not found for commitment");
    }

    #[test]
    fn get_state_paths_is_all_or_nothing_in_input_order() {
        let mut q = query();
        let sp = state_path();
        q.add_state_path("42field", &sp.to_string()).expect("constructed path parses");
        let (c42, c7) = (commitment(42), commitment(7));
        q.add_state_path(&c7.to_string(), &sp.to_string())
            .expect("constructed path parses");

        // All present → Ok, in the order the commitments were given.
        let paths = q.get_state_paths_for_commitments(&[c42, c7]).expect("both present");
        assert_eq!(paths, vec![sp.clone(), sp.clone()]);

        // One missing → the pinned batch error, even though the other is present.
        let err = q
            .get_state_paths_for_commitments(&[c42, commitment(1)])
            .expect_err("commitment 1 was never inserted");
        assert_eq!(
            err.to_string(),
            "Not all commitments found in stored state paths, please ensure the offline query object contains all commitments and statepaths required"
        );
    }

    // ── async trait variants delegate ──────────────────────────────────

    #[test]
    fn async_variants_match_sync() {
        let mut q = query();
        let sp = state_path();
        q.add_state_path("42field", &sp.to_string()).expect("constructed path parses");
        let c42 = commitment(42);
        let path = q.get_state_path_for_commitment(&c42).expect("inserted above");

        // The sync methods are the reference implementation.
        assert_eq!(q.current_state_root().expect("infallible"), q.state_root());
        assert_eq!(
            block_on(q.current_state_root_async()).expect("infallible"),
            q.state_root()
        );
        assert_eq!(
            block_on(q.current_block_height_async()).expect("infallible"),
            q.block_height()
        );
        assert_eq!(
            block_on(q.get_state_path_for_commitment_async(&c42)).expect("inserted"),
            path
        );
        assert_eq!(
            block_on(q.get_state_paths_for_commitments_async(&[c42])).expect("inserted"),
            vec![path]
        );
    }
}
