//! JS SDK `Authorization` parity.
//!
//! The JS `Authorization` class is a thin wrapper: every method forwards to
//! `snarkvm::synthesizer::Authorization`. In this crate the native
//! [`Authorization`] type is used directly, so **16 of the 17 documented
//! methods need no wrapper at all**. The only one that has no single-call
//! equivalent is `functionName`, which is [`function_name`] here.
//!
//! | JS `Authorization` | Rust equivalent | Notes |
//! |--------------------|-----------------|-------|
//! | `new(request)` | `Authorization::new(request)` | native; no transitions yet |
//! | `replicate()` | `Authorization::replicate()` | native; independent copy |
//! | `toString()` | `Display` | native; renders **JSON** |
//! | `fromString(s)` | `FromStr` | native; parses that same JSON |
//! | `toBytesLe()` | `ToBytes::to_bytes_le()` | native; versioned binary form |
//! | `fromBytesLe(b)` | `FromBytes::from_bytes_le()` | native; rejects empty sets |
//! | `equals(other)` | `PartialEq` (`==`) | native; deep, see below |
//! | `len()` | `Authorization::len()` | native; **requests**, not transitions |
//! | `isEmpty()` | `Authorization::is_empty()` | native |
//! | `isFeePrivate()` | `Authorization::is_fee_private()` | native; see caveat |
//! | `isFeePublic()` | `Authorization::is_fee_public()` | native; see caveat |
//! | `isSplit()` | `Authorization::is_split()` | native; see caveat |
//! | `insertTransition(t)` | `Authorization::insert_transition(t)` | native; rejects duplicates |
//! | `transitions()` | `Authorization::transitions()` | native; `IndexMap`, not a `Vec` |
//! | `toExecutionId()` | `Authorization::to_execution_id()` | native; needs a transition |
//! | `functionName()` | [`function_name`] | **added here** |
//!
//! snarkVM also exposes capabilities the JS page does not list, all usable
//! as-is: `is_upgrade()`, `check_valid_edition()`, `check_valid_records()`,
//! `peek_next()` / `next()` / `get(index)` / `push(request)` /
//! `to_vec_deque()`, `collect_record_names()`, `collect_program_checksums()`.
//!
//! # Semantics worth knowing before relying on them
//!
//! **The `is_*` predicates describe the call, not the fee mode.**
//! `is_fee_private()` answers "is this authorization a single call to
//! `credits.aleo/fee_private`". It returns `false` for any authorization that
//! holds more than one request, and it does not recognise the other fee
//! entry points (`pay_fee_private` / `pay_fee_public`). Read it as a
//! classifier of *what was authorized*, never as "is the fee private".
//!
//! **`Authorization::new(request)` has no transitions.** A request-only
//! authorization cannot produce an execution ID — `to_execution_id()` fails
//! with "Cannot compute the execution ID for an empty authorization" — and
//! `to_bytes_le()` writes bytes that `from_bytes_le()` then refuses, because
//! the binary reader requires at least one request *and* one transition.
//! Authorizations produced by [`ExecutionEngine::authorize`] are not in this
//! state: snarkVM 4.12 inserts the transition during authorization, so they
//! already carry one.
//!
//! **Empty authorizations only round-trip through JSON.** `from_bytes_le()`
//! rejects zero requests and zero transitions, while `FromStr` accepts
//! `{"requests":[],"transitions":[]}` — which is the only way to obtain an
//! empty [`Authorization`].
//!
//! **Equality is deep.** `==` compares the request deque *and* the transition
//! map, so a JSON or bytes round-trip compares equal while two authorizations
//! for different calls do not.
//!
//! [`ExecutionEngine::authorize`]: crate::execution::ExecutionEngine::authorize

use anyhow::{Context, Result};
use snarkvm::prelude::{Authorization, Network};

/// Return the function name of the root call — the JS `functionName()`.
///
/// Requests are stored in pre-order (parents before children), so index 0 is
/// the call the caller asked for, not one of its inner calls. Pair this with
/// [`authorization_locator`] when the program ID is needed too.
///
/// # Errors
///
/// Fails when the authorization holds no requests, which is only reachable
/// through an empty JSON payload (`{"requests":[],"transitions":[]}`).
///
/// [`authorization_locator`]: crate::execution::ExecutionEngine::authorization_locator
pub fn function_name<N: Network>(authorization: &Authorization<N>) -> Result<String> {
    let request = authorization.get(0).context("Authorization contains no requests")?;
    Ok(request.function_name().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::ExecutionEngine;
    use snarkvm::prelude::{
        Address, ComputeKey, FromBytes, FromStr, PrivateKey, ProgramID, TestRng, TestnetV0, ToBytes,
    };

    const CREDITS: &str = "credits.aleo";

    /// A cheap offline authorization: `credits.aleo/transfer_public` needs no
    /// circuit synthesis, unlike a user program.
    fn credits_authorization(
        engine: &ExecutionEngine,
        rng: &mut TestRng,
    ) -> Authorization<TestnetV0> {
        let pk = PrivateKey::new(rng).unwrap();
        let address = Address::<TestnetV0>::try_from(ComputeKey::try_from(&pk).unwrap()).unwrap();
        let program_id = ProgramID::<TestnetV0>::from_str(CREDITS).unwrap();
        engine
            .authorize(
                &pk,
                &program_id,
                "transfer_public",
                vec![address.to_string().as_str(), "1u64"],
                rng,
            )
            .unwrap()
    }

    fn empty_authorization() -> Authorization<TestnetV0> {
        Authorization::<TestnetV0>::from_str(r#"{"requests":[],"transitions":[]}"#).unwrap()
    }

    #[test]
    fn function_name_reports_the_root_call() {
        let engine = ExecutionEngine::new().unwrap();
        let mut rng = TestRng::default();
        let authorization = credits_authorization(&engine, &mut rng);

        assert_eq!(function_name(&authorization).unwrap(), "transfer_public");
        // Same answer the locator gives, from the same request.
        let (_, locator_fn) = ExecutionEngine::authorization_locator(&authorization).unwrap();
        assert_eq!(function_name(&authorization).unwrap(), locator_fn);
    }

    #[test]
    fn function_name_rejects_an_empty_authorization() {
        let error = function_name(&empty_authorization()).unwrap_err().to_string();
        assert!(error.contains("no requests"), "{error}");
    }

    /// `len()` counts requests, and snarkVM 4.12 already attaches the matching
    /// transition during authorization — which is why an execution ID is
    /// available before proving.
    #[test]
    fn authorization_carries_one_request_and_one_transition() {
        let engine = ExecutionEngine::new().unwrap();
        let mut rng = TestRng::default();
        let authorization = credits_authorization(&engine, &mut rng);

        assert_eq!(authorization.len(), 1);
        assert!(!authorization.is_empty());
        assert_eq!(authorization.transitions().len(), 1);
        assert!(authorization.to_execution_id().is_ok());
    }

    /// A request-only authorization is the one shape that breaks, and it breaks
    /// in both directions: no execution ID, and bytes that cannot be read back.
    #[test]
    fn a_request_only_authorization_has_no_execution_id_and_unreadable_bytes() {
        let engine = ExecutionEngine::new().unwrap();
        let mut rng = TestRng::default();
        let authorization = credits_authorization(&engine, &mut rng);

        let request = authorization.peek_next().unwrap();
        let request_only = Authorization::<TestnetV0>::new(request);

        assert_eq!(request_only.len(), 1);
        assert!(request_only.transitions().is_empty());

        let error = request_only.to_execution_id().unwrap_err().to_string();
        assert!(error.contains("empty authorization"), "{error}");

        // Writes 0 transitions, reads back as an error: a one-way trip.
        let bytes = request_only.to_bytes_le().unwrap();
        let error = Authorization::<TestnetV0>::from_bytes_le(bytes.as_slice())
            .unwrap_err()
            .to_string();
        assert!(error.contains("no transitions"), "{error}");
    }

    #[test]
    fn json_round_trip_is_deeply_equal() {
        let engine = ExecutionEngine::new().unwrap();
        let mut rng = TestRng::default();
        let authorization = credits_authorization(&engine, &mut rng);

        let json = authorization.to_string();
        assert!(json.contains("\"requests\""), "{json}");
        assert!(json.contains("\"transitions\""), "{json}");

        let restored = Authorization::<TestnetV0>::from_str(&json).unwrap();
        assert!(restored == authorization);
        assert_eq!(
            restored.to_execution_id().unwrap(),
            authorization.to_execution_id().unwrap()
        );
        assert_eq!(
            function_name(&restored).unwrap(),
            function_name(&authorization).unwrap()
        );
    }

    #[test]
    fn bytes_round_trip_is_deeply_equal() {
        let engine = ExecutionEngine::new().unwrap();
        let mut rng = TestRng::default();
        let authorization = credits_authorization(&engine, &mut rng);

        let bytes = authorization.to_bytes_le().unwrap();
        let restored = Authorization::<TestnetV0>::from_bytes_le(bytes.as_slice()).unwrap();

        assert!(restored == authorization);
        assert_eq!(
            restored.to_execution_id().unwrap(),
            authorization.to_execution_id().unwrap()
        );
    }

    /// An empty authorization is JSON-only: the binary reader rejects it.
    #[test]
    fn an_empty_authorization_round_trips_through_json_but_not_bytes() {
        let empty = empty_authorization();
        assert!(empty.is_empty());

        let json = empty.to_string();
        let restored = Authorization::<TestnetV0>::from_str(&json).unwrap();
        assert!(restored.is_empty());
        assert!(restored == empty);

        let bytes = empty.to_bytes_le().unwrap();
        let error = Authorization::<TestnetV0>::from_bytes_le(bytes.as_slice())
            .unwrap_err()
            .to_string();
        assert!(error.contains("no requests"), "{error}");
    }

    #[test]
    fn replicate_is_an_independent_copy() {
        let engine = ExecutionEngine::new().unwrap();
        let mut rng = TestRng::default();
        let authorization = credits_authorization(&engine, &mut rng);
        let replica = authorization.replicate();

        assert!(replica == authorization);

        // `replicate` deep-copies both the request deque and the transition map,
        // so growing the replica must leave the original untouched.
        replica.push(authorization.get(0).unwrap()).unwrap();

        assert_eq!(replica.len(), 2);
        assert_eq!(authorization.len(), 1);
        assert_eq!(function_name(&replica).unwrap(), "transfer_public");
    }

    #[test]
    fn inserting_the_same_transition_twice_is_rejected() {
        let engine = ExecutionEngine::new().unwrap();
        let mut rng = TestRng::default();
        let authorization = credits_authorization(&engine, &mut rng);

        let transition = authorization.transitions().into_values().next().unwrap();
        let error = authorization.insert_transition(transition).unwrap_err().to_string();
        assert!(error.contains("already in the authorization"), "{error}");
    }

    #[test]
    fn transitions_are_keyed_by_transition_id() {
        let engine = ExecutionEngine::new().unwrap();
        let mut rng = TestRng::default();
        let authorization = credits_authorization(&engine, &mut rng);

        let transitions = authorization.transitions();
        assert_eq!(transitions.len(), 1);
        let (id, transition) = transitions.into_iter().next().unwrap();
        assert_eq!(id, *transition.id());
    }

    /// The predicates classify the **call**, so a genuine `fee_public`
    /// authorization answers `true` to exactly one of them.
    #[test]
    fn fee_predicates_classify_the_authorized_call() {
        let engine = ExecutionEngine::new().unwrap();
        let mut rng = TestRng::default();
        let pk = PrivateKey::new(&mut rng).unwrap();
        let authorization = credits_authorization(&engine, &mut rng);

        let fee_public = engine
            .authorize_fee_public_authorization(&pk, 1_000_000, 0, &authorization, &mut rng)
            .unwrap();

        assert!(fee_public.is_fee_public());
        assert!(!fee_public.is_fee_private());
        assert!(!fee_public.is_split());
        assert!(!fee_public.is_upgrade());

        // And the execution authorization is none of them.
        assert!(!authorization.is_fee_public());
        assert!(!authorization.is_fee_private());
        assert!(!authorization.is_split());
        assert_eq!(function_name(&fee_public).unwrap(), "fee_public");
    }

    /// Every predicate requires **exactly one** request, so pushing a second
    /// one silently turns a happy classifier into a `false`. This is why they
    /// must not be read as "does this authorization contain a fee call".
    #[test]
    fn predicates_stop_matching_once_a_second_request_is_pushed() {
        let engine = ExecutionEngine::new().unwrap();
        let mut rng = TestRng::default();
        let pk = PrivateKey::new(&mut rng).unwrap();
        let authorization = credits_authorization(&engine, &mut rng);
        let fee_public = engine
            .authorize_fee_public_authorization(&pk, 1_000_000, 0, &authorization, &mut rng)
            .unwrap();
        assert!(fee_public.is_fee_public());

        fee_public.push(fee_public.get(0).unwrap()).unwrap();

        assert_eq!(fee_public.len(), 2);
        assert!(!fee_public.is_fee_public());
        assert!(!fee_public.is_fee_private());
        // The root request is unchanged, so `function_name` still answers.
        assert_eq!(function_name(&fee_public).unwrap(), "fee_public");
    }
}
