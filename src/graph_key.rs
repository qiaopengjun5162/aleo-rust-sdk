//! Aleo `GraphKey` — parity with the JS SDK's wasm `GraphKey` class.
//!
//! Like [`crate::view_key`], this is a thin account-page parity: snarkVM's
//! [`GraphKey<N>`] **already implements every method** on the JS page natively. A graph key wraps a single field element
//! — the `sk_tag` — which is derived from a [`ViewKey`] and used to determine
//! record ownership without revealing the view key itself. The wasm binding
//! wraps it as `GraphKey(CiphertextNative)` purely to reuse the ciphertext
//! string format for `toString`/`fromString`; the native type is `Copy` and
//! already carries `sk_tag`, `FromStr`, `Display`, and `TryFrom<&ViewKey>`, so
//! no wrapper is needed here.
//!
//! ## JS `GraphKey` → Rust mapping
//!
//! | # | JS `GraphKey` | Rust equivalent | Where |
//! |---|---|---|---|
//! | 1 | `GraphKey.fromViewKey(vk)` | [`from_view_key`] / `GraphKey::try_from(&vk)` | snarkVM (`TryFrom`) |
//! | 2 | `GraphKey.fromString(s)` | [`from_string`] / `GraphKey::from_str(s)` | snarkVM (`FromStr`) |
//! | 3 | `graphKey.toString()` | [`to_string`] / `graph_key.to_string()` | snarkVM (`Display`) |
//! | 4 | `graphKey.skTag()` | [`sk_tag`] / `graph_key.sk_tag()` | snarkVM (`const fn`) |
//!
//! ## What `sk_tag` is for
//!
//! The graph key's only payload is `sk_tag`, a field element derived as
//! `hash_psd2(view_key, G^sk_prf)`-style tag material (the exact derivation
//! lives inside `GraphKey::try_from`). Records commit to a tag derived from the
//! owner's graph key, so a holder can test ownership — via record-commitment
//! lookups — without exposing the secret `sk_prf`. [`sk_tag`] returns that
//! field directly.
//!
//! ## Usage
//!
//! ```
//! use aleo_rust_sdk::graph_key;
//! use snarkvm::prelude::{FromStr, PrivateKey, TestnetV0, ViewKey};
//!
//! let pk = PrivateKey::<TestnetV0>::from_str(
//!     "APrivateKey1zkp4RyQ8Utj7aRcJgPQGEok8RMzWwUZzBhhgX6rhmBT8dcP",
//! )
//! .unwrap();
//! let vk = ViewKey::try_from(&pk).unwrap();
//!
//! // JS: GraphKey.fromViewKey(vk)
//! let gk = graph_key::from_view_key(&vk).unwrap();
//!
//! // JS: graphKey.toString() / GraphKey.fromString(s) — round-trips.
//! let gk2 = graph_key::from_string(&gk.to_string()).unwrap();
//! assert_eq!(gk, gk2);
//!
//! // JS: graphKey.skTag() — the ownership tag field.
//! let _tag = graph_key::sk_tag(&gk);
//! ```
//!
//! [`GraphKey<N>`]: snarkvm::prelude::GraphKey
//! [`ViewKey`]: snarkvm::prelude::ViewKey

use anyhow::Result;
use snarkvm::prelude::{Field, GraphKey, Network, ViewKey};
use std::str::FromStr;

/// Derives the graph key from a view key — JS `GraphKey.fromViewKey(vk)`.
///
/// The graph key's `sk_tag` is computed from the view key's PRF secret; this
/// never fails for a valid view key. The only error path is a malformed key.
///
/// # Arguments
/// * `view_key` - The view key to derive the graph key from.
pub fn from_view_key<N: Network>(view_key: &ViewKey<N>) -> Result<GraphKey<N>> {
    GraphKey::try_from(view_key)
}

/// Parses a graph key from its string form — JS `GraphKey.fromString(s)`.
///
/// The string is the canonical bech32m encoding of the graph key (which the
/// wasm binding renders via the ciphertext string format).
///
/// # Arguments
/// * `s` - The string representation of the graph key.
pub fn from_string<N: Network>(s: &str) -> Result<GraphKey<N>> {
    GraphKey::from_str(s)
}

/// Returns the string form of the graph key — JS `graphKey.toString()`.
///
/// # Arguments
/// * `graph_key` - The graph key.
pub fn to_string<N: Network>(graph_key: &GraphKey<N>) -> String {
    graph_key.to_string()
}

/// Returns the `sk_tag` field — JS `graphKey.skTag()`.
///
/// `sk_tag` is the single field element a graph key carries; it is the material
/// records commit to so an owner can prove/check record ownership.
///
/// # Arguments
/// * `graph_key` - The graph key.
pub fn sk_tag<N: Network>(graph_key: &GraphKey<N>) -> Field<N> {
    graph_key.sk_tag()
}

#[cfg(test)]
mod tests {
    use super::*;

    use snarkvm::prelude::{PrivateKey, TestnetV0, ViewKey, Zero};

    type CurrentNetwork = TestnetV0;

    /// Canonical key used across the account parity pages for determinism.
    const PRIVATE_KEY: &str = "APrivateKey1zkp4RyQ8Utj7aRcJgPQGEok8RMzWwUZzBhhgX6rhmBT8dcP";

    fn vk(s: &str) -> ViewKey<CurrentNetwork> {
        ViewKey::try_from(&PrivateKey::from_str(s).expect("literal private key parses"))
            .expect("view key derives from private key")
    }

    // ── from_view_key ─────────────────────────────────────────────────

    #[test]
    fn from_view_key_matches_try_from() {
        let view_key = vk(PRIVATE_KEY);

        // `fromViewKey(vk)` must equal the native `TryFrom<&ViewKey>`.
        let graph_key = from_view_key(&view_key).unwrap();
        assert_eq!(graph_key, GraphKey::try_from(&view_key).unwrap());
    }

    // ── from_string / to_string round-trip ───────────────────────────

    #[test]
    fn string_round_trip_is_stable() {
        let view_key = vk(PRIVATE_KEY);
        let graph_key = from_view_key(&view_key).unwrap();

        // `toString()` then `fromString()` reproduces the same key.
        let rendered = to_string(&graph_key);
        let parsed = from_string::<CurrentNetwork>(&rendered).unwrap();
        assert_eq!(graph_key, parsed);

        // `fromString` and the native `FromStr` agree.
        assert_eq!(GraphKey::from_str(&rendered).unwrap(), parsed);
    }

    #[test]
    fn from_string_rejects_malformed_graph_key() {
        assert!(from_string::<CurrentNetwork>("not-a-graph-key").is_err());
        // A truncated bech32m string fails the checksum/length check.
        assert!(from_string::<CurrentNetwork>("AViewKey1ccEt8A2Ryva5rx").is_err());
    }

    // ── sk_tag ───────────────────────────────────────────────────────

    #[test]
    fn sk_tag_is_non_trivial_and_deterministic() {
        let view_key = vk(PRIVATE_KEY);
        let graph_key = from_view_key(&view_key).unwrap();

        let tag = sk_tag(&graph_key);

        // `sk_tag` is derived material, not the zero field element.
        assert_ne!(tag, Field::zero());

        // The same view key always yields the same `sk_tag`.
        let graph_key2 = from_view_key(&view_key).unwrap();
        assert_eq!(sk_tag(&graph_key2), tag);
    }
}
