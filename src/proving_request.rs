//! JS SDK `ProvingRequest` parity.
//!
//! Unlike the previous pages, this one **adds a type**. `ProvingRequestNative`
//! is defined by the wasm crate itself (`wasm/src/types/native/request/mod.rs`),
//! not by snarkVM: it is an untagged, two-variant bundle of an execution
//! authorization (or a signed request) plus the optional fee counterpart and a
//! `broadcast` flag. snarkVM has `Authorization<N>` and `Request<N>` but no
//! container that pairs either with its fee — that pairing is the DPS wire
//! contract.
//!
//! | JS `ProvingRequest` | Rust equivalent | Notes |
//! |---|---|---|
//! | `new ProvingRequest(auth, fee_auth, broadcast)` | [`ProvingRequest::new`] | **this module**; Authorization variant |
//! | `fromRequest(req, fee_req, broadcast)` | [`ProvingRequest::from_request`] | **this module**; page omits it, wasm has it |
//! | `kind()` | [`ProvingRequest::kind`] | **this module**; `"authorization"` / `"request"` |
//! | `toString()` | `Display` (`to_string()`) | **this module**; renders JSON |
//! | `fromString(s)` | `FromStr` (`ProvingRequest::from_str`) | **this module**; parses that same JSON |
//! | `toBytesLe()` | `ToBytes::to_bytes_le()` | **this module**; dispatches on the variant |
//! | `fromBytesLe(b)` | [`ProvingRequest::from_bytes_le`] | **this module**; reads the **Authorization** variant |
//! | `fromBytesLeRequest(b)` | [`ProvingRequest::from_bytes_le_request`] | **this module**; reads the **Request** variant |
//! | `authorization()` | [`ProvingRequest::authorization`] | **this module**; errors on the Request variant |
//! | `feeAuthorization()` | [`ProvingRequest::fee_authorization`] | **this module** |
//! | `request()` | [`ProvingRequest::request`] | **this module**; page omits it, wasm has it |
//! | `feeRequest()` | [`ProvingRequest::fee_request`] | **this module**; page omits it, wasm has it |
//! | `broadcast()` | [`ProvingRequest::broadcast`] | **this module** |
//! | `equals(other)` | `PartialEq` (`==`) | **this module**; the flag participates |
//!
//! # The JSON has no tag
//!
//! Upstream derives `#[serde(untagged)]`, so the variant is inferred from which
//! fields are present: `authorization` / `fee_authorization` means the
//! Authorization variant, `request` / `fee_request` means the Request variant.
//! Consequences that are easy to get wrong:
//!
//! - **Both present → Authorization wins.** Untagged enums try variants in
//!   declaration order, and `Authorization` is declared first. It is not an
//!   error, and it is not "ambiguous" — the extra `request` field is simply
//!   ignored.
//! - **Unknown fields are ignored**, because untagged deserialization cannot use
//!   `deny_unknown_fields`. A typo in a field name is therefore silent unless it
//!   removes a required field.
//! - **`broadcast` is required in both shapes.** It is a plain `bool`, not an
//!   `Option<bool>`, so a payload without it fails instead of defaulting.
//! - Deserialization is written by hand here rather than by `serde`'s untagged
//!   machinery: untagged buffers the whole payload and collapses every failure
//!   into "data did not match any variant", which hides which variant was tried
//!   and why it failed. The field-dispatch rule is identical; only the error is
//!   better.
//!
//! # The bytes have no discriminator either
//!
//! `write_le` writes `payload ‖ u8(has_fee) ‖ [fee_payload] ‖ u8(broadcast)`,
//! with `payload` being an `Authorization` or a `Request` depending on the
//! variant — and **nothing marks which one**. That is why there are two readers
//! and no `FromBytes` impl: implementing `FromBytes` would force a default
//! choice, and the upstream default (Authorization, for back-compat) is exactly
//! the footgun. [`ProvingRequest::from_bytes_le`] and
//! [`ProvingRequest::from_bytes_le_request`] make the choice explicit at the
//! call site.
//!
//! The layouts happen to be distinguishable anyway: `Authorization::write_le`
//! starts with version **1** and `Request::write_le` with version **2**, so
//! picking the wrong reader fails loudly ("Invalid authorization version")
//! instead of parsing garbage. Tests pin that, because it is the only reason a
//! wrong choice is survivable.
//!
//! # `Debug` hides the payload
//!
//! An authorization carries the private inputs of the call, so `Debug` prints
//! the variant, the request count and the flags — never the authorizations,
//! signatures or input values. Do not add derived `Debug` here.
//!
//! # Relationship to [`crate::delegated::ProvingRequest`]
//!
//! The delegated-proving module has its own `ProvingRequest`, and it is not
//! redundant: that one is pinned to `TestnetV0`, models **only** the
//! Authorization variant (the `/prove/authorization` route) and hands back a
//! `Zeroizing` buffer, because its bytes are the plaintext inside the sealed
//! box. This type is network-generic, models both variants (the extra one is the
//! `/prove/request` route) and is the one that matches the wasm class. The bytes
//! are the same layout: [`ProvingRequest::from_bytes_le`] parses what
//! `delegated::ProvingRequest::to_bytes_le` produces.
//!
//! # Example
//!
//! ```
//! use aleo_rust_sdk::proving_request::{ProvingRequest, ProvingRequestKind};
//! use snarkvm::prelude::{Authorization, Request, TestnetV0};
//! use std::str::FromStr;
//!
//! # fn run(authorization: Authorization<TestnetV0>, request: Request<TestnetV0>)
//! # -> anyhow::Result<()> {
//! let paid = ProvingRequest::new(authorization, None, true);
//! assert_eq!(paid.kind(), ProvingRequestKind::Authorization);
//! assert!(paid.broadcast());
//!
//! let signed = ProvingRequest::from_request(request, None, false);
//! assert_eq!(signed.kind(), ProvingRequestKind::Request);
//!
//! // `toString` / `fromString`: JSON, variant recovered from the field shape.
//! let reparsed = ProvingRequest::<TestnetV0>::from_str(&paid.to_string())?;
//! assert_eq!(reparsed, paid);
//! # Ok(())
//! # }
//! ```

use std::fmt;
use std::io::{Cursor, Write};
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use serde::de::DeserializeOwned;
use serde_json::Value;
use snarkvm::prelude::{Authorization, FromBytes, Network, Request, ToBytes};

/// Which of the two payloads a [`ProvingRequest`] carries.
///
/// The wasm class exposes this as `kind() → "authorization" | "request"`. A
/// separate type rather than a `String` so the two possible answers cannot drift
/// in a comparison, and so a `match` over the variants is exhaustive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProvingRequestKind {
    /// Built from an executed `Authorization` — the `/prove/authorization` route.
    Authorization,
    /// Built from a signed `Request` — the `/prove/request` route.
    Request,
}

impl ProvingRequestKind {
    /// The string the JS `kind()` returns.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Authorization => "authorization",
            Self::Request => "request",
        }
    }
}

impl fmt::Display for ProvingRequestKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A proving request submitted to a delegated proving service.
///
/// Two shapes, mirroring the DPS routes: an [`Authorization`] (already traced
/// locally) or a signed [`Request`] (traced server-side). Either may carry the
/// matching fee payload, and a `broadcast` flag asking the prover to submit the
/// resulting transaction.
///
/// Both field sets and both byte layouts are documented in the module docs —
/// in particular, neither the JSON nor the bytes carry a variant tag.
#[derive(Clone)]
pub enum ProvingRequest<N: Network> {
    /// A function authorization, plus the optional fee authorization.
    Authorization {
        /// Authorization for the call being proved.
        authorization: Authorization<N>,
        /// Authorization of `credits.aleo/fee_public` or `fee_private`.
        fee_authorization: Option<Authorization<N>>,
        /// Ask the prover to submit the transaction it produces.
        broadcast: bool,
    },
    /// A signed request, plus the optional fee request.
    Request {
        /// Signed request for the call being proved.
        request: Request<N>,
        /// Signed request for the fee function.
        fee_request: Option<Request<N>>,
        /// Ask the prover to submit the transaction it produces.
        broadcast: bool,
    },
}

impl<N: Network> ProvingRequest<N> {
    /// Create an `Authorization`-variant request — the JS constructor.
    pub fn new(
        authorization: Authorization<N>,
        fee_authorization: Option<Authorization<N>>,
        broadcast: bool,
    ) -> Self {
        Self::Authorization {
            authorization,
            fee_authorization,
            broadcast,
        }
    }

    /// Create a `Request`-variant request — the JS `fromRequest`.
    ///
    /// The docs page omits this constructor, but the wasm class has it and it is
    /// the only way to build the second variant. The DPS serves it at
    /// `/prove/request`, which only accepts single-public-request executions:
    /// layered calls have no single request to sign.
    pub fn from_request(
        request: Request<N>,
        fee_request: Option<Request<N>>,
        broadcast: bool,
    ) -> Self {
        Self::Request {
            request,
            fee_request,
            broadcast,
        }
    }

    /// Which variant this is — the JS `kind()`.
    pub fn kind(&self) -> ProvingRequestKind {
        match self {
            Self::Authorization { .. } => ProvingRequestKind::Authorization,
            Self::Request { .. } => ProvingRequestKind::Request,
        }
    }

    /// Whether this is the `Authorization` variant.
    pub fn is_authorization(&self) -> bool {
        matches!(self, Self::Authorization { .. })
    }

    /// Whether this is the `Request` variant.
    pub fn is_request(&self) -> bool {
        matches!(self, Self::Request { .. })
    }

    /// The main-function authorization.
    ///
    /// # Errors
    ///
    /// Fails on the `Request` variant. This is the JS `authorization()`, which
    /// throws there for the same reason: there is nothing to return, and
    /// silently returning `None` would turn a routing bug into a missing field.
    pub fn authorization(&self) -> Result<&Authorization<N>> {
        match self {
            Self::Authorization { authorization, .. } => Ok(authorization),
            Self::Request { .. } => bail!(
                "ProvingRequest is a Request variant; call `request()` instead of `authorization()`"
            ),
        }
    }

    /// The fee authorization, if the `Authorization` variant carries one.
    ///
    /// Returns `None` on the `Request` variant as well — the JS
    /// `feeAuthorization()` returns `undefined` there.
    pub fn fee_authorization(&self) -> Option<&Authorization<N>> {
        match self {
            Self::Authorization {
                fee_authorization, ..
            } => fee_authorization.as_ref(),
            Self::Request { .. } => None,
        }
    }

    /// The signed request.
    ///
    /// # Errors
    ///
    /// Fails on the `Authorization` variant. The page omits this getter; the wasm
    /// class has it, and it is the mirror image of [`Self::authorization`].
    pub fn request(&self) -> Result<&Request<N>> {
        match self {
            Self::Request { request, .. } => Ok(request),
            Self::Authorization { .. } => bail!(
                "ProvingRequest is an Authorization variant; call `authorization()` instead of `request()`"
            ),
        }
    }

    /// The fee request, if the `Request` variant carries one.
    pub fn fee_request(&self) -> Option<&Request<N>> {
        match self {
            Self::Request { fee_request, .. } => fee_request.as_ref(),
            Self::Authorization { .. } => None,
        }
    }

    /// Whether the prover should submit the transaction itself.
    pub fn broadcast(&self) -> bool {
        match self {
            Self::Authorization { broadcast, .. } | Self::Request { broadcast, .. } => *broadcast,
        }
    }

    /// The JSON value the JS `toString` produces.
    ///
    /// Exposed separately from `Display` so a caller can embed the request in a
    /// larger payload without stringifying and re-parsing it.
    pub fn to_json_value(&self) -> Result<Value> {
        Ok(match self {
            Self::Authorization {
                authorization,
                fee_authorization,
                broadcast,
            } => serde_json::json!({
                "authorization": serde_json::to_value(authorization)
                    .context("Failed to serialize authorization")?,
                "fee_authorization": match fee_authorization {
                    Some(fee) => serde_json::to_value(fee)
                        .context("Failed to serialize fee authorization")?,
                    None => Value::Null,
                },
                "broadcast": broadcast,
            }),
            Self::Request {
                request,
                fee_request,
                broadcast,
            } => serde_json::json!({
                "request": serde_json::to_value(request)
                    .context("Failed to serialize request")?,
                "fee_request": match fee_request {
                    Some(fee) => serde_json::to_value(fee)
                        .context("Failed to serialize fee request")?,
                    None => Value::Null,
                },
                "broadcast": broadcast,
            }),
        })
    }

    /// Read the `Authorization` variant — the JS `fromBytesLe`.
    ///
    /// # Errors
    ///
    /// Fails if the bytes are not an authorization payload, and fails on trailing
    /// bytes: a length mismatch means the reader and the writer disagree about
    /// the layout, and ignoring the tail would hide exactly that.
    pub fn from_bytes_le(bytes: &[u8]) -> Result<Self> {
        let mut reader = Cursor::new(bytes);
        let authorization =
            Authorization::<N>::read_le(&mut reader).context("Failed to read authorization")?;
        let has_fee = bool::read_le(&mut reader).context("Failed to read fee flag")?;
        let fee_authorization: Option<Authorization<N>> =
            read_optional(&mut reader, has_fee).context("Failed to read fee authorization")?;
        let broadcast = bool::read_le(&mut reader).context("Failed to read broadcast flag")?;
        ensure_exhausted(&reader, bytes.len())?;
        Ok(Self::Authorization {
            authorization,
            fee_authorization,
            broadcast,
        })
    }

    /// Read the `Request` variant — the JS `fromBytesLeRequest`.
    ///
    /// # Errors
    ///
    /// Fails if the bytes are not a request payload, and fails on trailing bytes
    /// like [`Self::from_bytes_le`].
    pub fn from_bytes_le_request(bytes: &[u8]) -> Result<Self> {
        let mut reader = Cursor::new(bytes);
        let request =
            Request::<N>::read_le(&mut reader).context("Failed to read request payload")?;
        let has_fee = bool::read_le(&mut reader).context("Failed to read fee flag")?;
        let fee_request: Option<Request<N>> =
            read_optional(&mut reader, has_fee).context("Failed to read fee request")?;
        let broadcast = bool::read_le(&mut reader).context("Failed to read broadcast flag")?;
        ensure_exhausted(&reader, bytes.len())?;
        Ok(Self::Request {
            request,
            fee_request,
            broadcast,
        })
    }
}

impl<N: Network> ToBytes for ProvingRequest<N> {
    /// `payload ‖ u8(has_fee) ‖ [fee_payload] ‖ u8(broadcast)`.
    ///
    /// No discriminator: the reader has to know which variant it holds (see the
    /// module docs). Writing is safe because the variant is right here.
    fn write_le<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        match self {
            Self::Authorization {
                authorization,
                fee_authorization,
                broadcast,
            } => {
                authorization.write_le(&mut writer)?;
                write_optional(fee_authorization, &mut writer)?;
                broadcast.write_le(&mut writer)
            }
            Self::Request {
                request,
                fee_request,
                broadcast,
            } => {
                request.write_le(&mut writer)?;
                write_optional(fee_request, &mut writer)?;
                broadcast.write_le(&mut writer)
            }
        }
    }
}

impl<N: Network> PartialEq for ProvingRequest<N> {
    /// Deep equality, including `broadcast` and the fee payload.
    ///
    /// A different variant never compares equal, even when the payloads came from
    /// the same call: the two shapes route to different DPS endpoints, so they are
    /// different requests, not two spellings of one.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Authorization {
                    authorization,
                    fee_authorization,
                    broadcast,
                },
                Self::Authorization {
                    authorization: other_authorization,
                    fee_authorization: other_fee,
                    broadcast: other_broadcast,
                },
            ) => {
                authorization == other_authorization
                    && fee_authorization == other_fee
                    && broadcast == other_broadcast
            }
            (
                Self::Request {
                    request,
                    fee_request,
                    broadcast,
                },
                Self::Request {
                    request: other_request,
                    fee_request: other_fee,
                    broadcast: other_broadcast,
                },
            ) => {
                request == other_request && fee_request == other_fee && broadcast == other_broadcast
            }
            _ => false,
        }
    }
}

impl<N: Network> Eq for ProvingRequest<N> {}

impl<N: Network> fmt::Display for ProvingRequest<N> {
    /// The JS `toString`: compact JSON, variant recoverable from the field shape.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json = self.to_json_value().map_err(|_| fmt::Error)?;
        write!(f, "{json}")
    }
}

impl<N: Network> FromStr for ProvingRequest<N> {
    type Err = anyhow::Error;

    /// The JS `fromString`, with the variant picked by field presence.
    ///
    /// `authorization` wins when both `authorization` and `request` are present,
    /// matching the declaration order untagged `serde` would use.
    fn from_str(s: &str) -> Result<Self> {
        let value: Value =
            serde_json::from_str(s).context("Failed to parse proving request JSON")?;
        let Value::Object(mut object) = value else {
            bail!("Expected a JSON object for a proving request");
        };

        if object.contains_key("authorization") {
            let authorization = take::<Authorization<N>>(&mut object, "authorization")?;
            let fee_authorization =
                take_optional::<Authorization<N>>(&mut object, "fee_authorization")?;
            let broadcast = take::<bool>(&mut object, "broadcast")?;
            return Ok(Self::Authorization {
                authorization,
                fee_authorization,
                broadcast,
            });
        }

        if object.contains_key("request") {
            let request = take::<Request<N>>(&mut object, "request")?;
            let fee_request = take_optional::<Request<N>>(&mut object, "fee_request")?;
            let broadcast = take::<bool>(&mut object, "broadcast")?;
            return Ok(Self::Request {
                request,
                fee_request,
                broadcast,
            });
        }

        bail!(
            "A proving request needs either an `authorization` or a `request` field \
             (the JSON carries no variant tag)"
        )
    }
}

impl<N: Network> fmt::Debug for ProvingRequest<N> {
    /// Never print the payloads: an authorization holds the private inputs of the
    /// call. Counts and flags are enough to tell two requests apart while
    /// debugging.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization {
                authorization,
                fee_authorization,
                broadcast,
            } => f
                .debug_struct("ProvingRequest::Authorization")
                .field("requests", &authorization.len())
                .field("has_fee_authorization", &fee_authorization.is_some())
                .field("broadcast", broadcast)
                .finish(),
            Self::Request {
                request,
                fee_request,
                broadcast,
            } => f
                .debug_struct("ProvingRequest::Request")
                .field("inputs", &request.inputs().len())
                .field("has_fee_request", &fee_request.is_some())
                .field("broadcast", broadcast)
                .finish(),
        }
    }
}

/// Write the `has_fee` flag and, when set, the fee payload.
fn write_optional<W: Write, T: ToBytes>(
    payload: &Option<T>,
    writer: &mut W,
) -> std::io::Result<()> {
    match payload {
        Some(payload) => {
            true.write_le(&mut *writer)?;
            payload.write_le(writer)
        }
        None => false.write_le(writer),
    }
}

/// Read the fee payload if the flag was set.
fn read_optional<T: FromBytes, R: std::io::Read>(
    reader: &mut R,
    has_fee: bool,
) -> std::io::Result<Option<T>> {
    match has_fee {
        true => Ok(Some(T::read_le(reader)?)),
        false => Ok(None),
    }
}

/// Reject trailing bytes.
///
/// Kept as a hard error rather than a warning: a tail means the reader and the
/// writer disagree about the layout, and every "ignore it" variant of that bug
/// surfaces later as a request the prover cannot open.
fn ensure_exhausted<R: std::io::Read>(reader: &Cursor<R>, len: usize) -> Result<()> {
    let consumed = reader.position() as usize;
    if consumed != len {
        bail!("Trailing bytes after proving request: consumed {consumed} of {len}");
    }
    Ok(())
}

/// Remove a required field and parse it, naming the field on failure.
fn take<T: DeserializeOwned>(object: &mut serde_json::Map<String, Value>, key: &str) -> Result<T> {
    let value = object.remove(key).ok_or_else(|| anyhow!("Missing `{key}` field"))?;
    serde_json::from_value(value).with_context(|| format!("Failed to parse `{key}`"))
}

/// Remove an optional field and parse it; missing and `null` both mean `None`.
fn take_optional<T: DeserializeOwned>(
    object: &mut serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<T>> {
    match object.remove(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => Ok(Some(
            serde_json::from_value(value).with_context(|| format!("Failed to parse `{key}`"))?,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::ExecutionEngine;
    use snarkvm::prelude::{Address, ComputeKey, PrivateKey, ProgramID, TestRng, TestnetV0};
    use std::sync::LazyLock;

    type N = TestnetV0;

    /// One offline authorization, shared by every test: `Process::load` plus the
    /// trace dominates this module's runtime, and a `credits.aleo/transfer_public`
    /// authorization never proves, so it costs milliseconds.
    ///
    /// It must be a *real* authorization (request **and** transition): the JSON
    /// reader goes through `Authorization::try_from((requests, transitions))`,
    /// which rejects the counts when they differ.
    fn authorization() -> &'static Authorization<N> {
        static AUTHORIZATION: LazyLock<Authorization<N>> = LazyLock::new(|| {
            let engine = ExecutionEngine::new().expect("process should load");
            let mut rng = TestRng::fixed(21);
            let private_key = PrivateKey::<N>::new(&mut rng).unwrap();
            let address =
                Address::<N>::try_from(ComputeKey::try_from(&private_key).unwrap()).unwrap();
            let program_id = ProgramID::<N>::from_str("credits.aleo").unwrap();
            engine
                .authorize(
                    &private_key,
                    &program_id,
                    "transfer_public",
                    vec![address.to_string().as_str(), "1u64"],
                    &mut rng,
                )
                .expect("offline authorization should succeed")
        });
        &AUTHORIZATION
    }

    /// A signed request for the same call shape, without any proving.
    fn request() -> Request<N> {
        let mut rng = TestRng::fixed(22);
        let private_key = PrivateKey::<N>::new(&mut rng).unwrap();
        let address = Address::<N>::try_from(ComputeKey::try_from(&private_key).unwrap()).unwrap();
        crate::execution_request::sign(
            &private_key,
            "credits.aleo",
            "transfer_public",
            &[&address.to_string(), "1u64"],
            &["address.public", "u64.public"],
            None,
            None,
            true,
            false,
            &mut rng,
        )
        .unwrap()
    }

    #[test]
    fn authorization_variant_exposes_its_payload() {
        let paid = ProvingRequest::new(authorization().clone(), None, true);

        assert_eq!(paid.kind(), ProvingRequestKind::Authorization);
        assert_eq!(paid.kind().as_str(), "authorization");
        assert_eq!(paid.kind().to_string(), "authorization");
        assert!(paid.is_authorization());
        assert!(!paid.is_request());
        assert!(paid.broadcast());
        assert_eq!(paid.authorization().unwrap(), authorization());
        assert!(paid.fee_authorization().is_none());
        // The request-side getters stay empty on this variant instead of failing.
        assert!(paid.fee_request().is_none());
    }

    #[test]
    fn request_variant_exposes_its_payload() {
        let signed = ProvingRequest::from_request(request(), None, false);

        assert_eq!(signed.kind(), ProvingRequestKind::Request);
        assert_eq!(signed.kind().as_str(), "request");
        assert!(signed.is_request());
        assert!(!signed.is_authorization());
        assert!(!signed.broadcast());
        assert_eq!(signed.request().unwrap(), &request());
        assert!(signed.fee_request().is_none());
        assert!(signed.fee_authorization().is_none());
    }

    #[test]
    fn variant_specific_getters_name_the_other_getter() {
        // The JS getters throw, and the message has to say which call to make
        // instead — returning `None` would turn a routing mistake into a missing
        // field two frames later.
        let paid = ProvingRequest::new(authorization().clone(), None, false);
        let error = paid.request().unwrap_err().to_string();
        assert!(error.contains("is an Authorization variant"), "{error}");
        assert!(error.contains("call `authorization()`"), "{error}");

        let signed = ProvingRequest::from_request(request(), None, false);
        let error = signed.authorization().unwrap_err().to_string();
        assert!(error.contains("is a Request variant"), "{error}");
        assert!(error.contains("call `request()`"), "{error}");
    }

    #[test]
    fn json_shape_reveals_the_variant() {
        let paid = ProvingRequest::new(authorization().clone(), None, true);
        let json = paid.to_string();
        assert!(
            json.contains("\"authorization\""),
            "unexpected JSON: {json}"
        );
        assert!(json.contains("\"fee_authorization\":null"), "{json}");
        assert!(json.contains("\"broadcast\":true"), "{json}");
        assert!(!json.contains("\"request\""), "{json}");

        let signed = ProvingRequest::from_request(request(), None, false);
        let json = signed.to_string();
        assert!(json.contains("\"request\""), "unexpected JSON: {json}");
        assert!(json.contains("\"fee_request\":null"), "{json}");
        assert!(json.contains("\"broadcast\":false"), "{json}");

        // `toString` is the only representation that records the variant, so the
        // round trip has to recover the same value — not merely the same payload.
        let reparsed = ProvingRequest::<N>::from_str(&paid.to_string()).unwrap();
        assert_eq!(reparsed, paid);
        assert_eq!(reparsed.kind(), ProvingRequestKind::Authorization);

        let reparsed = ProvingRequest::<N>::from_str(&signed.to_string()).unwrap();
        assert_eq!(reparsed, signed);
        assert_eq!(reparsed.kind(), ProvingRequestKind::Request);
    }

    #[test]
    fn json_field_presence_picks_the_variant() {
        // Both keys present: `authorization` is tried first, so it wins and the
        // `request` key is ignored — this is what untagged serde does upstream.
        let paid = ProvingRequest::new(authorization().clone(), None, false);
        let mut value = paid.to_json_value().unwrap();
        let signed = ProvingRequest::from_request(request(), None, false);
        value["request"] = signed.to_json_value().unwrap()["request"].clone();

        let parsed = ProvingRequest::<N>::from_str(&value.to_string()).unwrap();
        assert_eq!(parsed.kind(), ProvingRequestKind::Authorization);
        assert_eq!(parsed, paid);

        // Neither key: no variant to pick, and the error says why.
        let error =
            ProvingRequest::<N>::from_str(r#"{"broadcast":false}"#).unwrap_err().to_string();
        assert!(
            error.contains("either an `authorization` or a `request` field"),
            "{error}"
        );
    }

    #[test]
    fn json_ignores_unknown_fields_but_not_a_missing_flag() {
        let paid = ProvingRequest::new(authorization().clone(), None, true);
        let mut value = paid.to_json_value().unwrap();
        // Untagged deserialization cannot use `deny_unknown_fields`, so a stray
        // field is silent. Worth pinning: it is also why a typo in a field name
        // only fails when it removes something required.
        value["kind"] = serde_json::json!("authorization");
        assert_eq!(
            ProvingRequest::<N>::from_str(&value.to_string()).unwrap(),
            paid
        );

        // `broadcast` is a plain bool, not an Option, so it cannot be omitted.
        value.as_object_mut().unwrap().remove("broadcast");
        let error = ProvingRequest::<N>::from_str(&value.to_string()).unwrap_err().to_string();
        assert!(error.contains("Missing `broadcast` field"), "{error}");

        // A `null` fee payload reads back as absent, same as a missing one.
        let mut value = paid.to_json_value().unwrap();
        value["fee_authorization"] = Value::Null;
        let parsed = ProvingRequest::<N>::from_str(&value.to_string()).unwrap();
        assert!(parsed.fee_authorization().is_none());
    }

    #[test]
    fn bytes_round_trip_per_variant() {
        let paid = ProvingRequest::new(authorization().clone(), None, true);
        let bytes = paid.to_bytes_le().unwrap();
        let parsed = ProvingRequest::<N>::from_bytes_le(&bytes).unwrap();
        assert_eq!(parsed, paid);
        assert_eq!(parsed.to_bytes_le().unwrap(), bytes);
        assert_eq!(parsed.kind(), ProvingRequestKind::Authorization);

        let signed = ProvingRequest::from_request(request(), None, false);
        let bytes = signed.to_bytes_le().unwrap();
        let parsed = ProvingRequest::<N>::from_bytes_le_request(&bytes).unwrap();
        assert_eq!(parsed, signed);
        assert_eq!(parsed.to_bytes_le().unwrap(), bytes);
        assert_eq!(parsed.kind(), ProvingRequestKind::Request);
    }

    #[test]
    fn the_fee_payload_round_trips_in_both_variants() {
        // The fee payload is what makes the two shapes asymmetric in JSON
        // (`fee_authorization` vs `fee_request`). Without this test the `Some`
        // half of the flag+buffer code never runs.
        let paid =
            ProvingRequest::new(authorization().clone(), Some(authorization().clone()), true);
        assert!(paid.fee_authorization().is_some());
        let json = paid.to_string();
        assert!(!json.contains("\"fee_authorization\":null"), "{json}");
        assert_eq!(ProvingRequest::<N>::from_str(&json).unwrap(), paid);

        // `payload ‖ 1 ‖ fee_payload ‖ 1`, and the fee is the same size here.
        let auth_len = authorization().to_bytes_le().unwrap().len();
        let bytes = paid.to_bytes_le().unwrap();
        assert_eq!(bytes.len(), 2 * auth_len + 2);
        assert_eq!(ProvingRequest::<N>::from_bytes_le(&bytes).unwrap(), paid);

        let signed = ProvingRequest::from_request(request(), Some(request()), false);
        assert!(signed.fee_request().is_some());
        assert_eq!(
            ProvingRequest::<N>::from_bytes_le_request(&signed.to_bytes_le().unwrap()).unwrap(),
            signed
        );
        assert_eq!(
            ProvingRequest::<N>::from_str(&signed.to_string()).unwrap(),
            signed
        );
    }

    #[test]
    fn the_byte_layout_has_no_discriminator() {
        // Nothing in the buffer marks the variant, so the reader must be told.
        // The version byte is the only reason a wrong pick fails loudly rather
        // than parsing garbage: Authorization writes 1, Request writes 2.
        let paid_bytes =
            ProvingRequest::new(authorization().clone(), None, false).to_bytes_le().unwrap();
        let request_bytes =
            ProvingRequest::from_request(request(), None, false).to_bytes_le().unwrap();
        assert_eq!(
            paid_bytes[0], 1,
            "authorization payload starts with version 1"
        );
        assert_eq!(request_bytes[0], 2, "request payload starts with version 2");

        // The outer context names the read that failed; the version check is one
        // link further down the chain.
        let error = ProvingRequest::<N>::from_bytes_le(&request_bytes).unwrap_err();
        let chain = format!("{error:#}");
        assert!(chain.contains("Failed to read authorization"), "{chain}");
        assert!(chain.contains("Invalid authorization version"), "{chain}");

        // The other direction is not symmetric — `Request::read_le` accepts
        // version 1 for back-compat — but the address/network fields that follow
        // are a different shape, so it still fails instead of silently succeeding.
        assert!(ProvingRequest::<N>::from_bytes_le_request(&paid_bytes).is_err());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        for bytes in [
            ProvingRequest::new(authorization().clone(), None, false).to_bytes_le().unwrap(),
            ProvingRequest::from_request(request(), None, false).to_bytes_le().unwrap(),
        ] {
            let mut padded = bytes.clone();
            padded.push(0xff);
            let error = match bytes[0] {
                1 => ProvingRequest::<N>::from_bytes_le(&padded).unwrap_err().to_string(),
                _ => ProvingRequest::<N>::from_bytes_le_request(&padded).unwrap_err().to_string(),
            };
            assert!(
                error.contains("Trailing bytes"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn the_authorization_bytes_match_the_delegated_transport_layout() {
        // `delegated::ProvingRequest` is pinned to TestnetV0 and only models the
        // Authorization variant, but it writes the same bytes. If these two ever
        // drift, one of them is talking to the prover with a layout it cannot
        // open.
        let transport = crate::delegated::ProvingRequest::new(authorization().clone(), None, true);
        let generic = ProvingRequest::new(authorization().clone(), None, true);

        assert_eq!(
            transport.to_bytes_le().unwrap().as_slice(),
            generic.to_bytes_le().unwrap().as_slice()
        );
        // And this type reads what the transport wrote.
        assert_eq!(
            ProvingRequest::<N>::from_bytes_le(&transport.to_bytes_le().unwrap()).unwrap(),
            generic
        );
    }

    #[test]
    fn equality_includes_the_broadcast_flag_and_the_variant() {
        let quiet = ProvingRequest::new(authorization().clone(), None, false);
        let loud = ProvingRequest::new(authorization().clone(), None, true);
        assert_ne!(quiet, loud, "broadcast participates in equality");

        // Same call, different shape: different request, not another spelling.
        let signed = ProvingRequest::from_request(request(), None, false);
        assert_ne!(quiet, signed);

        // An attached fee payload also participates.
        let fee = ProvingRequest::new(
            authorization().clone(),
            Some(authorization().clone()),
            false,
        );
        assert_ne!(quiet, fee);
        assert!(fee.fee_authorization().is_some());
    }

    #[test]
    fn debug_hides_the_payload() {
        // An authorization carries the private inputs of the call; `Debug` must
        // not print them, and it must not print the signer either.
        let paid = ProvingRequest::new(authorization().clone(), None, true);
        let debug = format!("{paid:?}");
        assert!(debug.contains("ProvingRequest::Authorization"), "{debug}");
        assert!(debug.contains("has_fee_authorization"), "{debug}");
        assert!(
            !debug.contains(authorization().peek_next().unwrap().signer().to_string().as_str())
        );
        assert!(!debug.contains("aleo1"), "signer address leaked: {debug}");

        let signed = ProvingRequest::from_request(request(), None, false);
        let debug = format!("{signed:?}");
        assert!(debug.contains("ProvingRequest::Request"), "{debug}");
        assert!(!debug.contains("aleo1"), "signer address leaked: {debug}");
        assert!(!debug.contains("1u64"), "input value leaked: {debug}");
    }
}
