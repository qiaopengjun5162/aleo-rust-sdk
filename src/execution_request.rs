//! JS SDK `ExecutionRequest` parity.
//!
//! The wasm class is a newtype over snarkVM's [`Request<N>`]
//! (`wasm/src/programs/request.rs`, `pub struct ExecutionRequest(RequestNative)`),
//! so **16 of the 18 documented methods have a one-call Rust equivalent** and
//! no new type is needed here. The two that do not are [`sign`] and [`verify`],
//! both because the JS layer parses `string` inputs into typed values before
//! forwarding to snarkVM.
//!
//! | JS `ExecutionRequest` | Rust equivalent | Notes |
//! |---|---|---|
//! | `toString()` | `Display` (`to_string()`) | native; renders **JSON** |
//! | `fromString(s)` | `FromStr` (`Request::<N>::from_str`) | native; parses that same JSON |
//! | `toBytesLe()` | `ToBytes::to_bytes_le()` | native; always writes **version 2** |
//! | `fromBytesLe(b)` | `FromBytes::from_bytes_le()` | native; reads v1 and v2 |
//! | `signer()` | `Request::signer()` | native; `&Address<N>` |
//! | `network_id()` | [`network_id`] | native is `&U16<N>`, JS gives a `number` |
//! | `program_id()` | `Request::program_id().to_string()` | native; `String` in JS, `&ProgramID<N>` here |
//! | `function_name()` | `Request::function_name().to_string()` | native; `String` in JS, `&Identifier<N>` here |
//! | `input_ids()` | `Request::input_ids()` | native; `&[InputID<N>]`, see below |
//! | `inputs()` | [`input_strings`] | JS renders each `Value` with `Display` |
//! | `signature()` | `Request::signature()` | native; `&Signature<N>` |
//! | `sk_tag()` | `Request::sk_tag()` | native |
//! | `tvk()` | `Request::tvk()` | native |
//! | `to_tpk()` | `Request::to_tpk()` | native; **recomputed** from the signature |
//! | `tcm()` | `Request::tcm()` | native |
//! | `scm()` | `Request::scm()` | native |
//! | `sign(...)` | [`sign`] | **this module**; JS-shaped string arguments + RNG |
//! | `verify(...)` | [`verify`] | **this module**; parses types and guards the arity |
//!
//! The wasm class also exposes camelCase aliases (`networkId`, `programId`,
//! `functionName`, `inputIds`, `skTag`, `toTpk`) and external-signing
//! constructors (`fromExternallySignedData*`, `computeExternalSigningInputs`)
//! that the docs page does not list. The aliases are the same call in Rust; the
//! external-signing constructors belong to a page that does not exist here yet
//! and are out of scope for this module.
//!
//! # The docs page is missing an argument
//!
//! The page documents `sign` with eight parameters and no `is_dynamic`. The
//! wasm implementation takes **nine** — `is_dynamic` sits between
//! `program_checksum`/`is_root` and the RNG — and [`sign`] matches the
//! implementation, not the page.
//!
//! # `verify` is narrower than its name suggests
//!
//! Three behaviours the page does not mention, all pinned by tests below:
//!
//! **`input_types` is only consulted for record inputs.** `verify` dispatches on
//! the *stored* `InputID` variant and only the `Record` arm reads the declared
//! type (to recover the record name feeding the commitment). For
//! constant/public/private/external-record/dynamic-record inputs the declared
//! type is ignored entirely, so a request signed against `"u64.public"` also
//! verifies when you pass `"u64.private"`. Treat the type list as "the record
//! names", not as a type check.
//!
//! **A wrong number of types panics inside snarkVM.** The verification zips
//! `input_ids`, `inputs` and `input_types` with `itertools::zip_eq`, which
//! panics on a length mismatch. [`verify`] checks the arity first and returns an
//! error instead — a panic crossing wasm-bindgen aborts the whole module, which
//! is exactly the failure mode the JS wrapper inherits.
//!
//! **`is_dynamic` is carried, never verified.** It is absent from the signature
//! message and `verify` never reads it, so flipping the flag on a rebuilt
//! request still verifies. Dynamic-ness is decided at
//! `Process::authorize_request` time; treat the flag as routing metadata.
//!
//! What `verify` *does* prove: `tvk → tcm` is consistent, the function ID
//! matches the stored program/function, every stored input ID re-derives from
//! the stored input, record inputs belong to the signer, and the signature over
//! that message was produced by the signer. Failures print to **stderr** via
//! `eprintln!` and return `false` — snarkVM will not tell you which check
//! failed, and that stderr contains input hashes, so do not forward it to end
//! users verbatim.
//!
//! # Other things worth knowing
//!
//! - **`input_ids()` is heterogeneous in JS, typed in Rust.** JS returns a
//!   `Field` for constant/public/private/external/dynamic inputs, and a
//!   five-element array `[commitment, gamma, record_view_key, serial_number,
//!   tag]` for record inputs. Rust returns `InputID<N>` variants; match on the
//!   variant instead of indexing a tuple.
//! - **The JSON uses `program` and `function`, not `program_id` and
//!   `function_name`.** `to_string()` is `serde_json`, so the keys come from
//!   snarkVM's derives — do not hand-build the object from the getter names.
//! - **`to_tpk()` is not stored.** It is recomputed as
//!   `pk_sig * challenge + response * G` on every call, so it cannot drift out
//!   of sync with the signature.
//! - **`sign` needs an RNG.** JS reaches for thread entropy; this crate never
//!   does, so the caller supplies one.
//! - **`root_tvk` is `None` for the top-level call.** snarkVM then substitutes
//!   the request's own `tvk` when building `scm`, which is why a root request's
//!   `scm` is `Hash(signer, tvk)`.
//! - **Bytes are version 2 on write, version 1 or 2 on read.** A v1 payload has
//!   no dynamic flag and is read as static.
//!
//! # Usage
//!
//! ```
//! use aleo_rust_sdk::execution_request;
//! use snarkvm::prelude::{Address, ComputeKey, Network, PrivateKey, TestRng, TestnetV0};
//!
//! let rng = &mut TestRng::fixed(0);
//! let private_key = PrivateKey::<TestnetV0>::new(rng).unwrap();
//! let address = Address::<TestnetV0>::try_from(ComputeKey::try_from(&private_key).unwrap()).unwrap();
//!
//! // JS: ExecutionRequest.sign(privateKey, "credits.aleo", "transfer_public",
//! //                           [address, "1u64"], ["address.public", "u64.public"],
//! //                           undefined, undefined, true)
//! let request = execution_request::sign(
//!     &private_key,
//!     "credits.aleo",
//!     "transfer_public",
//!     &[&address.to_string(), "1u64"],
//!     &["address.public", "u64.public"],
//!     None,
//!     None,
//!     true,
//!     false,
//!     rng,
//! )
//! .unwrap();
//!
//! // JS: request.verify(["address.public", "u64.public"], true, undefined)
//! assert!(execution_request::verify(&request, &["address.public", "u64.public"], true, None).unwrap());
//! assert_eq!(execution_request::network_id(&request), TestnetV0::ID);
//! ```

use anyhow::{Context, Result, bail};
use snarkvm::prelude::{
    CryptoRng, Field, FromStr, Identifier, Network, PrivateKey, ProgramID, Request, Rng, Value,
    ValueType,
};

/// Signs a request over a program ID and its inputs — the JS
/// `ExecutionRequest.sign(...)`.
///
/// Mirrors the wasm implementation (`wasm/src/programs/request.rs`), which
/// parses every argument from its JS string form before calling
/// [`Request::sign`]. Unlike the docs page, the argument list includes
/// `is_dynamic`, because the implementation requires it.
///
/// # Arguments
/// * `private_key` - The signer's private key; also determines the `signer`
///   address and the `sk_tag`.
/// * `program_id` - A program ID string, e.g. `"credits.aleo"`.
/// * `function_name` - A function identifier, e.g. `"transfer_public"`.
/// * `inputs` - Aleo value strings in the same order as `input_types`.
/// * `input_types` - Value types such as `"address.public"`, `"u64.private"`,
///   or `"credits.record"`.
/// * `root_tvk` - The `tvk` of the root call, or `None` when this **is** the
///   root call.
/// * `program_checksum` - The program checksum when the callee has a
///   constructor, `None` otherwise. It changes the signature message, so
///   supplying it for the wrong program yields a request that will not verify
///   against the on-chain function.
/// * `is_root` - Whether this call is the top of the call graph.
/// * `is_dynamic` - Whether this is a dynamic call. Stored, never signed.
/// * `rng` - Randomness source; Aleo signatures are randomized.
///
/// # Errors
/// Returns an error if `program_id` or `function_name` does not parse, if any
/// input or input type does not parse, if the two slices differ in length, or
/// if signing fails.
///
/// Input parse errors name the position (`Failed to parse input #1 ...`)
/// because the JS layer does the same; without the index, a bad address deep in
/// a ten-input call is indistinguishable from any other failure.
// Ten parameters is the JS/wasm signature verbatim; bundling them into a struct
// would hide the one thing this module exists to show — what the call actually
// takes. Upstream carries the same allow for the same reason.
#[allow(clippy::too_many_arguments)]
pub fn sign<N: Network, R: Rng + CryptoRng>(
    private_key: &PrivateKey<N>,
    program_id: &str,
    function_name: &str,
    inputs: &[&str],
    input_types: &[&str],
    root_tvk: Option<Field<N>>,
    program_checksum: Option<Field<N>>,
    is_root: bool,
    is_dynamic: bool,
    rng: &mut R,
) -> Result<Request<N>> {
    let program_id = ProgramID::<N>::from_str(program_id)
        .with_context(|| format!("Failed to parse '{program_id}' as a program ID"))?;
    let function_name = Identifier::<N>::from_str(function_name)
        .with_context(|| format!("Failed to parse '{function_name}' as a function name"))?;

    let parsed_inputs = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            Value::<N>::from_str(input)
                .with_context(|| format!("Failed to parse input #{index} ('{input}')"))
        })
        .collect::<Result<Vec<_>>>()?;

    let parsed_types = parse_input_types::<N>(input_types)?;

    Request::sign(
        private_key,
        program_id,
        function_name,
        parsed_inputs.into_iter(),
        &parsed_types,
        root_tvk,
        is_root,
        program_checksum,
        is_dynamic,
        rng,
    )
    .context("Failed to sign the execution request")
}

/// Verifies a request — the JS `ExecutionRequest.verify`.
///
/// Parses the type strings, checks the arity, then forwards to
/// [`Request::verify`]. See the module docs for what is and is not actually
/// checked: the type list only matters for record inputs.
///
/// # Arguments
/// * `request` - The request to check.
/// * `input_types` - Value type strings, one per input, in order.
/// * `is_root` - Whether this call is the top of the call graph. It **is** part
///   of the signature message, so guessing wrong yields `false`.
/// * `program_checksum` - Must match what was supplied at signing time.
///
/// # Returns
/// `Ok(true)` when every check passes, `Ok(false)` when a check fails.
///
/// # Errors
/// Returns an error when a type string does not parse, or when the number of
/// types differs from the number of inputs — snarkVM would **panic** in the
/// latter case (`itertools::zip_eq`), and a panic inside wasm-bindgen aborts the
/// module. A valid type that simply does not match the request is a `false`,
/// not an error: keeping the two apart stops a malformed type string from
/// looking like a successful rejection.
///
/// # Note
/// snarkVM prints the failing check to stderr. This function does not capture
/// or re-emit it.
pub fn verify<N: Network>(
    request: &Request<N>,
    input_types: &[&str],
    is_root: bool,
    program_checksum: Option<Field<N>>,
) -> Result<bool> {
    if input_types.len() != request.input_ids().len() {
        bail!(
            "Expected {} input types, found {}",
            request.input_ids().len(),
            input_types.len()
        );
    }

    let parsed_types = parse_input_types::<N>(input_types)?;
    Ok(request.verify(&parsed_types, is_root, program_checksum))
}

/// Returns the request's inputs rendered as strings — the JS `inputs()`.
///
/// JS maps `input.to_string()` over the stored values, so the strings are the
/// canonical Aleo representations (`"1u64"`, `"aleo1..."`, a full record
/// plaintext for record inputs), not JSON.
pub fn input_strings<N: Network>(request: &Request<N>) -> Vec<String> {
    request.inputs().iter().map(ToString::to_string).collect()
}

/// Returns the network ID as a `u16` — the JS `network_id()`.
///
/// Native [`Request::network_id`] hands back a `&U16<N>`; JS exposes a plain
/// number. This is the double deref, named so callers do not have to discover
/// that `U16` derefs to `u16`.
pub fn network_id<N: Network>(request: &Request<N>) -> u16 {
    **request.network_id()
}

/// Parses value type strings, naming the position on failure.
///
/// Shared by [`sign`] and [`verify`] so both report the same index for the same
/// bad string; the JS wrapper produces the identical message shape.
fn parse_input_types<N: Network>(input_types: &[&str]) -> Result<Vec<ValueType<N>>> {
    input_types
        .iter()
        .enumerate()
        .map(|(index, input_type)| {
            ValueType::<N>::from_str(input_type)
                .with_context(|| format!("Failed to parse input type #{index} ('{input_type}')"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::{
        Address, ComputeKey, FromBytes, GraphKey, Group, InputID, TestRng, TestnetV0, ToBytes,
        ViewKey, Zero,
    };

    type N = TestnetV0;

    const TYPES: [&str; 2] = ["address.public", "u64.public"];

    fn key_and_address(rng: &mut TestRng) -> (PrivateKey<N>, Address<N>) {
        let private_key = PrivateKey::<N>::new(rng).unwrap();
        let address = Address::<N>::try_from(ComputeKey::try_from(&private_key).unwrap()).unwrap();
        (private_key, address)
    }

    fn sample_request(rng: &mut TestRng) -> (PrivateKey<N>, Address<N>, Request<N>) {
        let (private_key, address) = key_and_address(rng);
        let request = sign(
            &private_key,
            "credits.aleo",
            "transfer_public",
            &[&address.to_string(), "1u64"],
            &TYPES,
            None,
            None,
            true,
            false,
            rng,
        )
        .unwrap();
        (private_key, address, request)
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let rng = &mut TestRng::fixed(0);
        let (_private_key, address, request) = sample_request(rng);

        assert!(verify(&request, &TYPES, true, None).unwrap());
        assert_eq!(*request.signer(), address);
        assert_eq!(request.program_id().to_string(), "credits.aleo");
        assert_eq!(request.function_name().to_string(), "transfer_public");
        assert_eq!(network_id(&request), N::ID);
        assert_eq!(
            input_strings(&request),
            vec![address.to_string(), "1u64".to_string()]
        );
    }

    #[test]
    fn verify_rejects_the_wrong_is_root() {
        // `is_root` is a `1field`/`0field` term inside the signature message, so a
        // request signed as root must not verify as a child call.
        let rng = &mut TestRng::fixed(1);
        let (_private_key, _address, request) = sample_request(rng);

        assert!(verify(&request, &TYPES, true, None).unwrap());
        assert!(!verify(&request, &TYPES, false, None).unwrap());
    }

    #[test]
    fn verify_ignores_declared_types_for_non_record_inputs() {
        // The type list is not a type check. `verify` dispatches on the stored
        // `InputID` variant, so declaring the second input private (when it was
        // signed public) still verifies — a trap for anyone porting the JS call.
        let rng = &mut TestRng::fixed(2);
        let (_private_key, _address, request) = sample_request(rng);

        assert!(verify(&request, &["address.private", "u64.private"], true, None).unwrap());
    }

    #[test]
    fn verify_rejects_a_type_count_mismatch() {
        // snarkVM zips `input_ids`/`inputs`/`input_types` with `zip_eq`, which
        // panics on a length mismatch. The wrapper turns that into an error so it
        // cannot abort a wasm module.
        let rng = &mut TestRng::fixed(3);
        let (_private_key, _address, request) = sample_request(rng);

        let error = verify(&request, &["address.public"], true, None).unwrap_err();
        assert!(
            format!("{error:#}").contains("Expected 2 input types"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn verify_rejects_a_wrong_record_name() {
        // Record inputs are the one place the declared type is used: the name goes
        // into the commitment, so renaming it breaks verification.
        let rng = &mut TestRng::fixed(4);
        let (private_key, address) = key_and_address(rng);
        let record = format!(
            "{{ owner: {address}.private, microcredits: 1u64.private, _nonce: 0group.public }}"
        );
        let types = ["credits.record", "address.public", "u64.public"];

        let request = sign(
            &private_key,
            "credits.aleo",
            "transfer_private",
            &[&record, &address.to_string(), "1u64"],
            &types,
            None,
            None,
            true,
            false,
            rng,
        )
        .unwrap();

        assert!(matches!(request.input_ids()[0], InputID::Record(..)));
        assert!(verify(&request, &types, true, None).unwrap());
        assert!(
            !verify(
                &request,
                &["other.record", "address.public", "u64.public"],
                true,
                None
            )
            .unwrap()
        );
    }

    #[test]
    fn verify_ignores_the_dynamic_flag() {
        // The wasm docs page omits `is_dynamic`; snarkVM stores it but never folds
        // it into the signature or the verification. Rebuilding the request with
        // the flag flipped therefore still verifies.
        let rng = &mut TestRng::fixed(5);
        let (_private_key, _address, request) = sample_request(rng);

        let flipped = Request::<N>::from((
            *request.signer(),
            *request.network_id(),
            *request.program_id(),
            *request.function_name(),
            request.input_ids().to_vec(),
            request.inputs().to_vec(),
            *request.signature(),
            *request.sk_tag(),
            *request.tvk(),
            *request.tcm(),
            *request.scm(),
            true,
        ));

        assert!(!request.is_dynamic());
        assert!(flipped.is_dynamic());
        assert!(verify(&flipped, &TYPES, true, None).unwrap());
    }

    #[test]
    fn json_and_bytes_round_trip() {
        let rng = &mut TestRng::fixed(6);
        let (_private_key, _address, request) = sample_request(rng);

        // The JSON keys are snarkVM's field names, not the JS getter names:
        // `program` / `function`, not `program_id` / `function_name`.
        let json = request.to_string();
        assert!(json.contains("\"program\""), "unexpected JSON: {json}");
        assert!(json.contains("\"function\""), "unexpected JSON: {json}");
        assert_eq!(Request::<N>::from_str(&json).unwrap(), request);

        let bytes = request.to_bytes_le().unwrap();
        assert_eq!(bytes[0], 2, "write_le always emits version 2");
        assert_eq!(Request::<N>::from_bytes_le(&bytes).unwrap(), request);
    }

    #[test]
    fn input_ids_are_typed_variants_not_tuples() {
        let rng = &mut TestRng::fixed(7);
        let (_private_key, _address, request) = sample_request(rng);

        let ids = request.input_ids();
        assert_eq!(ids.len(), 2);
        assert!(matches!(ids[0], InputID::Public(_)));
        assert!(matches!(ids[1], InputID::Public(_)));
        // Two different inputs hash to two different IDs.
        assert_ne!(ids[0].id(), ids[1].id());
    }

    #[test]
    fn commitments_follow_the_documented_relations() {
        let rng = &mut TestRng::fixed(8);
        let (private_key, address, request) = sample_request(rng);

        // tcm = Hash(tvk)
        assert_eq!(*request.tcm(), N::hash_psd2(&[*request.tvk()]).unwrap());

        // scm = Hash(signer.x, root_tvk), and root_tvk defaults to this request's tvk.
        let signer_x = address.to_x_coordinate();
        assert_eq!(
            *request.scm(),
            N::hash_psd2(&[signer_x, *request.tvk()]).unwrap()
        );

        // sk_tag comes from the graph key of the signer's view key.
        let view_key = ViewKey::<N>::try_from(&private_key).unwrap();
        assert_eq!(
            *request.sk_tag(),
            GraphKey::try_from(&view_key).unwrap().sk_tag()
        );

        // tpk is recomputed from the signature, never stored.
        assert_ne!(request.to_tpk(), Group::<N>::zero());
    }

    #[test]
    fn child_call_uses_the_root_tvk_in_scm() {
        // With an explicit root_tvk, scm commits to *that* tvk instead of this
        // request's own — the only difference between a root and a child request.
        let rng = &mut TestRng::fixed(9);
        let (private_key, address) = key_and_address(rng);
        let root_tvk = Field::<N>::from_str("1field").unwrap();

        let request = sign(
            &private_key,
            "credits.aleo",
            "transfer_public",
            &[&address.to_string(), "1u64"],
            &TYPES,
            Some(root_tvk),
            None,
            false,
            false,
            rng,
        )
        .unwrap();

        let signer_x = address.to_x_coordinate();
        assert_eq!(*request.scm(), N::hash_psd2(&[signer_x, root_tvk]).unwrap());
        assert!(verify(&request, &TYPES, false, None).unwrap());
    }

    #[test]
    fn sign_names_the_offending_input() {
        let rng = &mut TestRng::fixed(10);
        let (private_key, address) = key_and_address(rng);

        let error = sign(
            &private_key,
            "credits.aleo",
            "transfer_public",
            &[&address.to_string(), "not-a-value"],
            &TYPES,
            None,
            None,
            true,
            false,
            rng,
        )
        .unwrap_err();

        assert!(
            format!("{error:#}").contains("input #1"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn sign_rejects_a_length_mismatch() {
        let rng = &mut TestRng::fixed(11);
        let (private_key, address) = key_and_address(rng);

        let error = sign(
            &private_key,
            "credits.aleo",
            "transfer_public",
            &[&address.to_string()],
            &TYPES,
            None,
            None,
            true,
            false,
            rng,
        )
        .unwrap_err();

        assert!(
            format!("{error:#}").contains("expects 2 inputs"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn verify_reports_bad_type_strings_as_errors() {
        // A type string that does not parse is an error, not a `false` — otherwise
        // a typo would read as a successful rejection.
        let rng = &mut TestRng::fixed(12);
        let (_private_key, _address, request) = sample_request(rng);

        let error = verify(&request, &["address.nope", "u64.public"], true, None).unwrap_err();
        assert!(
            format!("{error:#}").contains("input type #0"),
            "unexpected error: {error:#}"
        );
    }
}
