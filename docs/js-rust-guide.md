# From `@provablehq/sdk` to `aleo-rust-sdk`

A mapping guide for developers who know the JavaScript/TypeScript SDK and want
to do the same things in Rust.

- **Version:** `aleo-rust-sdk` 0.11.x (published on crates.io).
- **Scope:** the 32 pages of the `@provablehq/sdk` **WASM API Reference** site —
  the surface this crate ported in #51–#79. Wallet adapters, the Leo language
  and on-chain standards are out of scope.

```bash
cargo add aleo-rust-sdk
```

Requires Rust **1.96+** (snarkVM 4.12.0's MSRV).

---

## 1. Don't look for a function with the same name

The Rust side is not a method-by-method translation. The first question during
the port was always: **does snarkVM already have this type?**

| Upstream wasm shape | Rust approach | Representative pages |
|---|---|---|
| Thin wrapper over a native type (most of them) | Thin shell that forwards to snarkVM | Address / Signature / Authorization / Boolean / Field / Group / Scalar / ViewKey / ComputeKey / GraphKey |
| Bundle or untagged enum **owned by wasm** | A new generic container, because snarkVM has no equivalent | `ExecutionResponse` (#58), `KeyPair` (#61), `OfflineQuery` (#62), `ProvingRequest` (#77) |
| Convenience methods bolted onto a native type | Reuse the native type, do not build a parallel class | Integer Types (#74) use `U8..I128`; Hash Functions (#75) use the nine default domains |

🔴 The most useful rule: **a `get*` name does not mean read-only.** The test is
the upstream signature — `&self` versus `&mut self` / `Option::take()`. A
"one-shot key bag" like `KeyPair` really does give the key up in Rust; do not
treat it as an ordinary getter.

---

## 2. The mapping, by category

The left column is the JS capability; the right column is the entry point that
exists in this crate (all `pub`). `cargo doc --open` has the full signatures.

### Accounts and keys

| JS capability | Rust entry point | Notes |
|---|---|---|
| `new Account()` / restore from a private key | `AleoAccount::{new_random, from_private_key_str, from_seed}` | `account.rs`; also `address_str` / `private_key_str` / `view_key_str` |
| Address validation, address from a ProgramID | `Address::{verify, from_program_id, to_plaintext}` | `address.rs` |
| `PrivateKey.encrypt` / decrypt | `private_key::{encrypt_private_key, decrypt_private_key, new_encrypted}` | 🔴 **Two incompatible wire formats**: `account.rs` uses `aleo-enc-v1:` (AES-GCM); only `private_key.rs` matches the JS SDK |
| `ViewKey` decrypt / to address | `ViewKey::{from_private_key, decrypt, to_address, to_scalar, to_field}` | `view_key.rs`; `to_bytes_le` / `from_bytes_le` too |
| Sign / verify message bytes | `AleoAccount::{sign, verify}` | 🔴 **Not** `Signature::{sign_value, verify_value}` — that pair matches wasm's `Signature.signValue`, and the two paths do not accept each other's signatures |
| Record / transition view keys | `AleoAccount::{generate_record_view_key, generate_transition_view_key, decrypt_record, decrypt_records, owns_record_ciphertext}` | `account.rs` |
| Record scanner helpers | `scanner::RecordScanService`, `encryption::{decrypt_owned_records, decrypt_record_with_rvk, decrypt_sender, decrypt_transition_with_tvk}` | see §4 |

### Records

| JS capability | Rust entry point | Notes |
|---|---|---|
| `RecordPlaintext` members | `RecordPlaintext::{owner, get_member, microcredits, nonce, commitment, tag, serial_number_string, record_view_key, decrypt_sender, gamma}` | `record_plaintext.rs`; `to_js_object` mirrors JS `toJsObject` |
| Serialization | `RecordPlaintext::{from_string, to_bytes_le, from_bytes_le, to_bits_le, to_fields}` | same module |
| `RecordCiphertext` decrypt / ownership | `RecordCiphertext::{decrypt, is_owner, tag, nonce, decrypt_with_record_view_key, record_view_key}` | `record_ciphertext.rs` |

### Programs and transactions

| JS capability | Rust entry point | Notes |
|---|---|---|
| `Program` source / id | `Program::{from_source, from_local_file, credits, id, address, inner, into_inner}` | `program.rs` |
| `getFunctions` / `getMappings` / `getImports` and 10 more | `program_parity::{get_functions, get_function_inputs, get_mappings, get_record_members, get_struct_members, get_imports, has_function, is_equal, ...}` | 🔴 Five methods from the full upstream manual are **not** implemented: `isArc20`, `isArc22`, `getCallGraph`, `nameToField`, `toChecksum` — see §6 |
| `Transaction` parsing and queries | `Transaction::{from_string, from_bytes_le, to_bytes_le, id, transaction_type, transitions, execution, deployed_program, is_deploy, is_execute, is_fee, fee_amount, base_fee_amount, priority_fee_amount, find_record, contains_serial_number, contains_commitment, owned_records, records, summary}` | `transaction.rs` |
| `Execution` / `ExecutionRequest` / `ExecutionResponse` | `execution.rs`, `execution_request.rs`, `execution_response.rs` | `ExecutionResponse` is a new generic container |
| `ProvingKey` / `VerifyingKey` | Same-named modules, with bech32m `prover1…` / `verifier1…` `Display` / `FromStr` / `ToBytes` | `VerifyingKey::from_bytes_le` comes from the **`FromBytes`** trait — `use snarkvm::prelude::FromBytes` |
| `Metadata` (parameter URL catalogue) | `metadata::{base_url, transfer_public, fee_public, bond_public, to_json_value, ...}` | Static URLs; nothing is downloaded |

### Hashes, integers, utilities

| JS capability | Rust entry point |
|---|---|
| `hashBHP256` / `hashPedersen64` / `hashPoseidon2` — the nine default domains | `hash_functions::{bhp256, bhp512, bhp768, bhp1024, pedersen64, pedersen128, poseidon2, poseidon4, poseidon8}` |
| Integer `toXxxLossy` / `toPlaintext` / `toBooleanLossy` | `integer_types::{cast_lossy, to_plaintext, to_boolean_lossy}` (one generic covers all ten widths) |
| `Plaintext.toObject` / type queries | `plaintext::{to_json_value, plaintext_type, to_bytes_raw_le, to_bytes_raw_be}` |
| `getOrInitConsensusVersionTestHeights` | `utility_functions::consensus_version_test_heights` (22 versions, V1–V22) |
| `initThreadPool` | `utility_functions::init_thread_pool` — a **no-op natively** (only wasm-rayon needs it) |
| `verifyFunctionExecution` | `utility_functions::verify_function_execution` (`Ok(false)` means the proof is invalid; that is not an error) |

---

## 3. Minimal runnable examples

### Read chain state (no private key)

```rust
use aleo_rust_sdk::AleoClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = AleoClient::new("https://api.provable.com/v2/testnet")?;
    println!("height: {}", client.get_block_height().await?);
    println!("state root: {}", client.get_state_root().await?);
    Ok(())
}
```

### Create an account and read its balance

```rust
use aleo_rust_sdk::{AleoAccount, AleoClient};
use snarkvm::prelude::TestRng;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut rng = TestRng::default();
    let account = AleoAccount::new_random(&mut rng)?;
    let mut client = AleoClient::new("https://api.provable.com/v2/testnet")?;
    client.set_account_from_private_key_str(&account.private_key_str())?;
    println!("address: {}", account.address_str());
    println!("balance: {:?}", client.get_balance().await?);
    Ok(())
}
```

### Public transfer

```rust
use aleo_rust_sdk::AleoClient;
use snarkvm::console::program::ProgramID;
use std::str::FromStr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut client = AleoClient::new("https://api.provable.com/v2/testnet")?;
    client.set_account_from_private_key_str("APrivateKey1...")?;
    let tx_id = client.execute_and_broadcast(
        &client.require_account()?.private_key,
        &ProgramID::from_str("credits.aleo")?,
        "transfer_public",
        vec!["aleo1recipient...", "1000000u64"],
        0,
    ).await?;
    println!("{tx_id}");
    Ok(())
}
```

### Waiting for confirmation

A broadcast that returns HTTP 200 is **not** on chain — it means the node
accepted the transaction into its mempool.

```rust
client.wait_for_confirmation(&tx_id).await?;
```

`wait_for_confirmation` polls `/transaction/confirmed/{id}`: that route answers
404 while the transaction is pending and 200 with a `{status, type, index,
transaction, finalize}` wrapper once it is in a block. A `rejected` status is an
error, because the transaction is on chain but its finalize block refused it.

> **0.11.0 known issue.** The published 0.11.0 polled `/transaction/{id}` and
> required a top-level `block_hash`, which the v2 API never returns for that
> route, so every real transaction timed out after 30 attempts. If you are on
> 0.11.0, use `fetch_confirmed_transaction(&tx_id)` instead (200 once mined, 404
> while pending) or upgrade to the next patch release.

---

## 4. Network and auth configuration

`AleoNetworkOptions` takes a network name once and derives the rest; every
service URL can be overridden individually.

```rust
use aleo_rust_sdk::{AleoNetworkOptions, ApiAuth};

let options = AleoNetworkOptions::testnet()
    .with_auth(ApiAuth::None);           // free tier, the default
let url = options.rest_url();            // .../v2/testnet
```

| Item | Notes |
|---|---|
| `PROVABLE_REST_BASE` | `https://api.explorer.provable.com/v2` (no network segment); `api.provable.com/v2` is the same service |
| v2 vs v1 | **v2 is recommended** (a superset of v1 plus indexed data); v1 is still online and `with_rest_base(".../v1")` switches without touching any other code |
| `x-api-key` | **Optional rate-limit boost, not a requirement.** The Explorer API's free tier needs no key and is not metered; only Delegated Proving / Record Scanning differ (90 → 300 / 1000 requests per minute) |
| `ApiAuth` | `None` / `ApiKey { value, header }` (default header `X-API-Key`; header names are case-insensitive) / `Jwt` |
| `ApiAuth::Jwt` | **Deprecated upstream.** Kept for compatibility, never used by default — do not pick it in new code |

`AleoHttpClient` sends no key on plain REST reads. That is the intended design,
not a missing feature.

---

## 5. The six differences that bite

| # | Symptom | What to do |
|---|---|---|
| 1 | Encryption signatures do not match | snarkVM 4.12 uses **rand 0.10**; an `OsRng` from a project on `rand = 0.8` does not satisfy `Rng + CryptoRng` → **inject the RNG**, do not add argument-free convenience wrappers |
| 2 | `Field::inverse()` gives the wrong answer | `inverse()` on `Field` / `Scalar` is the **additive** inverse (negation); only `Group` has a multiplicative one. `Group::scalar_multiply` does not exist — write `group * scalar` |
| 3 | `i128` / `u128` JSON changed | They serialize as **strings**, not numbers |
| 4 | BHP `hashToGroup` is missing | BHP does not implement `HashToGroup`; use `HashUncompressed::hash_uncompressed`. An empty input returns the identity — Poseidon's same-named method errors instead |
| 5 | Cross-width casts look wrong | The "checked" operations (`AbsChecked`, `Rem`) `E::halt`, i.e. **panic**, rather than returning `Result`; and widening does **not** sign-extend (`-1i8` → `255i32`) |
| 6 | `Program::from_str` fails | `import` statements must come **before** the program declaration, and literals need explicit suffixes such as `u64.private` |

One engineering note: `cargo check`, `cargo clippy` without `--tests`, and
rustdoc **do not compile `#[cfg(test)]` modules**. Run `cargo test` separately
after editing tests.

---

## 6. Boundaries

Listed honestly so nobody arrives from the JS docs and finds nothing:

- **Five methods from the full upstream `Program` manual are not implemented**
  (`isArc20`, `isArc22`, `getCallGraph`, `nameToField`, `toChecksum`). They are
  not on the WASM API Reference pages, so they are a scope difference; only the
  "complete manual" reading would require them.
- **v2's indexed explorer data** (metrics, staking, DeFi, provers, address
  history, `Explorer*`, BigQuery, Health) is not wrapped. This crate is a
  chain-data and cryptography kernel, not a block explorer.
- **Record autojoin orchestration and end-to-end USDCx bridging** are wallet/
  application responsibilities. The crate ships the off-chain primitives
  (`circle::generate_hook_data`, `sealance::generate_exclusion_proof`, Merkle
  tree fetching), not the bridge workflow.
- Coverage is measured over all of `src/` from lcov; the CI gate is 87%. The
  uncovered lines are paths that need a live network or real circuit synthesis.
