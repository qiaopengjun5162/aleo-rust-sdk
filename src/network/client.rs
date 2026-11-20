//! Async REST + JSON-RPC transport for Aleo nodes.
//!
//! See [`super`] for the endpoint map and for the two Merkle-query types that
//! live alongside this client.

use anyhow::{Context, Result};
use serde_json::Value;
use snarkvm::prelude::{Network, Program, TestnetV0};
use std::str::FromStr;

use super::BROWSER_UA;
use crate::options::TESTNET_JSON_RPC_URL;

/// Polling schedule for [`AleoHttpClient::wait_for_confirmation_with`].
#[derive(Clone, Copy, Debug)]
pub struct ConfirmationPoll {
    /// Maximum number of checks.
    pub attempts: u32,
    /// Delay between checks. Not applied after the final attempt.
    pub interval: std::time::Duration,
}

impl Default for ConfirmationPoll {
    /// The production schedule: 30 checks, 5 seconds apart (~145s worst case).
    fn default() -> Self {
        Self {
            attempts: 30,
            interval: std::time::Duration::from_secs(5),
        }
    }
}

/// The `status` of a `/transaction/confirmed/{id}` body, if it has the shape
/// this SDK expects.
///
/// The endpoint only answers for transactions that are already in a block, so a
/// 2xx is the signal; requiring a non-empty `status` string on top of it is a
/// shape check, so that a proxy's 200 error page cannot be mistaken for a mined
/// transaction. A false positive here cannot be undone by waiting, a false
/// negative can.
///
/// # The status domain
///
/// `snarkvm-ledger-block`'s `ConfirmedTransaction` serialiser emits only
/// `accepted` or `rejected`, and its deserialiser fails on every other value, so
/// a node cannot produce a third status. Callers nevertheless match `accepted`
/// explicitly instead of treating "not `rejected`" as success.
///
/// # Why not `block_hash`
///
/// Until 0.11.x this looked for a top-level `block_hash` on `/transaction/{id}`.
/// Provable's v2 API answers that route with a bare transaction
/// (`type`/`id`/`execution`/`fee`) and never includes `block_hash` — verified
/// against both `mainnet` and `testnet`, on both `api.provable.com` and
/// `api.explorer.provable.com`, for mined transactions. The mock tests had
/// invented the field, so the check passed in CI and timed out against the real
/// network every single time.
fn confirmation_status(body: &str) -> Option<String> {
    serde_json::from_str::<Value>(body)
        .ok()?
        .get("status")?
        .as_str()
        .filter(|status| !status.is_empty())
        .map(str::to_owned)
}

/// HTTP client with browser-like headers for Aleo network interaction.
#[derive(Clone, Debug)]
pub struct AleoHttpClient {
    /// Base URL for REST endpoints (e.g. `https://api.explorer.provable.com/v2/testnet`)
    pub base_url: String,
    /// JSON-RPC endpoint (e.g. `https://testnetbeta.aleorpc.com`)
    rpc_url: String,
    inner: reqwest::Client,
}

/// Build the HTTP client every REST read uses.
///
/// Extracted so that [`AleoNetworkOptions`](crate::AleoNetworkOptions) can hand
/// out the same configuration — TLS and proxy handling below must not be
/// re-implemented by a second constructor, because the copy that drifts is the
/// one that keeps signing transactions while quietly skipping verification.
pub(crate) fn default_http_client() -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .http1_only()
        .timeout(std::time::Duration::from_secs(120));

    // Certificate verification is ON by default. Behind a corporate TLS
    // intercepting proxy you can opt out with ALEO_INSECURE_TLS=1 — but
    // never disable it silently: this client signs and broadcasts
    // transactions, so a MITM can steal funds.
    if std::env::var("ALEO_INSECURE_TLS").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
    {
        tracing::warn!("ALEO_INSECURE_TLS is set — TLS certificate verification is DISABLED");
        builder = builder.danger_accept_invalid_certs(true);
    }

    // Respect HTTP_PROXY / HTTPS_PROXY env vars (e.g. Clash at 127.0.0.1:7890).
    // No manual proxy detection needed — reqwest 0.12 respects these by default
    // when Proxy::system() is used. We set custom() to control exactly.
    if let Ok(proxy_url) = std::env::var("HTTP_PROXY")
        .or_else(|_| std::env::var("http_proxy"))
        .or_else(|_| std::env::var("HTTPS_PROXY"))
        .or_else(|_| std::env::var("https_proxy"))
        && let Ok(proxy) =
            reqwest::Proxy::http(&proxy_url).or_else(|_| reqwest::Proxy::all(&proxy_url))
    {
        builder = builder.proxy(proxy);
    }

    builder.build().context("Failed to build HTTP client")
}

impl AleoHttpClient {
    /// Create a new client pointing at an Aleo node (default RPC endpoint).
    ///
    /// # Errors
    ///
    /// Fails when the default HTTP client cannot be built.
    pub fn new(base_url: &str) -> Result<Self> {
        Self::new_with_rpc(base_url, TESTNET_JSON_RPC_URL)
    }

    /// Create a client with a custom RPC URL (useful for testing with wiremock).
    ///
    /// # Errors
    ///
    /// Fails when the default HTTP client cannot be built.
    pub fn new_with_rpc(base_url: &str, rpc_url: &str) -> Result<Self> {
        Ok(Self::with_http(base_url, rpc_url, default_http_client()?))
    }

    /// Create a client around an already-built [`reqwest::Client`].
    ///
    /// Lets a caller share one connection pool (and one timeout) with the rest
    /// of an application instead of keeping a pool per SDK client — see
    /// [`AleoNetworkOptions::with_http_client`](crate::AleoNetworkOptions::with_http_client).
    pub fn with_http(base_url: &str, rpc_url: &str, inner: reqwest::Client) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            rpc_url: rpc_url.trim_end_matches('/').to_string(),
            inner,
        }
    }

    fn headers() -> reqwest::header::HeaderMap {
        use reqwest::header::{ACCEPT, HeaderValue, USER_AGENT};
        let mut h = reqwest::header::HeaderMap::new();
        // Static literals go through `from_static`: no runtime parsing, no
        // `unwrap()`. `parse().unwrap()` on a constant is a latent panic that
        // a future edit to the constant would turn into a crash.
        h.insert(USER_AGENT, HeaderValue::from_static(BROWSER_UA));
        h.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/plain, */*"),
        );
        h
    }

    /// JSON headers (`Content-Type: application/json`) — required by both the
    /// JSON-RPC POST and the broadcast POST.
    fn json_headers() -> reqwest::header::HeaderMap {
        let mut headers = Self::headers();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        headers
    }

    /// Helper: JSON-RPC POST call.
    async fn json_rpc(&self, method: &str, params: Vec<Value>) -> Result<Value> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let resp = self
            .inner
            .post(&self.rpc_url)
            .headers(Self::json_headers())
            .json(&body)
            .send()
            .await?;
        let text = resp.text().await?;
        let v: Value = serde_json::from_str(&text).context("Failed to parse JSON-RPC response")?;

        if let Some(err) = v.get("error") {
            anyhow::bail!("JSON-RPC error ({method}): {err}");
        }
        v.get("result").cloned().context("JSON-RPC response missing result")
    }

    /// `GET url`, failing on any non-2xx instead of handing the error page to
    /// the caller.
    ///
    /// Without this check a failed request surfaces as whatever the parser
    /// makes of the error body — `fetch_block_height` on a 404 reports a
    /// `ParseIntError`, which points at the wrong layer.
    ///
    /// The same reasoning applies to the body itself, which is why a body that
    /// cannot be read and a body that arrives empty are both reported here
    /// rather than downstream. Reading the body used to swallow its error with
    /// `unwrap_or_default()`, so a dropped connection mid-body reached the
    /// caller as "did not return JSON" — an error naming the parser while the
    /// fault was in the transport. Both are errors to every caller of this
    /// function; the only question is which layer to blame.
    pub(crate) async fn get_text_checked(&self, url: &str) -> Result<String> {
        let resp = self
            .inner
            .get(url)
            .headers(Self::headers())
            .send()
            .await
            .with_context(|| format!("GET {url} failed"))?;
        let status = resp.status();
        let body = resp.text().await.with_context(|| {
            format!("GET {url} -> {status}: the response body could not be read")
        })?;
        if !status.is_success() {
            anyhow::bail!("GET {url} -> {status}: {}", crate::hosted::truncate(&body));
        }
        if body.trim().is_empty() {
            anyhow::bail!("GET {url} -> {status} with a 0-byte body; nothing to parse");
        }
        Ok(body)
    }

    /// `GET url`, parsed as JSON.
    pub(crate) async fn get_json(&self, url: &str) -> Result<Value> {
        let text = self.get_text_checked(url).await?;
        serde_json::from_str(&text).with_context(|| format!("GET {url} did not return JSON"))
    }

    /// `GET url` whose body must be a JSON *string* (`"at1…"`).
    ///
    /// The node pretty-prints these, so the quotes arrive verbatim. A body that
    /// is not a non-empty JSON string is an error rather than a value that
    /// happens to be quoted — an id that was never fetched must not look like
    /// one that was.
    pub(crate) async fn get_json_string(&self, url: &str) -> Result<String> {
        match self.get_json(url).await? {
            Value::String(s) if !s.is_empty() => Ok(s),
            other => anyhow::bail!("GET {url}: expected a JSON string, got {other}"),
        }
    }

    /// Fetch a program from the network (REST GET).
    ///
    /// # Errors
    ///
    /// Fails when the request fails, or when the body is not a valid program. An
    /// unknown id is an error, never an empty program.
    pub async fn fetch_program(&self, program_id: &str) -> Result<Program<TestnetV0>> {
        self.fetch_program_edition(program_id, None).await
    }

    /// Fetch a specific edition of a program (`None` = latest).
    ///
    /// The node serves `program/{id}/{edition}` for a pinned edition and
    /// `program/{id}` for the latest; both answer with the same program text.
    ///
    /// # Errors
    ///
    /// Fails when the request fails, or when the body is not a valid program. A
    /// pinned `edition` the node does not have is an error; pass `None` for the
    /// latest.
    pub async fn fetch_program_edition(
        &self,
        program_id: &str,
        edition: Option<u16>,
    ) -> Result<Program<TestnetV0>> {
        let url = match edition {
            Some(edition) => format!("{}/program/{program_id}/{edition}", self.base_url),
            None => format!("{}/program/{program_id}", self.base_url),
        };
        tracing::info!("GET {url}");
        let text = self.get_text_checked(&url).await?;

        // The node answers with a JSON string — `"program credits.aleo;\n…"` —
        // so the escapes have to be decoded exactly once. Hand-rolled
        // `trim_matches('"')` plus `replace("\\n", "\n")` decodes one escape
        // and silently leaves `\"`, `\\` and `\t` in place, which turns into a
        // parse error that names the program rather than the response.
        // A bare body is still accepted: that is what a plain-text node would
        // return, and refusing it would be a regression for no gain.
        let program_text = if text.trim_start().starts_with('"') {
            serde_json::from_str::<String>(&text)
                .with_context(|| format!("GET {url}: body is not a valid JSON string"))?
        } else {
            text
        };
        Program::<TestnetV0>::from_str(&program_text).context("Failed to parse program")
    }

    /// Fetch the latest block height together with the state root committed at
    /// that height (REST GET).
    ///
    /// ## Why the height is read first
    ///
    /// `/stateRoot/latest` and `/block/height/latest` are backed by caches that
    /// are **not** synchronised: sampling the live API showed the root lagging
    /// or leading the height by one block, in both directions. Reading both
    /// "latest" values and pairing them therefore produced a `(root, height)`
    /// pair that never existed on chain — and the pair is what
    /// [`AleoClient`](crate::AleoClient) uses to pick a consensus version and to
    /// seed [`ProvableQuery`](crate::ProvableQuery).
    ///
    /// Reading `H` first and then `root@H` instead gives a pair that is always
    /// internally consistent; a block mined in between only makes it one block
    /// stale, which is what a "latest" query means anyway.
    ///
    /// # Errors
    ///
    /// Fails when either the height or the root cannot be fetched. The pair is
    /// always internally consistent: the root is read at the height just returned,
    /// so a block mined in between only makes the answer one block stale.
    pub async fn fetch_state_root(&self) -> Result<(<TestnetV0 as Network>::StateRoot, u32)> {
        let height = self.fetch_block_height().await?;
        let state_root = self.fetch_state_root_at(height).await?;
        Ok((state_root, height))
    }

    /// Broadcast a JSON-serialized transaction (REST POST).
    ///
    /// Uses `?check_transaction=true` so the node runs `check_transaction_basic`
    /// and returns a detailed error message if the transaction is invalid,
    /// rather than silently dropping it after accepting the broadcast.
    ///
    /// The Cloud API at `api.explorer.provable.com/v2/testnet/transaction/broadcast` (singular)
    /// matches the snarkOS node REST route definition in `node/rest/src/lib.rs:337`.
    ///
    /// # Errors
    ///
    /// Fails when the node rejects the transaction, or when the body cannot be read.
    /// `check_transaction=true` makes the node run full validation first, so a
    /// rejection here is the verdict rather than a transport hiccup.
    pub async fn broadcast_transaction(&self, tx_json: String) -> Result<String> {
        let url = format!(
            "{}/transaction/broadcast?check_transaction=true",
            self.base_url
        );
        let mut headers = Self::json_headers();
        headers.insert(
            reqwest::header::ORIGIN,
            reqwest::header::HeaderValue::from_static("https://explorer.provable.com"),
        );
        headers.insert(
            reqwest::header::REFERER,
            reqwest::header::HeaderValue::from_static("https://explorer.provable.com/"),
        );

        let resp = self.inner.post(&url).headers(headers).body(tx_json).send().await?;
        let status = resp.status();
        // The body is the node's verdict and, on success, the transaction id —
        // so it is read with its error intact. `unwrap_or_default()` here used
        // to turn "the connection dropped mid-body" into `Ok("")`: a caller
        // would get an empty string where it expected an id, and a rejection
        // would report `400: ` with the reason silently blanked out.
        let body = resp.text().await.with_context(|| {
            format!("Broadcast to {url} -> {status}: the response body could not be read")
        })?;

        if !status.is_success() {
            anyhow::bail!("Broadcast rejected ({status}): {body}");
        }
        if body.trim().is_empty() {
            anyhow::bail!(
                "Broadcast to {url} -> {status} with a 0-byte body; \
                 the node accepted nothing and returned no transaction id"
            );
        }
        Ok(body)
    }

    /// Fetch a transaction by its ID and return the raw body.
    ///
    /// A non-2xx answer is an error: `/transaction/{id}` 404s for an id the node
    /// does not know, and handing that error body back as if it were a
    /// transaction only moves the failure into the deserializer, where it reads
    /// as "malformed transaction" instead of "unknown transaction".
    ///
    /// # Errors
    ///
    /// Fails for an unknown id (the route 404s) and for any other non-2xx. The body
    /// is returned verbatim, so an error page is never handed back as a transaction.
    pub async fn fetch_transaction(&self, tx_id: &str) -> Result<String> {
        let url = format!("{}/transaction/{tx_id}", self.base_url);
        self.get_text_checked(&url).await
    }

    /// Poll for confirmation with the production schedule (30 attempts, 5s apart).
    ///
    /// See [`Self::wait_for_confirmation_with`] for what counts as confirmed.
    ///
    /// # Errors
    ///
    /// Fails when the status endpoint errors, when the transaction is reported
    /// `rejected`, or when the schedule runs out (30 attempts, ~145 s).
    pub async fn wait_for_confirmation(&self, tx_id: &str) -> Result<()> {
        self.wait_for_confirmation_with(tx_id, ConfirmationPoll::default()).await
    }

    /// Poll for confirmation using an explicit schedule.
    ///
    /// Confirmation is read from `/transaction/confirmed/{id}`: that route
    /// answers 200 only once the transaction is in a block, and 404 while it is
    /// still in the mempool. A 200 additionally has to carry a `status` string,
    /// which rules out a proxy error page being mistaken for a mined
    /// transaction. See `confirmation_status` for why the previous
    /// `block_hash` check could never succeed against the live API.
    ///
    /// A transaction that is on chain but `rejected` by its finalize block is an
    /// error, not a success: the transfer did not happen, and reporting
    /// otherwise would send the caller on to spend records that no longer exist.
    /// Success requires the status to be exactly `accepted`; see
    /// `confirmation_status` for why no other value can appear today, and why
    /// the match is a whitelist regardless.
    ///
    /// The first check happens immediately; the interval only separates
    /// attempts. [`ConfirmationPoll`] is a parameter rather than a constant
    /// because the timeout path otherwise takes 150 seconds and cannot run in
    /// CI, which is how the previous version ended up `#[ignore]`d — present
    /// but never executed.
    ///
    /// # Errors
    ///
    /// Fails when the status endpoint errors, when the transaction is reported
    /// `rejected`, or when `poll.attempts` is exhausted. A 2xx without a `status`
    /// string, and a 2xx with any status other than `accepted`, keep polling
    /// rather than reporting a false confirmation: a false positive cannot be
    /// undone by waiting, a false negative can.
    pub async fn wait_for_confirmation_with(
        &self,
        tx_id: &str,
        poll: ConfirmationPoll,
    ) -> Result<()> {
        let check_url = format!("{}/transaction/confirmed/{tx_id}", self.base_url);
        tracing::info!(
            "Waiting for confirmation... ({} attempts, {:?} apart)",
            poll.attempts,
            poll.interval
        );

        // A body that cannot be read is treated as "no status yet" and the loop
        // keeps polling, matching the policy above for a 2xx without a status
        // string. It is remembered, though: if every attempt dies in the
        // transport, the terminal error must not read as a plain timeout.
        let mut unreadable_body: Option<String> = None;

        for attempt in 1..=poll.attempts {
            match self.inner.get(&check_url).headers(Self::headers()).send().await {
                Ok(res) if res.status().is_success() => {
                    match res.text().await {
                        Ok(body) => {
                            match confirmation_status(&body).as_deref() {
                                Some("accepted") => {
                                    tracing::info!("Confirmed on chain (status: accepted)!");
                                    tracing::info!(
                                        "🔗 https://testnet.explorer.provable.com/transaction/{tx_id}"
                                    );
                                    return Ok(());
                                }
                                Some("rejected") => anyhow::bail!(
                                    "Transaction {tx_id} is on chain but was rejected (status: rejected)"
                                ),
                                Some(other) => {
                                    // `ConfirmedTransaction` serialises only `accepted`
                                    // or `rejected`, and its deserialiser rejects every
                                    // other value, so this branch is unreachable
                                    // against a healthy node. It exists so that a future
                                    // third status reads as "not confirmed yet": a false
                                    // positive cannot be undone by waiting, a false
                                    // negative can.
                                    tracing::warn!(
                                        "unrecognised confirmation status `{other}` \
                                         (attempt {attempt}); still polling"
                                    );
                                }
                                None => {
                                    // A 200 whose body is not a confirmed-transaction
                                    // wrapper: keep polling rather than trusting the
                                    // status code alone.
                                    tracing::debug!(
                                        "200 without a status field (attempt {attempt})"
                                    );
                                }
                            }
                        }
                        Err(error) => {
                            tracing::debug!(
                                "confirmation body unreadable (attempt {attempt}): {error}"
                            );
                            unreadable_body = Some(error.to_string());
                        }
                    }
                }
                Ok(res) => {
                    // 404 is the normal "not mined yet" answer.
                    tracing::debug!("not yet confirmed ({}) on attempt {attempt}", res.status());
                }
                Err(error) => {
                    tracing::debug!("confirmation poll failed (attempt {attempt}): {error}");
                }
            }
            if attempt < poll.attempts {
                tokio::time::sleep(poll.interval).await;
            }
        }
        match unreadable_body {
            Some(error) => anyhow::bail!(
                "Timed out waiting for confirmation of {tx_id}; \
                 the last status response arrived but its body could not be read: {error}"
            ),
            None => anyhow::bail!("Timed out waiting for confirmation of {tx_id}"),
        }
    }

    // ── On-chain state queries ──────────────────────────────────────────

    /// GET a mapping entry and return the raw body, or `None` when the key is
    /// absent (the API answers 404).
    ///
    /// Both public mapping helpers below resolve to the *same* REST route and
    /// the same "4xx means absent" rule; the only difference between them is
    /// whether the body is parsed as a `u64`. This is the single place that
    /// knows the route, so the two cannot drift.
    pub(crate) async fn mapping_value_raw(
        &self,
        program_id: &str,
        mapping_name: &str,
        key: &str,
    ) -> Result<Option<String>> {
        let url = format!(
            "{}/program/{program_id}/mapping/{mapping_name}/{key}",
            self.base_url
        );
        let resp = self.inner.get(&url).headers(Self::headers()).send().await?;
        if resp.status().is_client_error() {
            return Ok(None); // 404 = no entry
        }
        Ok(Some(resp.text().await?))
    }

    /// Query a numeric mapping value (`credits.aleo/account`).
    ///
    /// A key that exists answers with a JSON string holding an Aleo literal —
    /// `"6630224u64"` — so the `u64` suffix is stripped and the remainder parsed
    /// as a [`u64`].
    ///
    /// # Errors
    ///
    /// Fails on any non-2xx other than 404, and when a 2xx body is not a `u64`
    /// literal. A 404 is `Ok(None)` by design — a missing key is not an error.
    ///
    /// A body that does not parse is **an error, not `Ok(None)`**. This route
    /// answers 2xx only for a key that exists, so a 2xx body that is not a
    /// `u64` means the response format changed. Reporting `None` there would
    /// answer "no balance" for a balance that does exist — the one failure mode
    /// a balance query must not have.
    pub async fn fetch_mapping_value_rest(
        &self,
        program_id: &str,
        mapping_name: &str,
        key: &str,
    ) -> Result<Option<u64>> {
        let Some(text) = self.mapping_value_raw(program_id, mapping_name, key).await? else {
            return Ok(None);
        };
        let literal = text.trim().trim_matches('"');
        let digits = literal.strip_suffix("u64").unwrap_or(literal);
        digits.parse::<u64>().map(Some).with_context(|| {
            format!(
                "GET {program_id}/mapping/{mapping_name}: expected a u64 literal, got {literal} \
                 — the response format changed; a missing key is a 404, not this"
            )
        })
    }

    /// Query a mapping value as its raw serialized string.
    ///
    /// Use this for mappings whose values are not `u64` (structs, addresses,
    /// other plaintext literals). Returns `None` on 404.
    ///
    /// # Errors
    ///
    /// Fails on any non-2xx other than 404. A 404 is `Ok(None)` by design.
    pub async fn fetch_mapping_value(
        &self,
        program_id: &str,
        mapping_name: &str,
        key: &str,
    ) -> Result<Option<String>> {
        self.mapping_value_raw(program_id, mapping_name, key).await
    }

    /// Fetch the current block height (REST GET).
    ///
    /// The body is a bare JSON integer (`23688766`), not a quoted string and not
    /// an object — see [`Self::fetch_state_root_only`] for the neighbouring
    /// endpoint that answers in a different shape.
    ///
    /// # Errors
    ///
    /// Fails on a non-2xx, or when the body is not a bare integer. The parse is
    /// strict for that reason: a proxy's 200 error page must not become height 0.
    pub async fn fetch_block_height(&self) -> Result<u32> {
        let url = format!("{}/block/height/latest", self.base_url);
        let text = self.get_text_checked(&url).await?;
        text.trim()
            .parse()
            .with_context(|| format!("GET {url}: block height is not a u32: {text}"))
    }

    /// Fetch the latest state root only (REST GET).
    ///
    /// Answers with a quoted JSON string (`"sr1…"`), so the quotes are stripped
    /// before parsing. Use [`Self::fetch_state_root_at`] when the root has to
    /// pair with a specific height.
    ///
    /// # Errors
    ///
    /// Fails on a non-2xx, or when the unquoted body is not a `StateRoot`.
    pub async fn fetch_state_root_only(&self) -> Result<<TestnetV0 as Network>::StateRoot> {
        let url = format!("{}/stateRoot/latest", self.base_url);
        let text = self.get_text_checked(&url).await?;
        <TestnetV0 as Network>::StateRoot::from_str(text.trim().trim_matches('"'))
            .context("Failed to parse state root")
    }

    /// Fetch the state root committed at `height` (REST GET).
    ///
    /// `/stateRoot/{height}` is the counterweight to the two desynchronised
    /// `latest` caches: it is indexed by height, so a height read from
    /// [`Self::fetch_block_height`] yields a pair that really existed. Heights
    /// past the node's tip answer 404; a non-numeric height answers 400.
    ///
    /// ## Which side of the block
    ///
    /// The root is the state **after** the block at that height executed, not
    /// the state it started from. Measured on the live testnet API over four
    /// consecutive heights:
    ///
    /// ```text
    /// /stateRoot/21637802  ==  block 21637803's header.previous_state_root
    /// /stateRoot/21637801  ==  block 21637802's header.previous_state_root
    /// /stateRoot/21637800  ==  block 21637801's header.previous_state_root
    /// /stateRoot/21637799  ==  block 21637800's header.previous_state_root
    /// ```
    ///
    /// So the "state root at height `h`" and block `h`'s own
    /// `header.previous_state_root` are different roots, one block apart. Read
    /// "committed at height `h`" as *produced by* block `h`; anything that means
    /// the pre-block state is block `h`'s `previous_state_root`.
    ///
    /// # Errors
    ///
    /// Fails with a 404 for a height past the node's tip and a 400 for a non-numeric
    /// one. Unlike the `statePath` family this endpoint does distinguish them, so the
    /// error text is worth reading rather than treating every failure as retryable.
    pub async fn fetch_state_root_at(
        &self,
        height: u32,
    ) -> Result<<TestnetV0 as Network>::StateRoot> {
        let url = format!("{}/stateRoot/{height}", self.base_url);
        let text = self.get_text_checked(&url).await?;
        <TestnetV0 as Network>::StateRoot::from_str(text.trim().trim_matches('"'))
            .with_context(|| format!("GET {url}: not a state root: {text}"))
    }

    /// Fetch unspent records by view key via JSON-RPC.
    ///
    /// # Errors
    ///
    /// Fails when the current height cannot be read, or when the JSON-RPC call fails.
    /// The window is the last 1 000 blocks from that height.
    pub async fn fetch_records(&self, view_key: &str) -> Result<String> {
        let height = self.fetch_block_height().await?;
        let start = height.saturating_sub(1000);

        let result = self
            .json_rpc(
                "records/isOwner",
                vec![
                    Value::String(view_key.to_string()),
                    Value::Number(serde_json::Number::from(start)),
                    Value::Number(serde_json::Number::from(height)),
                ],
            )
            .await?;

        Ok(serde_json::to_string_pretty(&result)?)
    }

    /// Fetch all records within a block range via JSON-RPC `records/all`.
    ///
    /// Returns raw record ciphertexts that must be decrypted with a view key —
    /// see [`RecordScanner`](crate::record::RecordScanner) for that half.
    ///
    /// # Errors
    ///
    /// Fails when a page cannot be fetched, or when the body is not an array. An
    /// empty array is a legitimate answer, so `Ok(vec![])` and a failure stay
    /// distinguishable.
    pub async fn fetch_all_records(
        &self,
        start: u32,
        end: u32,
        page: u32,
        per_page: u32,
    ) -> Result<Value> {
        let params = serde_json::json!({
            "start": start,
            "end": end,
            "page": page,
            "recordsPerRequest": per_page,
        });
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "records/all",
            "params": params,
        });

        let resp = self
            .inner
            .post(&self.rpc_url)
            .headers(Self::json_headers())
            .json(&body)
            .send()
            .await?;
        let text = resp.text().await?;
        let v: Value =
            serde_json::from_str(&text).context("Failed to parse records/all response")?;
        if let Some(err) = v.get("error") {
            anyhow::bail!("records/all error: {err}");
        }
        v.get("result").cloned().context("records/all response missing result")
    }

    // ── Stablecoin API methods ──────────────────────────────────────────

    /// Fetch the freeze list for a compliant stablecoin from the Provable API.
    ///
    /// Endpoint: `GET /v2/{network}/programs/{freeze_list_program_id}/compliance/freeze-list`
    ///
    /// `freeze_list_program_id` is the **freeze-list program**, not the token:
    /// `test_usdcx_freezelist.aleo` / `test_usad_freezelist.aleo` on testnet,
    /// `usdcx_freezelist.aleo` / `usad_freezelist.aleo` on mainnet. The route
    /// segment is `programs` (plural); the singular `/program/…` route has no
    /// `compliance` sub-resource and answers 404.
    ///
    /// The body is an array of decimal strings. The **last** element is the
    /// Merkle root — compare it against
    /// `/program/{freeze_list_program_id}/mapping/freeze_list_root/1u8` to tell
    /// whether the tree changed, which is how a cached exclusion proof is
    /// invalidated. Every element goes through
    /// `SealanceMerkleTree::convert_tree_to_fields`.
    ///
    /// Measured on both networks, 2026-11-19:
    ///
    /// ```text
    /// /v2/testnet/programs/test_usdcx_freezelist.aleo/compliance/freeze-list
    /// /v2/mainnet/programs/usdcx_freezelist.aleo/compliance/freeze-list
    ///   -> 200 ["0","0","3642222252059314292809609689035560016959342421640560347114299934615987159853"]
    /// /v2/testnet/program/test_usdcx_freezelist.aleo/mapping/freeze_list_root/1u8
    ///   -> 200 "3642222252059314292809609689035560016959342421640560347114299934615987159853field"
    /// ```
    ///
    /// This replaces `/stablecoin/{stablecoin}/merkle-tree`, which the published
    /// guide describes but the gateway does not serve: it answers
    /// `404 Cannot GET` on both networks, for every spelling of the name.
    ///
    /// # Errors
    ///
    /// Fails on a non-2xx, or when the body is not an array of decimal strings.
    pub async fn fetch_stablecoin_merkle_tree(
        &self,
        freeze_list_program_id: &str,
    ) -> Result<Vec<String>> {
        let url = format!(
            "{}/programs/{freeze_list_program_id}/compliance/freeze-list",
            self.base_url
        );
        tracing::info!("GET {url}");
        let text = self.get_text_checked(&url).await?;

        let tree: Vec<String> = serde_json::from_str(&text)
            .with_context(|| format!("GET {url}: body is not an array of decimal strings"))?;
        Ok(tree)
    }
}
