//! # Endpoint configuration — one network name, every service base.
//!
//! This crate talks to five distinct endpoints. Before this module each one was
//! configured by a different constructor, and the *network* was spelled out
//! independently in four of them:
//!
//! | Service | Constructor | Where the network was named |
//! |---------|-------------|-----------------------------|
//! | REST (blocks, programmes, broadcast) | `AleoHttpClient::new(url)` | inside `url` (`…/v2/testnet`) |
//! | JSON-RPC (`records/*`) | `AleoHttpClient::new_with_rpc(url, rpc)` | inside `url` |
//! | Delegated proving (TEE) | `DelegatedProver::new(network, auth)` | a bare argument |
//! | Record scanning (TEE) | `RecordScanService::new(network, auth)` | a bare argument |
//!
//! Nothing tied those four together, so switching to mainnet meant editing four
//! call sites, and any one of them left behind produced a client that quietly
//! queried the wrong chain. [`AleoNetworkOptions`] makes the network a single
//! value and derives every service base from it.
//!
//! ## Relationship to the JavaScript SDK
//!
//! The shape follows `AleoNetworkClientOptions` in Provable's JS SDK: the
//! service URIs are stored **without** the network segment, which is appended
//! when the client is built — `proverUri: "https://prover.provable.prove"`
//! becomes `…/testnet`. The JS SDK does that by substituting a
//! `%%NETWORK%%` placeholder at bundle time; here it is
//! `format!("{base}/{network}")` at run time, so one binary can serve both
//! networks.
//!
//! Two deliberate differences:
//!
//! - **`api_origin` is an explicit field.** The JS SDK derives the JWT mint
//!   origin from `host` (`new URL(host).origin`). That derivation is wrong for
//!   Provable's default deployment: REST lives on
//!   `https://api.explorer.provable.com/v2` while JWTs are minted at
//!   `https://api.provable.com`, a *different* origin. Deriving would mint
//!   against the wrong host, so the origin is stated instead of guessed.
//! - **The JSON-RPC endpoint has no network segment.** Its network is baked
//!   into the hostname (`testnetbeta.aleorpc.com`), and there is no mainnet
//!   counterpart, so it is an `Option` that [`AleoNetworkOptions::new`] only
//!   fills for testnet.
//!
//! ## Transport
//!
//! The JS SDK's `transport` option swaps the `fetch` implementation. The
//! equivalent here is supplying the [`reqwest::Client`] itself
//! ([`AleoNetworkOptions::with_http_client`]): one connection pool, one timeout,
//! one proxy setting shared by the REST client and both TEE services. Without
//! it each service builds — and keeps — its own pool.
//!
//! ```no_run
//! use aleo_rust_sdk::{AleoNetworkOptions, ApiAuth};
//!
//! # async fn run() -> anyhow::Result<()> {
//! // Stated once, chainable: auth applies to both hosted services.
//! let options = AleoNetworkOptions::testnet().with_auth(ApiAuth::None);
//!
//! let http = options.http_client()?;
//! println!("REST base: {}", http.base_url);
//!
//! // The same options build the two hosted clients, too.
//! let prover = options.prover()?;
//! let scanner = options.scanner()?;
//! # let _ = (prover, scanner);
//! # Ok(())
//! # }
//! ```

use anyhow::{Context, Result, bail};
use std::fmt;

use crate::client::AleoClient;
use crate::delegated::DelegatedProver;
use crate::hosted::ApiAuth;
use crate::network::AleoHttpClient;
use crate::scanner::RecordScanService;

/// REST base of Provable's v2 API, **without** the trailing network segment.
///
/// Appending `/{network}` gives the base every REST read uses, e.g.
/// `https://api.explorer.provable.com/v2/testnet`.
pub const PROVABLE_REST_BASE: &str = "https://api.explorer.provable.com/v2";

/// JSON-RPC endpoint for testnet, used by `records/isOwner` and `records/all`.
///
/// A **complete** URL rather than a base: the network is part of the hostname,
/// so no segment is appended. There is no mainnet equivalent — the hostname
/// `mainnetbeta.aleorpc.com` does not accept connections — which is why
/// [`AleoNetworkOptions`] only defaults this for testnet.
pub const TESTNET_JSON_RPC_URL: &str = "https://testnetbeta.aleorpc.com";

/// Prover base of the Delegated Proving Service, without the network segment.
pub const PROVABLE_PROVER_BASE: &str = "https://prover.provable.prove";

/// Record-scanning base, without the network segment.
pub const PROVABLE_SCANNER_BASE: &str = "https://api.provable.com/scanner";

/// Origin that mints JWTs for the legacy `api.provable.com` gateway.
///
/// Not derivable from [`PROVABLE_REST_BASE`]: that host is
/// `api.explorer.provable.com`, a different origin from the one that signs
/// tokens.
pub const PROVABLE_API_ORIGIN: &str = "https://api.provable.com";

/// Every endpoint the SDK talks to, plus the network they share.
///
/// Construct with [`Self::testnet`] for a working default, or [`Self::new`]
/// with another network name, then override whatever is self-hosted.
///
/// The three service bases ([`Self::rest_base`], [`Self::prover_base`],
/// [`Self::scanner_base`]) are stored **without** a network segment; the
/// accessors that return a usable URL [`Self::rest_url`],
/// [`Self::prover_url`] and [`Self::scanner_url`] append it.
#[derive(Clone)]
pub struct AleoNetworkOptions {
    network: String,
    rest_base: String,
    rpc_url: Option<String>,
    prover_base: String,
    scanner_base: String,
    api_origin: String,
    auth: ApiAuth,
    http: Option<reqwest::Client>,
}

impl AleoNetworkOptions {
    /// Options for `network` (`"testnet"` or `"mainnet"`), using Provable's
    /// hosted endpoints.
    ///
    /// The JSON-RPC endpoint is only filled for testnet, because no mainnet
    /// one exists; [`Self::http_client`] reports that rather than silently
    /// pointing at the testnet node.
    ///
    /// # Errors
    ///
    /// Fails if `network` is empty, or is not a single path segment (it becomes
    /// one when the service bases are built, so `"a/b"` would silently address
    /// a different route).
    pub fn new(network: impl Into<String>) -> Result<Self> {
        let network = network.into();
        if network.is_empty() {
            bail!("network must not be empty");
        }
        if network.contains('/') || network.chars().any(char::is_whitespace) {
            bail!("network must be a single path segment, got `{network}`");
        }
        Ok(Self {
            rpc_url: (network == "testnet").then(|| TESTNET_JSON_RPC_URL.to_string()),
            rest_base: PROVABLE_REST_BASE.to_string(),
            prover_base: PROVABLE_PROVER_BASE.to_string(),
            scanner_base: PROVABLE_SCANNER_BASE.to_string(),
            api_origin: PROVABLE_API_ORIGIN.to_string(),
            auth: ApiAuth::None,
            http: None,
            network,
        })
    }

    /// Options for testnet with every default filled in.
    pub fn testnet() -> Self {
        Self::new("testnet").expect("`testnet` passes `new`'s segment checks")
    }

    // ── Reads ────────────────────────────────────────────────────────────

    /// The network this configuration targets.
    pub fn network(&self) -> &str {
        &self.network
    }

    /// REST base without the network segment.
    pub fn rest_base(&self) -> &str {
        &self.rest_base
    }

    /// REST base with the network segment appended — the value
    /// [`AleoHttpClient`] takes.
    pub fn rest_url(&self) -> String {
        join(&self.rest_base, &self.network)
    }

    /// The JSON-RPC endpoint, when one is known for this network.
    pub fn rpc_url(&self) -> Option<&str> {
        self.rpc_url.as_deref()
    }

    /// Prover base without the network segment.
    pub fn prover_base(&self) -> &str {
        &self.prover_base
    }

    /// Prover base with the network segment appended.
    pub fn prover_url(&self) -> String {
        join(&self.prover_base, &self.network)
    }

    /// Record-scanner base without the network segment.
    pub fn scanner_base(&self) -> &str {
        &self.scanner_base
    }

    /// Record-scanner base with the network segment appended.
    pub fn scanner_url(&self) -> String {
        join(&self.scanner_base, &self.network)
    }

    /// Origin used to mint JWTs.
    pub fn api_origin(&self) -> &str {
        &self.api_origin
    }

    /// How the hosted services authenticate.
    pub fn auth(&self) -> &ApiAuth {
        &self.auth
    }

    /// The auth mode's name, safe to log.
    pub fn auth_kind(&self) -> &'static str {
        match &self.auth {
            ApiAuth::None => "none",
            ApiAuth::ApiKey { .. } => "api-key",
            ApiAuth::Jwt { .. } => "jwt",
        }
    }

    /// Whether an explicit [`reqwest::Client`] was supplied.
    pub fn has_custom_http_client(&self) -> bool {
        self.http.is_some()
    }

    // ── Overrides ────────────────────────────────────────────────────────

    /// Point REST reads at another base (still without the network segment).
    pub fn with_rest_base(mut self, base: impl Into<String>) -> Self {
        self.rest_base = base.into();
        self
    }

    /// Set the JSON-RPC endpoint. Required for any network other than testnet.
    pub fn with_rpc_url(mut self, url: impl Into<String>) -> Self {
        self.rpc_url = Some(url.into());
        self
    }

    /// Point delegated proving at another base (without the network segment).
    pub fn with_prover_base(mut self, base: impl Into<String>) -> Self {
        self.prover_base = base.into();
        self
    }

    /// Point record scanning at another base (without the network segment).
    pub fn with_scanner_base(mut self, base: impl Into<String>) -> Self {
        self.scanner_base = base.into();
        self
    }

    /// Override the JWT mint origin (a self-hosted gateway mints elsewhere).
    pub fn with_api_origin(mut self, origin: impl Into<String>) -> Self {
        self.api_origin = origin.into();
        self
    }

    /// How the hosted prover and scanner should authenticate.
    pub fn with_auth(mut self, auth: ApiAuth) -> Self {
        self.auth = auth;
        self
    }

    /// Share one [`reqwest::Client`] across REST, proving, and scanning.
    ///
    /// Without this each service builds its own pool, and its own timeout.
    /// The supplied client is used verbatim, so its timeout applies to the TEE
    /// calls too — set it for the slowest service, or leave it out and let each
    /// service keep its tuned default (120s for all three).
    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.http = Some(http);
        self
    }

    // ── Builders ─────────────────────────────────────────────────────────

    /// Build the REST + JSON-RPC client these options describe.
    ///
    /// # Errors
    ///
    /// Fails when no JSON-RPC endpoint is known for the network (see
    /// [`Self::with_rpc_url`]), or when the default HTTP client cannot be
    /// constructed.
    pub fn http_client(&self) -> Result<AleoHttpClient> {
        let rpc = self.rpc_url.as_deref().with_context(|| {
            format!(
                "no JSON-RPC endpoint is known for network `{}`; call `with_rpc_url(..)`",
                self.network
            )
        })?;
        let inner = match &self.http {
            Some(client) => client.clone(),
            None => crate::network::default_http_client()?,
        };
        Ok(AleoHttpClient::with_http(&self.rest_url(), rpc, inner))
    }

    /// Build the delegated-proving client these options describe.
    pub fn prover(&self) -> Result<DelegatedProver> {
        DelegatedProver::with_endpoints_and_http(
            self.prover_url(),
            &self.api_origin,
            self.auth.clone(),
            self.http.clone(),
        )
    }

    /// Build the record-scanning client these options describe.
    pub fn scanner(&self) -> Result<RecordScanService> {
        RecordScanService::with_endpoints_and_http(
            self.scanner_url(),
            &self.api_origin,
            self.auth.clone(),
            self.http.clone(),
        )
    }

    /// Build a high-level [`AleoClient`] wired to these endpoints.
    pub fn client(&self) -> Result<AleoClient> {
        Ok(AleoClient::with_network(self.http_client()?))
    }
}

impl Default for AleoNetworkOptions {
    /// Testnet, matching the JS SDK's default deployment.
    fn default() -> Self {
        Self::testnet()
    }
}

/// Deliberately opaque: printing the options must not print the API key.
///
/// `ApiAuth` itself redacts its secrets (see its `Debug`), but ordering a
/// config dump through a derive here would re-expose whatever that type grows
/// next, so the fields are listed one by one.
impl fmt::Debug for AleoNetworkOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AleoNetworkOptions")
            .field("network", &self.network)
            .field("rest_url", &self.rest_url())
            .field("rpc_url", &self.rpc_url)
            .field("prover_url", &self.prover_url())
            .field("scanner_url", &self.scanner_url())
            .field("api_origin", &self.api_origin)
            .field("auth", &self.auth_kind())
            .field("custom_http_client", &self.http.is_some())
            .finish()
    }
}

/// Append the network segment to a base, tolerating a trailing slash.
fn join(base: &str, network: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), network)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testnet_fills_every_default() {
        let options = AleoNetworkOptions::testnet();
        assert_eq!(options.network(), "testnet");
        assert_eq!(
            options.rest_url(),
            "https://api.explorer.provable.com/v2/testnet"
        );
        assert_eq!(
            options.prover_url(),
            "https://prover.provable.prove/testnet"
        );
        assert_eq!(
            options.scanner_url(),
            "https://api.provable.com/scanner/testnet"
        );
        assert_eq!(options.rpc_url(), Some(TESTNET_JSON_RPC_URL));
        assert_eq!(options.api_origin(), "https://api.provable.com");
        assert_eq!(options.auth_kind(), "none");
        assert!(!options.has_custom_http_client());
    }

    #[test]
    fn every_service_base_shares_one_network_segment() {
        // The whole point of the type: four URLs, one network string.
        for network in ["testnet", "mainnet"] {
            let options = AleoNetworkOptions::new(network).unwrap();
            for url in [options.rest_url(), options.prover_url(), options.scanner_url()] {
                assert!(
                    url.ends_with(&format!("/{network}")),
                    "`{url}` does not end in `/{network}`"
                );
            }
        }
    }

    #[test]
    fn rpc_default_only_exists_for_testnet() {
        assert_eq!(
            AleoNetworkOptions::new("mainnet").unwrap().rpc_url(),
            None,
            "there is no mainnet JSON-RPC host, so no default may be invented"
        );
    }

    #[test]
    fn mainnet_without_rpc_cannot_build_a_http_client() {
        let err = AleoNetworkOptions::new("mainnet")
            .unwrap()
            .http_client()
            .unwrap_err()
            .to_string();
        assert!(err.contains("with_rpc_url"), "unhelpful error: {err}");
    }

    #[test]
    fn mainnet_with_an_explicit_rpc_builds() {
        let client = AleoNetworkOptions::new("mainnet")
            .unwrap()
            .with_rpc_url("https://rpc.example")
            .http_client()
            .unwrap();
        assert_eq!(
            client.base_url,
            "https://api.explorer.provable.com/v2/mainnet"
        );
    }

    #[test]
    fn bases_tolerate_a_trailing_slash() {
        let options = AleoNetworkOptions::testnet()
            .with_rest_base("https://rest.example/v1/")
            .with_prover_base("https://prover.example/")
            .with_scanner_base("https://scanner.example/");
        assert_eq!(options.rest_url(), "https://rest.example/v1/testnet");
        assert_eq!(options.prover_url(), "https://prover.example/testnet");
        assert_eq!(options.scanner_url(), "https://scanner.example/testnet");
    }

    #[test]
    fn rejects_networks_that_are_not_one_path_segment() {
        for bad in ["", "test/net", "test net", " testnet"] {
            assert!(
                AleoNetworkOptions::new(bad).is_err(),
                "`{bad}` should have been rejected"
            );
        }
    }

    #[test]
    fn auth_kind_names_the_mode_without_leaking_it() {
        let options = AleoNetworkOptions::testnet().with_auth(ApiAuth::api_key("secret-key"));
        assert_eq!(options.auth_kind(), "api-key");
        let printed = format!("{options:?}");
        assert!(
            !printed.contains("secret-key"),
            "Debug leaked the key: {printed}"
        );
        assert!(printed.contains("api-key"));
    }

    #[test]
    fn api_auth_debug_redacts_secrets() {
        // The options' Debug lists the mode name, but `ApiAuth` is printed on
        // its own elsewhere (e.g. by `AuthProvider`), so it must redact too.
        let api_key = format!("{:?}", ApiAuth::api_key("secret-key"));
        assert!(
            !api_key.contains("secret-key"),
            "ApiAuth::Debug leaked: {api_key}"
        );

        let jwt = format!("{:?}", ApiAuth::jwt("secret-key", "consumer-1"));
        assert!(!jwt.contains("secret-key"), "ApiAuth::Debug leaked: {jwt}");
        assert!(
            jwt.contains("consumer-1"),
            "the non-secret half should stay: {jwt}"
        );
    }

    #[test]
    fn debug_shows_the_resolved_urls() {
        let printed = format!("{:?}", AleoNetworkOptions::testnet());
        assert!(printed.contains("https://api.explorer.provable.com/v2/testnet"));
        assert!(printed.contains("https://prover.provable.prove/testnet"));
        assert!(printed.contains("https://api.provable.com/scanner/testnet"));
    }
}
