//! HTTP session shared by all sources for one target domain.
//!
//! * One [`reqwest::Client`] (connection pool) is built per run with
//!   [`build_client`] and shared by every domain and source.
//! * A [`Session`] wraps that client with the per-domain [`Extractor`], the
//!   shared [`RateLimiter`], and the run's limits ([`SessionOptions`]).
//! * Response bodies are read through [`Session::read_body`], which stops at
//!   `max_body_size` bytes. This protects against huge or endless bodies and
//!   decompression bombs (the cap applies to the *decoded* bytes).

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use rand::seq::SliceRandom;

use super::Extractor;
use crate::passive::RateLimiter;

/// Browser-like User-Agent strings, one is picked at random per request.
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
];

/// Pick a random User-Agent string.
pub fn random_user_agent() -> &'static str {
    USER_AGENTS
        .choose(&mut rand::thread_rng())
        .copied()
        .unwrap_or(USER_AGENTS[0])
}

/// Build the shared HTTP client.
///
/// * `proxy`: optional `http://`, `https://` or `socks5://` proxy URL.
/// * `timeout`: per-request timeout (also used as connect timeout).
///
/// Certificate validation is disabled, matching subfinder: several public
/// sources serve broken certificate chains, and the data is untrusted text
/// that is validated afterwards anyway.
pub fn build_client(proxy: Option<&str>, timeout: Duration) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .pool_max_idle_per_host(100)
        .pool_idle_timeout(Duration::from_secs(90))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(10));

    if let Some(proxy) = proxy.filter(|p| !p.is_empty()) {
        let proxy =
            reqwest::Proxy::all(proxy).with_context(|| format!("invalid proxy URL {proxy}"))?;
        builder = builder.proxy(proxy);
    }

    builder.build().context("could not build HTTP client")
}

/// Limits and switches that apply to every source in a run.
#[derive(Debug, Clone)]
pub struct SessionOptions {
    /// Per-request timeout.
    pub timeout: Duration,
    /// Maximum bytes read from a response body (`0` = unlimited).
    pub max_body_size: usize,
    /// Maximum results per source (`0` = unlimited). Honored by paginating sources.
    pub max_results: usize,
    /// `true` when the user passed `-all` (some sources lift internal limits).
    pub all_sources: bool,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_body_size: 0,
            max_results: 0,
            all_sources: false,
        }
    }
}

/// HTTP session for one target domain.
pub struct Session {
    pub(crate) client: reqwest::Client,
    pub(crate) limiter: Option<Arc<RateLimiter>>,
    pub(crate) extractor: Extractor,
    pub(crate) options: SessionOptions,
}

impl Session {
    /// Create a session for `domain`.
    pub fn new(
        domain: &str,
        client: reqwest::Client,
        limiter: Option<Arc<RateLimiter>>,
        options: SessionOptions,
    ) -> anyhow::Result<Self> {
        let extractor = Extractor::new(domain).context("could not build subdomain extractor")?;
        Ok(Self {
            client,
            limiter,
            extractor,
            options,
        })
    }

    /// The underlying HTTP client.
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// The run options.
    pub fn options(&self) -> &SessionOptions {
        &self.options
    }

    /// Read a response body as text, stopping after `max_body_size` bytes.
    pub async fn read_body(&self, mut response: reqwest::Response) -> anyhow::Result<String> {
        let cap = self.options.max_body_size;
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("error reading response body")?
        {
            if cap > 0 && buf.len() + chunk.len() >= cap {
                buf.extend_from_slice(&chunk[..cap - buf.len()]);
                break;
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }
}

/// Error returned when a provider answers with a non-200 status code.
///
/// Sources that need to react to a specific status (e.g. fall back on 403)
/// can find it with `err.downcast_ref::<StatusError>()`.
#[derive(Debug, Clone)]
pub struct StatusError {
    /// HTTP status code.
    pub status: u16,
    /// Requested URL (secrets are scrubbed by the logger when printed).
    pub url: String,
    /// First bytes of the response body, for diagnostics.
    pub body: String,
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let url = percent_encoding::percent_decode_str(&self.url).decode_utf8_lossy();
        write!(
            f,
            "unexpected status code {} received from {}",
            self.status, url
        )
    }
}

impl std::error::Error for StatusError {}

/// Return the HTTP status code carried by an error, if any.
pub fn status_of(err: &anyhow::Error) -> Option<u16> {
    err.downcast_ref::<StatusError>().map(|e| e.status)
}
