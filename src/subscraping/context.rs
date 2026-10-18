//! [`Ctx`]: everything a running source needs, plus the [`Request`] builder.

use std::fmt::Display;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::mpsc;

use super::session::{random_user_agent, StatusError};
use super::utils::{pick_random, split_key_pair};
use super::{Session, SourceResult, StatsCounter};

/// Per-source execution context handed to [`Source::run`](super::Source::run).
pub struct Ctx {
    /// Target apex domain (normalized, lowercase).
    pub domain: String,
    source: &'static str,
    keys: Arc<Vec<String>>,
    session: Arc<Session>,
    tx: mpsc::Sender<SourceResult>,
    stats: Arc<StatsCounter>,
}

impl Ctx {
    pub(crate) fn new(
        domain: String,
        source: &'static str,
        keys: Arc<Vec<String>>,
        session: Arc<Session>,
        tx: mpsc::Sender<SourceResult>,
        stats: Arc<StatsCounter>,
    ) -> Self {
        Self {
            domain,
            source,
            keys,
            session,
            tx,
            stats,
        }
    }

    /// Name of the running source.
    pub fn source(&self) -> &'static str {
        self.source
    }

    /// All API keys configured for this source.
    pub fn keys(&self) -> &[String] {
        &self.keys
    }

    /// A random API key, or `None` when none is configured.
    pub fn random_key(&self) -> Option<String> {
        pick_random(&self.keys).cloned()
    }

    /// A random `left:right` key split in two (e.g. `email:key`), choosing only
    /// among keys that have exactly that shape.
    pub fn random_key_pair(&self) -> Option<(String, String)> {
        let pairs: Vec<(String, String)> =
            self.keys.iter().filter_map(|k| split_key_pair(k)).collect();
        pick_random(&pairs).cloned()
    }

    /// Access the shared session (HTTP client and options).
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Per-request timeout configured for the run.
    pub fn timeout(&self) -> Duration {
        self.session.options.timeout
    }

    /// `true` when the user selected all sources (`-all`).
    pub fn all_sources(&self) -> bool {
        self.session.options.all_sources
    }

    /// Maximum results per source (`0` = unlimited).
    pub fn max_results(&self) -> usize {
        self.session.options.max_results
    }

    /// `true` once this source has emitted `--max-results` candidates.
    pub fn limit_reached(&self) -> bool {
        let max = self.max_results();
        max > 0 && self.stats.results.load(Ordering::Relaxed) >= max as u64
    }

    /// Extract candidate subdomains of the target from arbitrary text.
    pub fn extract(&self, text: &str) -> Vec<String> {
        self.session.extractor.extract(text)
    }

    /// Emit one candidate. Returns `false` when the source should stop
    /// (output closed or `--max-results` reached).
    pub async fn emit(&self, value: impl Into<String>) -> bool {
        let value = value.into();
        if value.trim().is_empty() {
            return !self.limit_reached();
        }
        let sent = self
            .tx
            .send(SourceResult::Subdomain {
                source: self.source,
                value,
            })
            .await
            .is_ok();
        if sent {
            self.stats.results.fetch_add(1, Ordering::Relaxed);
        }
        sent && !self.limit_reached()
    }

    /// Emit every value in an iterator. Returns `false` when the source should stop.
    pub async fn emit_all<I, S>(&self, values: I) -> bool
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for value in values {
            if !self.emit(value).await {
                return false;
            }
        }
        true
    }

    /// Run the extractor over `text` and emit every match.
    /// Returns `false` when the source should stop.
    pub async fn emit_extracted(&self, text: &str) -> bool {
        self.emit_all(self.extract(text)).await
    }

    /// Record a non-fatal error and keep running.
    pub async fn error(&self, err: impl Display) {
        self.stats.errors.fetch_add(1, Ordering::Relaxed);
        let _ = self
            .tx
            .send(SourceResult::Error {
                source: self.source,
                error: err.to_string(),
            })
            .await;
    }

    /// Wait for a rate-limit slot and count one request. Called automatically
    /// by [`Request::send`]; call it yourself only for non-HTTP requests
    /// (e.g. the crt.sh PostgreSQL query).
    pub async fn acquire(&self) -> anyhow::Result<()> {
        if let Some(limiter) = &self.session.limiter {
            limiter.wait(self.source).await?;
        }
        self.stats.requests.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Start a GET request.
    pub fn get(&self, url: &str) -> Request<'_> {
        self.request(Method::GET, url)
    }

    /// Start a POST request.
    pub fn post(&self, url: &str) -> Request<'_> {
        self.request(Method::POST, url)
    }

    /// Start a request with any method.
    pub fn request(&self, method: Method, url: &str) -> Request<'_> {
        let builder = self
            .session
            .client
            .request(method, url)
            .header(reqwest::header::USER_AGENT, random_user_agent())
            .header(reqwest::header::ACCEPT, "*/*")
            .header(reqwest::header::ACCEPT_LANGUAGE, "en");
        Request {
            ctx: self,
            builder,
            url: url.to_string(),
        }
    }

    /// Read a response body (respecting `--response-size-read`).
    pub async fn read_text(&self, response: reqwest::Response) -> anyhow::Result<String> {
        self.session.read_body(response).await
    }

    /// Read and JSON-decode a response body.
    pub async fn read_json<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> anyhow::Result<T> {
        let body = self.read_text(response).await?;
        serde_json::from_str(&body)
            .with_context(|| format!("could not decode JSON response: {}", snippet(&body)))
    }
}

/// Builder for one HTTP request made by a source.
///
/// Created by [`Ctx::get`] / [`Ctx::post`]. Finish with [`send`](Self::send)
/// (status must be 200), [`send_raw`](Self::send_raw) (any status),
/// [`text`](Self::text) or [`decode`](Self::decode).
pub struct Request<'a> {
    ctx: &'a Ctx,
    builder: reqwest::RequestBuilder,
    url: String,
}

impl<'a> Request<'a> {
    /// Set a header (replaces the default for `User-Agent`, `Accept`, ...).
    pub fn header(mut self, name: &str, value: &str) -> Self {
        if let (Ok(name), Ok(value)) = (HeaderName::try_from(name), HeaderValue::try_from(value)) {
            // `header` appends; remove first so overrides actually replace.
            let mut tmp = reqwest::header::HeaderMap::new();
            tmp.insert(name, value);
            self.builder = self.builder.headers(tmp);
        }
        self
    }

    /// `Authorization: Bearer <token>`.
    pub fn bearer(self, token: &str) -> Self {
        self.header("Authorization", &format!("Bearer {token}"))
    }

    /// HTTP basic authentication.
    pub fn basic_auth(mut self, user: &str, password: &str) -> Self {
        self.builder = self.builder.basic_auth(user, Some(password));
        self
    }

    /// JSON request body (also sets `Content-Type: application/json`).
    pub fn json<T: Serialize + ?Sized>(mut self, body: &T) -> Self {
        self.builder = self.builder.json(body);
        self
    }

    /// Raw request body.
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.builder = self.builder.body(body.into());
        self
    }

    /// Send the request and return the response whatever its status.
    pub async fn send_raw(self) -> anyhow::Result<reqwest::Response> {
        self.ctx.acquire().await?;
        let url = self.url;
        self.builder
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("request to {url} failed: {}", e.without_url()))
    }

    /// Send the request; any status other than 200 becomes a [`StatusError`].
    pub async fn send(self) -> anyhow::Result<reqwest::Response> {
        let url = self.url.clone();
        let response = self.send_raw().await?;
        ensure_ok(response, &url).await
    }

    /// Send, require 200, and return the (size-capped) body text.
    pub async fn text(self) -> anyhow::Result<String> {
        let ctx = self.ctx;
        let response = self.send().await?;
        ctx.read_text(response).await
    }

    /// Send, require 200, and JSON-decode the body.
    pub async fn decode<T: DeserializeOwned>(self) -> anyhow::Result<T> {
        let ctx = self.ctx;
        let response = self.send().await?;
        ctx.read_json(response).await
    }
}

/// Turn a non-200 response into a [`StatusError`].
pub(crate) async fn ensure_ok(
    response: reqwest::Response,
    url: &str,
) -> anyhow::Result<reqwest::Response> {
    let status = response.status().as_u16();
    if status == 200 {
        return Ok(response);
    }
    // Read a little of the body for debug output; never fail on it.
    let body = tokio::time::timeout(Duration::from_secs(5), response.text())
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let err = StatusError {
        status,
        url: url.to_string(),
        body: snippet(&body),
    };
    crate::debug!("{err}: {}", err.body);
    Err(err.into())
}

/// First 200 characters of a body, on one line.
pub(crate) fn snippet(body: &str) -> String {
    let flat: String = body
        .chars()
        .take(200)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    flat.trim().to_string()
}
