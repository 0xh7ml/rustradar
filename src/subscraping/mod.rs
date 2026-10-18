//! Scraping framework: the [`Source`] trait every data provider implements,
//! the shared HTTP [`Session`], the boundary-safe subdomain [`Extractor`], and
//! the concrete source implementations in [`sources`].
//!
//! ## How a source runs
//!
//! 1. The passive [`Agent`](crate::passive::Agent) builds one [`Session`] per
//!    target domain and one [`Ctx`] per source.
//! 2. It calls [`Source::run`]. The source makes HTTP requests through
//!    [`Ctx::get`] / [`Ctx::post`]. Each request waits on the shared rate
//!    limiter, gets a random User-Agent, is counted in the statistics, and has
//!    its body capped at `--response-size-read` bytes.
//! 3. The source sends candidates with [`Ctx::emit`] or
//!    [`Ctx::emit_extracted`]. It does **not** need to deduplicate or validate
//!    them; the runner normalizes, checks the suffix, filters and dedups.
//! 4. Returning `Err(..)` from `run` records one error for the source and logs
//!    a warning. Use [`Ctx::error`] for non-fatal errors that should not stop
//!    the source.
//!
//! See `docs/ADDING_A_SOURCE.md` for a step-by-step guide.

mod context;
pub mod extractor;
pub mod session;
pub mod sources;
pub mod utils;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;

pub use context::{Ctx, Request};
pub use extractor::Extractor;
pub use session::{Session, SessionOptions, StatusError};

/// Whether a source needs an API key to work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyRequirement {
    /// Works without any key.
    None,
    /// Works without a key; a key unlocks higher limits or more data.
    Optional,
    /// Skipped unless at least one key is configured.
    Required,
}

/// Static description of a source, used for listing and selection.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct SourceInfo {
    /// Unique lowercase name, used in `-s`, `-es`, `-rls` and provider config.
    pub name: &'static str,
    /// Included when the user does not pass `-s` or `-all`.
    pub is_default: bool,
    /// Can enumerate subdomains of a subdomain (selected by `-recursive`).
    pub recursive: bool,
    /// API key requirement.
    pub key: KeyRequirement,
}

/// A passive subdomain data provider.
///
/// Implementations should be stateless unit structs: everything that changes
/// per run (domain, keys, HTTP client, output channel) arrives through [`Ctx`].
#[async_trait]
pub trait Source: Send + Sync + 'static {
    /// Static metadata for this source.
    fn info(&self) -> &'static SourceInfo;

    /// Query the provider for `ctx.domain` and emit every candidate found.
    async fn run(&self, ctx: &Ctx) -> anyhow::Result<()>;

    /// Shortcut for `info().name`.
    fn name(&self) -> &'static str {
        self.info().name
    }

    /// Shortcut for `info().is_default`.
    fn is_default(&self) -> bool {
        self.info().is_default
    }

    /// Shortcut for `info().recursive`.
    fn has_recursive_support(&self) -> bool {
        self.info().recursive
    }

    /// Shortcut for `info().key`.
    fn key_requirement(&self) -> KeyRequirement {
        self.info().key
    }

    /// `true` when the source is skipped without a key.
    fn needs_key(&self) -> bool {
        self.info().key == KeyRequirement::Required
    }
}

/// A single event streamed by a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceResult {
    /// A raw subdomain candidate (not yet normalized or validated).
    Subdomain {
        /// Source name.
        source: &'static str,
        /// Candidate value as returned by the provider.
        value: String,
    },
    /// A non-fatal error reported by the source.
    Error {
        /// Source name.
        source: &'static str,
        /// Human-readable error message.
        error: String,
    },
}

/// Per-source run statistics (summed over all domains in a run).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Statistics {
    /// Wall-clock time spent in the source.
    pub time_taken: Duration,
    /// HTTP (or SQL) requests sent.
    pub requests: u64,
    /// Candidates emitted (before dedup).
    pub results: u64,
    /// Errors recorded.
    pub errors: u64,
    /// `true` when the source was skipped because no key was configured.
    pub skipped: bool,
}

/// Lock-free counters shared between a running source and the agent.
#[derive(Debug, Default)]
pub(crate) struct StatsCounter {
    pub requests: AtomicU64,
    pub results: AtomicU64,
    pub errors: AtomicU64,
}

impl StatsCounter {
    pub fn snapshot(&self, time_taken: Duration) -> Statistics {
        Statistics {
            time_taken,
            requests: self.requests.load(Ordering::Relaxed),
            results: self.results.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            skipped: false,
        }
    }
}
