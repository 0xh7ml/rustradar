//! Orchestration: turns [`Options`] into a configured [`Runner`] and drives
//! batch enumeration, output and statistics.
//!
//! ```text
//! Options ──► Runner::new ──► (filters, provider keys, Agent, HTTP client, resolver)
//!                │
//!   run_enumeration (inputs: -d / -dL / stdin)
//!                │
//!   enumerate_domains ── one shared RateLimiter + resolver slots for the batch
//!                │          up to -t domains in parallel
//!                ▼
//!   enumerate_domain (per domain) ──► DomainResults ──► OutputWriter ──► stdout / -o / -oD
//! ```

mod banner;
pub mod config;
mod enumerate;
pub mod options;
pub mod output;
pub mod stats;
pub mod update;
pub mod util;
pub mod validate;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use futures::TryStreamExt;
use tokio::io::AsyncBufReadExt;

pub use banner::show_banner;
pub use enumerate::DomainResults;
pub use options::{normalize_args, Options};
pub use output::OutputWriter;
pub use validate::{validate_options, Filters};

use crate::passive::{
    parse_rate_limits, Agent, EnumerationOptions, RateLimit, RateLimiter, SourceSelection,
    DEFAULT_RATE_LIMITS,
};
use crate::resolve::{HostEntry, Resolver};
use crate::subscraping::session::build_client;
use crate::subscraping::{SessionOptions, Statistics};
use util::{is_ip, preprocess_domain};

/// Called once for every unique subdomain as soon as it is known (after DNS
/// resolution when `-active` is set).
pub type ResultCallback = Arc<dyn Fn(&HostEntry) + Send + Sync>;

/// A thread-safe output sink.
pub type SharedWriter = Arc<Mutex<dyn Write + Send>>;

/// The configured enumeration engine.
pub struct Runner {
    options: Arc<Options>,
    agent: Agent,
    client: reqwest::Client,
    resolver: Option<Resolver>,
    filters: Filters,
    rate_limits: HashMap<String, RateLimit>,
    callback: Option<ResultCallback>,
}

impl Runner {
    /// Build a runner: compile filters, load API keys, select sources, build
    /// the HTTP client and (with `-active`) the DNS resolver.
    pub fn new(options: Options) -> anyhow::Result<Self> {
        let filters = Filters::compile(
            &options.r#match,
            &options.filter,
            &options.match_regex,
            &options.filter_regex,
        )?;

        let provider_path = options
            .provider_config
            .clone()
            .unwrap_or_else(config::default_provider_config_path);
        crate::info!("Loading provider config from {}", provider_path.display());
        let keys = config::load_provider_keys(&provider_path)?;

        let selection = SourceSelection {
            include: options.sources.clone(),
            exclude: options.exclude_sources.clone(),
            all: options.all,
            recursive_only: options.recursive,
        };
        let agent = Agent::new(&selection, keys)?;

        let timeout = Duration::from_secs(options.timeout);
        let client = build_client(options.proxy.as_deref(), timeout)?;

        let resolver = if options.active {
            let mut list = options.resolvers.clone();
            if let Some(path) = &options.resolver_list {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("could not read resolver list {}", path.display()))?;
                list.extend(
                    text.lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .map(String::from),
                );
            }
            Some(Resolver::new(&list, timeout)?)
        } else {
            None
        };

        let mut rate_limits = parse_rate_limits(DEFAULT_RATE_LIMITS).map_err(anyhow::Error::msg)?;
        rate_limits.extend(parse_rate_limits(&options.rate_limits).map_err(anyhow::Error::msg)?);

        Ok(Self {
            options: Arc::new(options),
            agent,
            client,
            resolver,
            filters,
            rate_limits,
            callback: None,
        })
    }

    /// Register a callback invoked for every unique subdomain as it is found.
    pub fn with_result_callback(
        mut self,
        callback: impl Fn(&HostEntry) + Send + Sync + 'static,
    ) -> Self {
        self.callback = Some(Arc::new(callback));
        self
    }

    /// The options this runner was built with.
    pub fn options(&self) -> &Options {
        &self.options
    }

    /// Names of the selected sources.
    pub fn source_names(&self) -> Vec<&'static str> {
        self.agent.source_names()
    }

    /// Per-source statistics accumulated so far.
    pub fn statistics(&self) -> BTreeMap<String, Statistics> {
        self.agent.statistics()
    }

    fn enumeration_options(&self) -> EnumerationOptions {
        EnumerationOptions {
            session: SessionOptions {
                timeout: Duration::from_secs(self.options.timeout),
                max_body_size: self.options.response_size_read,
                max_results: self.options.max_results,
                all_sources: self.options.all,
            },
            max_enumeration_time: Duration::from_secs(self.options.max_time * 60),
        }
    }

    fn new_limiter(&self) -> Arc<RateLimiter> {
        Arc::new(RateLimiter::new(
            &self.agent.source_names(),
            self.options.rate_limit,
            &self.rate_limits,
        ))
    }

    /// Enumerate a single domain and return its results (nothing is written).
    pub async fn enumerate_single_domain(&self, domain: &str) -> anyhow::Result<DomainResults> {
        let domain = preprocess_domain(domain);
        if domain.is_empty() {
            anyhow::bail!("empty domain");
        }
        let resolver = self
            .resolver
            .as_ref()
            .map(|r| r.with_concurrency_limit(self.options.threads));
        self.enumerate_domain(&domain, self.new_limiter(), resolver)
            .await
    }

    /// CLI entry point: read domains from `-d`, `-dL` or stdin, enumerate
    /// them, and write results to stdout plus `-o` / `-oD` files.
    pub async fn run_enumeration(&self) -> anyhow::Result<usize> {
        let mut domains = self.options.domain.clone();
        if let Some(path) = &self.options.list {
            let text = tokio::fs::read_to_string(path)
                .await
                .with_context(|| format!("could not read domain list {}", path.display()))?;
            domains.extend(text.lines().map(String::from));
        }
        if domains.is_empty() && self.options.stdin {
            let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
            while let Some(line) = lines.next_line().await.context("could not read stdin")? {
                domains.push(line);
            }
        }
        let stdout: SharedWriter = Arc::new(Mutex::new(std::io::stdout()));
        self.enumerate_domains(domains, vec![stdout]).await
    }

    /// Enumerate many domains concurrently (up to `-t` at once) and write each
    /// domain's results to `writers` (and `-o` / `-oD` files) as soon as that
    /// domain finishes. Returns the total number of subdomains found.
    ///
    /// All domains share one rate limiter, so provider budgets are respected
    /// across the whole batch. Input is cleaned, deduplicated, and (with
    /// `-exclude-ip`) stripped of IP addresses.
    pub async fn enumerate_domains<I, S>(
        &self,
        domains: I,
        mut writers: Vec<SharedWriter>,
    ) -> anyhow::Result<usize>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut seen = HashSet::new();
        let domains: Vec<String> = domains
            .into_iter()
            .map(|d| preprocess_domain(d.as_ref()))
            .filter(|d| !d.is_empty())
            .filter(|d| !(self.options.exclude_ip && is_ip(d)))
            .filter(|d| seen.insert(d.clone()))
            .collect();
        if domains.is_empty() {
            crate::warn!("No valid input domains");
            return Ok(0);
        }

        if let Some(path) = &self.options.output {
            writers.push(open_output_file(path)?);
        }
        let output_dir = match (&self.options.output, &self.options.output_dir) {
            (None, Some(dir)) => {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("could not create {}", dir.display()))?;
                Some(dir.clone())
            }
            _ => None,
        };

        let limiter = self.new_limiter();
        let resolver = self
            .resolver
            .as_ref()
            .map(|r| r.with_concurrency_limit(self.options.threads));
        let output = OutputWriter::from_options(&self.options);
        let total = AtomicUsize::new(0);

        futures::stream::iter(domains.into_iter().map(Ok::<String, anyhow::Error>))
            .try_for_each_concurrent(self.options.threads.max(1), |domain| {
                let limiter = limiter.clone();
                let resolver = resolver.clone();
                let writers = &writers;
                let output_dir = &output_dir;
                let total = &total;
                async move {
                    let results = self.enumerate_domain(&domain, limiter, resolver).await?;
                    let text = output.render(&results);
                    write_all(writers, &text)?;
                    if let Some(dir) = output_dir {
                        let path = dir.join(format!("{domain}.{}", output.extension()));
                        std::fs::write(&path, &text)
                            .with_context(|| format!("could not write {}", path.display()))?;
                    }
                    total.fetch_add(results.len(), Ordering::Relaxed);
                    Ok(())
                }
            })
            .await?;

        for writer in &writers {
            if let Ok(mut w) = writer.lock() {
                w.flush().context("could not flush output")?;
            }
        }
        Ok(total.load(Ordering::Relaxed))
    }
}

/// Create (truncate) an output file, creating parent directories.
fn open_output_file(path: &PathBuf) -> anyhow::Result<SharedWriter> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("could not create {}", dir.display()))?;
    }
    let file = std::fs::File::create(path)
        .with_context(|| format!("could not create {}", path.display()))?;
    Ok(Arc::new(Mutex::new(std::io::BufWriter::new(file))))
}

/// Write one domain's block to every writer, keeping it contiguous.
fn write_all(writers: &[SharedWriter], text: &str) -> anyhow::Result<()> {
    if text.is_empty() {
        return Ok(());
    }
    for writer in writers {
        let mut w = writer
            .lock()
            .map_err(|_| anyhow::anyhow!("output lock poisoned"))?;
        w.write_all(text.as_bytes())
            .context("could not write output")?;
        w.flush().context("could not flush output")?;
    }
    Ok(())
}

/// Print the source catalog (`-ls`), as text or JSON.
pub fn list_sources(json: bool) -> String {
    let sources = crate::subscraping::sources::all();
    if json {
        let infos: Vec<_> = sources.iter().map(|s| s.info()).collect();
        return serde_json::to_string_pretty(&infos).unwrap_or_default();
    }
    let mut out = format!("Current list of available sources. [{}]\n", sources.len());
    out.push_str("Sources marked with an * need key(s) or token(s) to work.\n");
    out.push_str("Sources marked with a ~ are not used by default (use -all or -s).\n\n");
    for s in &sources {
        let key = if s.needs_key() { " *" } else { "" };
        let default = if s.is_default() { "" } else { " ~" };
        out.push_str(&format!("{}{key}{default}\n", s.name()));
    }
    out
}
