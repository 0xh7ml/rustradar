//! Passive enumeration: source selection, the shared [`RateLimiter`], and the
//! [`Agent`] that runs all selected sources concurrently for a domain.

mod limiter;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;

pub use limiter::{parse_rate_limits, RateLimit, RateLimiter, DEFAULT_RATE_LIMITS};

use crate::subscraping::{
    sources, Ctx, Session, SessionOptions, Source, SourceResult, Statistics, StatsCounter,
};

/// API keys per source name.
pub type ProviderKeys = HashMap<String, Vec<String>>;

/// Which sources to use (maps to `-s`, `-es`, `-all`, `-recursive`).
#[derive(Debug, Clone, Default)]
pub struct SourceSelection {
    /// Run only these sources (`-s`). Ignored when `all` is set.
    pub include: Vec<String>,
    /// Never run these sources (`-es`).
    pub exclude: Vec<String>,
    /// Use every source, including slow non-default ones (`-all`).
    pub all: bool,
    /// Keep only sources that support recursive enumeration (`-recursive`).
    pub recursive_only: bool,
}

/// Select sources from `available` according to `selection`.
///
/// Order of operations (same as subfinder): start from `-all`, `-s` or the
/// default set; remove `-es`; then, with `-recursive`, drop sources without
/// recursive support. Unknown names in `-s` are logged and ignored.
pub fn select_sources(
    available: Vec<Arc<dyn Source>>,
    selection: &SourceSelection,
) -> anyhow::Result<Vec<Arc<dyn Source>>> {
    let include: HashSet<String> = selection
        .include
        .iter()
        .map(|s| s.trim().to_lowercase())
        .collect();
    let exclude: HashSet<String> = selection
        .exclude
        .iter()
        .map(|s| s.trim().to_lowercase())
        .collect();

    if !selection.all {
        for name in &include {
            if !available.iter().any(|s| s.name() == name) {
                crate::warn!("There is no source with the name: {name}");
            }
        }
    }

    let mut selected: Vec<Arc<dyn Source>> = available
        .into_iter()
        .filter(|s| {
            if selection.all {
                true
            } else if !include.is_empty() {
                include.contains(s.name())
            } else {
                s.is_default()
            }
        })
        .filter(|s| !exclude.contains(s.name()))
        .filter(|s| !selection.recursive_only || s.has_recursive_support())
        .collect();

    selected.sort_by_key(|s| s.name());
    if selected.is_empty() {
        anyhow::bail!("no sources selected for this search");
    }
    crate::debug!(
        "Selected source(s) for this search: {}",
        selected
            .iter()
            .map(|s| s.name())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(selected)
}

/// Limits for one domain's passive enumeration.
#[derive(Debug, Clone)]
pub struct EnumerationOptions {
    /// Session settings shared by all sources.
    pub session: SessionOptions,
    /// Hard deadline for all sources on one domain (`-max-time`).
    pub max_enumeration_time: Duration,
}

impl Default for EnumerationOptions {
    fn default() -> Self {
        Self {
            session: SessionOptions::default(),
            max_enumeration_time: Duration::from_secs(10 * 60),
        }
    }
}

/// Runs the selected sources and aggregates their statistics.
///
/// Cloning an `Agent` is cheap; clones share statistics.
#[derive(Clone)]
pub struct Agent {
    sources: Arc<Vec<Arc<dyn Source>>>,
    keys: Arc<HashMap<String, Arc<Vec<String>>>>,
    stats: Arc<Mutex<BTreeMap<&'static str, Statistics>>>,
}

impl Agent {
    /// Build an agent from the full source catalog.
    pub fn new(selection: &SourceSelection, keys: ProviderKeys) -> anyhow::Result<Self> {
        Ok(Self::with_sources(
            select_sources(sources::all(), selection)?,
            keys,
        ))
    }

    /// Build an agent from an explicit list of sources (useful for tests and
    /// custom sources).
    pub fn with_sources(sources: Vec<Arc<dyn Source>>, keys: ProviderKeys) -> Self {
        let keys = keys
            .into_iter()
            .map(|(name, list)| (name.to_lowercase(), Arc::new(list)))
            .collect();
        Self {
            sources: Arc::new(sources),
            keys: Arc::new(keys),
            stats: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Names of the selected sources.
    pub fn source_names(&self) -> Vec<&'static str> {
        self.sources.iter().map(|s| s.name()).collect()
    }

    /// Enumerate `domain` with every selected source concurrently.
    ///
    /// Returns a channel of raw results; it closes when every source has
    /// finished or the `max_enumeration_time` deadline passed. Sources still
    /// running at the deadline are cancelled (their futures are dropped).
    pub fn enumerate(
        &self,
        domain: &str,
        client: reqwest::Client,
        limiter: Option<Arc<RateLimiter>>,
        options: &EnumerationOptions,
    ) -> mpsc::Receiver<SourceResult> {
        let (tx, rx) = mpsc::channel(1024);
        let agent = self.clone();
        let domain = domain.to_string();
        let options = options.clone();

        tokio::spawn(async move {
            let session = match Session::new(&domain, client, limiter, options.session.clone()) {
                Ok(session) => Arc::new(session),
                Err(err) => {
                    let _ = tx
                        .send(SourceResult::Error {
                            source: "rustradar",
                            error: format!("could not init passive session for {domain}: {err:#}"),
                        })
                        .await;
                    return;
                }
            };
            let deadline = Instant::now() + options.max_enumeration_time;
            let empty = Arc::new(Vec::new());

            let mut tasks = tokio::task::JoinSet::new();
            for source in agent.sources.iter() {
                let keys = agent
                    .keys
                    .get(source.name())
                    .cloned()
                    .unwrap_or_else(|| empty.clone());
                if source.needs_key() && keys.is_empty() {
                    agent.record(
                        source.name(),
                        Statistics {
                            skipped: true,
                            ..Default::default()
                        },
                    );
                    crate::debug!("Skipping {}: no API key configured", source.name());
                    continue;
                }
                let counter = Arc::new(StatsCounter::default());
                let ctx = Ctx::new(
                    domain.clone(),
                    source.name(),
                    keys,
                    session.clone(),
                    tx.clone(),
                    counter.clone(),
                );
                let agent = agent.clone();
                let source = source.clone();
                tasks.spawn(async move {
                    let started = Instant::now();
                    let outcome = tokio::time::timeout_at(deadline, source.run(&ctx)).await;
                    match outcome {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => ctx.error(format!("{err:#}")).await,
                        Err(_) => ctx.error("enumeration time limit (-max-time) reached; results may be incomplete").await,
                    }
                    agent.record(source.name(), counter.snapshot(started.elapsed()));
                });
            }
            drop(tx);
            while tasks.join_next().await.is_some() {}
        });

        rx
    }

    /// Merge one run's statistics into the totals.
    fn record(&self, source: &'static str, run: Statistics) {
        let Ok(mut stats) = self.stats.lock() else {
            return;
        };
        match stats.get_mut(source) {
            None => {
                stats.insert(source, run);
            }
            Some(total) => {
                total.time_taken += run.time_taken;
                total.requests += run.requests;
                total.results += run.results;
                total.errors += run.errors;
                total.skipped = total.skipped && run.skipped;
            }
        }
    }

    /// Statistics per source, summed over every domain enumerated so far.
    pub fn statistics(&self) -> BTreeMap<String, Statistics> {
        self.stats
            .lock()
            .map(|s| s.iter().map(|(k, v)| (k.to_string(), v.clone())).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subscraping::{KeyRequirement, SourceInfo};
    use async_trait::async_trait;

    struct Fake(&'static SourceInfo);

    #[async_trait]
    impl Source for Fake {
        fn info(&self) -> &'static SourceInfo {
            self.0
        }
        async fn run(&self, ctx: &Ctx) -> anyhow::Result<()> {
            if !ctx.emit(format!("www.{}", ctx.domain)).await {
                return Ok(());
            }
            ctx.emit(format!("api.{}", ctx.domain)).await;
            if self.0.name == "broken" {
                anyhow::bail!("boom");
            }
            Ok(())
        }
    }

    static DEFAULT_A: SourceInfo = SourceInfo {
        name: "a",
        is_default: true,
        recursive: true,
        key: KeyRequirement::None,
    };
    static SLOW_B: SourceInfo = SourceInfo {
        name: "b",
        is_default: false,
        recursive: false,
        key: KeyRequirement::None,
    };
    static KEYED_C: SourceInfo = SourceInfo {
        name: "c",
        is_default: true,
        recursive: false,
        key: KeyRequirement::Required,
    };
    static BROKEN: SourceInfo = SourceInfo {
        name: "broken",
        is_default: true,
        recursive: false,
        key: KeyRequirement::None,
    };

    fn catalog() -> Vec<Arc<dyn Source>> {
        vec![
            Arc::new(Fake(&DEFAULT_A)),
            Arc::new(Fake(&SLOW_B)),
            Arc::new(Fake(&KEYED_C)),
        ]
    }

    fn names(v: &[Arc<dyn Source>]) -> Vec<&'static str> {
        v.iter().map(|s| s.name()).collect()
    }

    #[test]
    fn selection_rules() {
        let sel = |s: SourceSelection| names(&select_sources(catalog(), &s).unwrap());
        assert_eq!(sel(SourceSelection::default()), vec!["a", "c"]);
        assert_eq!(
            sel(SourceSelection {
                all: true,
                ..Default::default()
            }),
            vec!["a", "b", "c"]
        );
        assert_eq!(
            sel(SourceSelection {
                include: vec!["B".into()],
                ..Default::default()
            }),
            vec!["b"]
        );
        assert_eq!(
            sel(SourceSelection {
                exclude: vec!["a".into()],
                ..Default::default()
            }),
            vec!["c"]
        );
        assert_eq!(
            sel(SourceSelection {
                all: true,
                recursive_only: true,
                ..Default::default()
            }),
            vec!["a"]
        );
        assert!(select_sources(
            catalog(),
            &SourceSelection {
                include: vec!["nope".into()],
                ..Default::default()
            }
        )
        .is_err());
    }

    #[tokio::test]
    async fn runs_sources_and_records_stats() {
        let agent = Agent::with_sources(
            vec![
                Arc::new(Fake(&DEFAULT_A)),
                Arc::new(Fake(&KEYED_C)),
                Arc::new(Fake(&BROKEN)),
            ],
            ProviderKeys::new(),
        );
        let client = reqwest::Client::new();
        let mut rx = agent.enumerate("example.com", client, None, &EnumerationOptions::default());
        let mut subs = 0;
        let mut errors = 0;
        while let Some(r) = rx.recv().await {
            match r {
                SourceResult::Subdomain { .. } => subs += 1,
                SourceResult::Error { source, .. } => {
                    assert_eq!(source, "broken");
                    errors += 1
                }
            }
        }
        assert_eq!(subs, 4); // a + broken; c skipped (no key)
        assert_eq!(errors, 1);
        let stats = agent.statistics();
        assert!(stats["c"].skipped);
        assert_eq!(stats["a"].results, 2);
        assert_eq!(stats["broken"].errors, 1);
    }

    #[tokio::test]
    async fn respects_max_results() {
        let agent = Agent::with_sources(vec![Arc::new(Fake(&DEFAULT_A))], ProviderKeys::new());
        let mut opts = EnumerationOptions::default();
        opts.session.max_results = 1;
        let mut rx = agent.enumerate("example.com", reqwest::Client::new(), None, &opts);
        let mut n = 0;
        while rx.recv().await.is_some() {
            n += 1;
        }
        assert_eq!(n, 1);
    }
}
