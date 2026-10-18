//! Enumeration of a single domain: passive collection, validation, dedup,
//! filtering, and (optionally) active resolution with wildcard removal.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use super::util::{is_valid_hostname, normalize_subdomain, strip_patterns};
use super::Runner;
use crate::passive::RateLimiter;
use crate::resolve::{HostEntry, ResolutionPool, ResolveResult, Resolved, Resolver};
use crate::subscraping::SourceResult;

/// Everything found for one input domain.
#[derive(Debug, Clone, Default)]
pub struct DomainResults {
    /// The input (apex) domain.
    pub domain: String,
    /// Unique subdomains from passive sources, with the first source seen.
    pub hosts: BTreeMap<String, HostEntry>,
    /// Every source that reported each subdomain.
    pub sources: BTreeMap<String, BTreeSet<String>>,
    /// With active resolution: subdomains that resolved and are not wildcard
    /// artifacts. `None` in passive mode.
    pub resolved: Option<BTreeMap<String, Resolved>>,
    /// Time taken for this domain.
    pub elapsed: Duration,
}

impl DomainResults {
    /// Final subdomains, sorted: resolved hosts in active mode, otherwise all
    /// unique passive hosts.
    pub fn hosts(&self) -> Vec<&str> {
        match &self.resolved {
            Some(resolved) => resolved.keys().map(String::as_str).collect(),
            None => self.hosts.keys().map(String::as_str).collect(),
        }
    }

    /// Number of final subdomains.
    pub fn len(&self) -> usize {
        match &self.resolved {
            Some(resolved) => resolved.len(),
            None => self.hosts.len(),
        }
    }

    /// `true` when nothing was found.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The passive entry for a host.
    pub fn entry(&self, host: &str) -> Option<&HostEntry> {
        self.hosts.get(host)
    }
}

impl Runner {
    /// Enumerate one domain using the given shared limiter and resolver.
    pub(crate) async fn enumerate_domain(
        &self,
        domain: &str,
        limiter: Arc<RateLimiter>,
        resolver: Option<Resolver>,
    ) -> anyhow::Result<DomainResults> {
        crate::info!("Enumerating subdomains for {domain}");
        let started = Instant::now();
        let active = self.options.active;

        // Wildcard probes run before passive enumeration so sinkhole IPs are
        // known when the first candidates arrive.
        let pool = match (&resolver, active) {
            (Some(resolver), true) => {
                let mut pool = ResolutionPool::new(resolver.clone(), self.options.threads, true);
                match pool.init_wildcards(domain).await {
                    Ok(true) => crate::info!(
                        "{domain} has wildcard DNS ({} sinkhole IPs); wildcard matches will be removed",
                        pool.wildcard_ips().len()
                    ),
                    Ok(false) => crate::debug!("{domain} is not a wildcard domain"),
                    Err(err) => crate::warn!("Could not get wildcards for domain {domain}: {err:#}"),
                }
                Some(pool)
            }
            _ => None,
        };

        let mut passive_rx = self.agent.enumerate(
            domain,
            self.client.clone(),
            Some(limiter),
            &self.enumeration_options(),
        );
        let (task_tx, result_rx) = match pool {
            Some(pool) => {
                let (tx, rx) = pool.spawn();
                (Some(tx), Some(rx))
            }
            None => (None, None),
        };

        let suffix = format!(".{domain}");
        let callback = self.callback.clone();
        let filters = &self.filters;

        // Consume passive results: validate, dedup, filter, forward to DNS.
        let collect = async move {
            let mut hosts: BTreeMap<String, HostEntry> = BTreeMap::new();
            let mut sources: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            while let Some(result) = passive_rx.recv().await {
                let (source, value) = match result {
                    SourceResult::Error { source, error } => {
                        crate::warn!("Encountered an error with source {source}: {error}");
                        continue;
                    }
                    SourceResult::Subdomain { source, value } => (source, value),
                };
                let value = normalize_subdomain(&value);
                let host = strip_patterns(&value);
                let wildcard = value.contains(&format!("*.{host}"));

                if !host.ends_with(&suffix) || !is_valid_hostname(&host) || !filters.allows(&host) {
                    continue;
                }

                let seen_by = sources.entry(host.clone()).or_default();
                if seen_by.insert(source.to_string()) {
                    crate::verbose!(source, "{host}");
                }

                if let Some(existing) = hosts.get_mut(&host) {
                    existing.wildcard_certificate |= wildcard;
                    continue;
                }

                let entry = HostEntry {
                    domain: domain.to_string(),
                    host: host.clone(),
                    source: source.to_string(),
                    wildcard_certificate: wildcard,
                };
                if !active {
                    if let Some(cb) = &callback {
                        cb(&entry);
                    }
                }
                if let Some(tx) = &task_tx {
                    let _ = tx.send(entry.clone()).await;
                }
                hosts.insert(host, entry);
            }
            drop(task_tx); // closes the resolution pool input
            (hosts, sources)
        };

        // Consume resolution results (active mode only).
        let callback = self.callback.clone();
        let resolve = async move {
            let mut rx = result_rx?;
            let mut found: BTreeMap<String, Resolved> = BTreeMap::new();
            while let Some(result) = rx.recv().await {
                match result {
                    ResolveResult::Error { host, error } => {
                        crate::debug!("Could not resolve host {host}: {error}")
                    }
                    ResolveResult::Subdomain(r) => {
                        if found.contains_key(&r.host) {
                            continue;
                        }
                        if let Some(cb) = &callback {
                            cb(&HostEntry {
                                domain: domain.to_string(),
                                host: r.host.clone(),
                                source: r.source.clone(),
                                wildcard_certificate: r.wildcard_certificate,
                            });
                        }
                        found.insert(r.host.clone(), r);
                    }
                }
            }
            Some(found)
        };

        let ((hosts, sources), mut resolved) = tokio::join!(collect, resolve);

        // A later source may have flagged a host as wildcard-certificate after
        // it was already sent for resolution; merge that flag back in.
        if let Some(resolved) = resolved.as_mut() {
            for (host, r) in resolved.iter_mut() {
                if hosts.get(host).is_some_and(|e| e.wildcard_certificate) {
                    r.wildcard_certificate = true;
                }
            }
        }

        let results = DomainResults {
            domain: domain.to_string(),
            hosts,
            sources,
            resolved,
            elapsed: started.elapsed(),
        };
        crate::info!(
            "Found {} subdomains for {domain} in {}",
            results.len(),
            super::stats::format_duration(results.elapsed)
        );
        Ok(results)
    }
}
