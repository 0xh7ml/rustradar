//! Wildcard detection and concurrent resolution of candidates.
//!
//! ## Wildcard algorithm
//!
//! A domain with a wildcard record (`*.example.com A 1.2.3.4`) makes *every*
//! name resolve, so "it resolves" proves nothing. Before resolving candidates
//! we query three random, certainly-nonexistent names (`<random>.example.com`).
//! If they resolve, their IPs are remembered as wildcard sinkholes. A candidate
//! that resolves to any sinkhole IP is then dropped as a wildcard artifact.

use std::collections::HashSet;
use std::sync::Arc;

use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::Serialize;
use tokio::sync::{mpsc, Semaphore};

use super::Resolver;

/// Number of canary probes sent per domain.
const MAX_WILDCARD_CHECKS: usize = 3;

/// A unique subdomain found by passive enumeration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostEntry {
    /// The input (apex) domain.
    pub domain: String,
    /// The discovered subdomain.
    pub host: String,
    /// First source that reported it.
    pub source: String,
    /// `true` when a source reported it as `*.host` (wildcard certificate).
    pub wildcard_certificate: bool,
}

/// A host that resolved and is not a wildcard artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Resolved {
    /// The subdomain.
    pub host: String,
    /// First IPv4 address it resolved to.
    pub ip: String,
    /// First source that reported it.
    pub source: String,
    /// Wildcard certificate flag carried over from [`HostEntry`].
    pub wildcard_certificate: bool,
}

/// Outcome of resolving one [`HostEntry`].
#[derive(Debug, Clone)]
pub enum ResolveResult {
    /// The host resolved to non-wildcard addresses.
    Subdomain(Resolved),
    /// The lookup failed (timeout, SERVFAIL, ...).
    Error {
        /// Host that failed.
        host: String,
        /// Error description.
        error: String,
    },
}

/// Resolves candidates for one domain and filters wildcard artifacts.
pub struct ResolutionPool {
    resolver: Resolver,
    threads: usize,
    remove_wildcard: bool,
    wildcard_ips: HashSet<String>,
}

impl ResolutionPool {
    /// Create a pool running at most `threads` concurrent lookups.
    pub fn new(resolver: Resolver, threads: usize, remove_wildcard: bool) -> Self {
        Self {
            resolver,
            threads: threads.max(1),
            remove_wildcard,
            wildcard_ips: HashSet::new(),
        }
    }

    /// Probe `domain` with random canary names.
    ///
    /// Returns `Ok(true)` when every probe resolved (the domain has wildcard
    /// DNS) and `Ok(false)` as soon as one probe does not resolve. IPs from
    /// probes that did resolve are kept as sinkholes either way.
    pub async fn init_wildcards(&mut self, domain: &str) -> anyhow::Result<bool> {
        for _ in 0..MAX_WILDCARD_CHECKS {
            let probe = format!("{}.{}", canary_label(), domain);
            let ips = self.resolver.lookup(&probe).await.unwrap_or_default();
            if ips.is_empty() {
                return Ok(false);
            }
            self.wildcard_ips.extend(ips);
        }
        Ok(true)
    }

    /// IPs identified as wildcard sinkholes.
    pub fn wildcard_ips(&self) -> &HashSet<String> {
        &self.wildcard_ips
    }

    /// Start resolving. Send candidates into the returned sender and drop it
    /// when done; the receiver yields results and closes after the last one.
    pub fn spawn(self) -> (mpsc::Sender<HostEntry>, mpsc::Receiver<ResolveResult>) {
        let (task_tx, mut task_rx) = mpsc::channel::<HostEntry>(1024);
        let (result_tx, result_rx) = mpsc::channel::<ResolveResult>(1024);
        let shared = Arc::new(self);

        tokio::spawn(async move {
            let slots = Arc::new(Semaphore::new(shared.threads));
            let mut tasks = tokio::task::JoinSet::new();
            while let Some(entry) = task_rx.recv().await {
                let Ok(permit) = slots.clone().acquire_owned().await else {
                    break;
                };
                let pool = shared.clone();
                let tx = result_tx.clone();
                tasks.spawn(async move {
                    if let Some(result) = pool.resolve(entry).await {
                        let _ = tx.send(result).await;
                    }
                    drop(permit);
                });
                // Reap finished tasks so the set does not grow unbounded.
                while tasks.try_join_next().is_some() {}
            }
            while tasks.join_next().await.is_some() {}
        });

        (task_tx, result_rx)
    }

    async fn resolve(&self, entry: HostEntry) -> Option<ResolveResult> {
        if !self.remove_wildcard {
            return Some(ResolveResult::Subdomain(Resolved {
                host: entry.host,
                ip: String::new(),
                source: entry.source,
                wildcard_certificate: entry.wildcard_certificate,
            }));
        }
        let ips = match self.resolver.lookup(&entry.host).await {
            Ok(ips) => ips,
            Err(err) => {
                return Some(ResolveResult::Error {
                    host: entry.host,
                    error: err.to_string(),
                })
            }
        };
        // Dead host, or a wildcard artifact.
        if ips.is_empty() || ips.iter().any(|ip| self.wildcard_ips.contains(ip)) {
            return None;
        }
        Some(ResolveResult::Subdomain(Resolved {
            host: entry.host,
            ip: ips[0].clone(),
            source: entry.source,
            wildcard_certificate: entry.wildcard_certificate,
        }))
    }
}

/// A random 20-character lowercase label (same length as an `xid`).
fn canary_label() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(20)
        .map(|c| (c as char).to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canary_labels_are_dns_safe() {
        let label = canary_label();
        assert_eq!(label.len(), 20);
        assert!(label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert_ne!(canary_label(), canary_label());
    }

    #[tokio::test]
    async fn passthrough_without_wildcard_removal() {
        let resolver = Resolver::new(&["127.0.0.1:1"], std::time::Duration::from_secs(1)).unwrap();
        let pool = ResolutionPool::new(resolver, 2, false);
        let (tx, mut rx) = pool.spawn();
        tx.send(HostEntry {
            domain: "example.com".into(),
            host: "a.example.com".into(),
            source: "test".into(),
            wildcard_certificate: false,
        })
        .await
        .unwrap();
        drop(tx);
        let result = rx.recv().await.unwrap();
        assert!(matches!(result, ResolveResult::Subdomain(r) if r.host == "a.example.com"));
        assert!(rx.recv().await.is_none());
    }
}
