//! DNS client wrapper.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig,
    ResolverOpts,
};
use hickory_resolver::error::ResolveErrorKind;
use hickory_resolver::TokioAsyncResolver;
use tokio::sync::Semaphore;

/// Public resolvers used when none are configured (Cloudflare, Google, Quad9,
/// Yandex, OpenDNS).
pub const DEFAULT_RESOLVERS: &[&str] = &[
    "1.1.1.1:53",
    "1.0.0.1:53",
    "8.8.8.8:53",
    "8.8.4.4:53",
    "9.9.9.9:53",
    "9.9.9.10:53",
    "77.88.8.8:53",
    "77.88.8.1:53",
    "208.67.222.222:53",
    "208.67.220.220:53",
];

/// Async DNS resolver with an optional shared concurrency limit.
///
/// Cloning is cheap; clones share the DNS client (and its cache) and, after
/// [`with_concurrency_limit`](Self::with_concurrency_limit), the same slots.
#[derive(Clone)]
pub struct Resolver {
    inner: Arc<TokioAsyncResolver>,
    slots: Option<Arc<Semaphore>>,
    resolvers: Arc<Vec<SocketAddr>>,
}

impl Resolver {
    /// Build a resolver. `resolvers` are `ip` or `ip:port` strings; when empty,
    /// [`DEFAULT_RESOLVERS`] is used.
    pub fn new<S: AsRef<str>>(resolvers: &[S], timeout: Duration) -> anyhow::Result<Self> {
        let list: Vec<String> = if resolvers.is_empty() {
            DEFAULT_RESOLVERS.iter().map(|s| s.to_string()).collect()
        } else {
            resolvers
                .iter()
                .map(|s| s.as_ref().trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };

        let addrs = list
            .iter()
            .map(|r| parse_resolver(r))
            .collect::<anyhow::Result<Vec<_>>>()?;
        if addrs.is_empty() {
            anyhow::bail!("no valid DNS resolvers configured");
        }

        let mut group = NameServerConfigGroup::new();
        for addr in &addrs {
            group.push(NameServerConfig::new(*addr, Protocol::Udp));
        }
        let config = ResolverConfig::from_parts(None, vec![], group);

        let mut opts = ResolverOpts::default();
        opts.timeout = timeout.clamp(Duration::from_secs(1), Duration::from_secs(10));
        opts.attempts = 2;
        opts.ip_strategy = LookupIpStrategy::Ipv4Only;
        opts.use_hosts_file = false;
        opts.edns0 = true;
        opts.num_concurrent_reqs = 2;

        Ok(Self {
            inner: Arc::new(TokioAsyncResolver::tokio(config, opts)),
            slots: None,
            resolvers: Arc::new(addrs),
        })
    }

    /// Return a copy whose lookups share a pool of at most `limit` in-flight
    /// queries (across every domain worker that holds the copy).
    pub fn with_concurrency_limit(&self, limit: usize) -> Self {
        Self {
            slots: Some(Arc::new(Semaphore::new(limit.max(1)))),
            ..self.clone()
        }
    }

    /// The nameservers in use.
    pub fn resolvers(&self) -> &[SocketAddr] {
        &self.resolvers
    }

    /// Resolve `host` to its IPv4 addresses. A name that does not exist (or has
    /// no A records) returns an empty list rather than an error.
    pub async fn lookup(&self, host: &str) -> anyhow::Result<Vec<String>> {
        let _permit = match &self.slots {
            Some(slots) => Some(slots.acquire().await.context("resolver closed")?),
            None => None,
        };
        let fqdn = if host.ends_with('.') {
            host.to_string()
        } else {
            format!("{host}.")
        };
        match self.inner.ipv4_lookup(fqdn.as_str()).await {
            Ok(answer) => Ok(answer.iter().map(|a| a.0.to_string()).collect()),
            Err(err) => match err.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => Ok(Vec::new()),
                _ => Err(anyhow::anyhow!("{host}: {err}")),
            },
        }
    }
}

/// Parse `ip` or `ip:port` (IPv6 as `[::1]:53`).
fn parse_resolver(value: &str) -> anyhow::Result<SocketAddr> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = value.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    anyhow::bail!("invalid resolver address {value:?} (expected ip or ip:port)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_resolver_addresses() {
        assert_eq!(parse_resolver("1.1.1.1").unwrap().to_string(), "1.1.1.1:53");
        assert_eq!(parse_resolver("8.8.8.8:5353").unwrap().port(), 5353);
        assert_eq!(parse_resolver("[2606:4700::1111]:53").unwrap().port(), 53);
        assert_eq!(parse_resolver("2606:4700::1111").unwrap().port(), 53);
        assert!(parse_resolver("dns.google").is_err());
    }

    #[tokio::test]
    async fn builds_with_defaults() {
        let r = Resolver::new::<&str>(&[], Duration::from_secs(3)).unwrap();
        assert_eq!(r.resolvers().len(), DEFAULT_RESOLVERS.len());
    }
}
