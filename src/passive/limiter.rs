//! Fixed-window rate limiter shared by every domain worker in a batch.
//!
//! Each source gets its own budget of `limit` requests per `period`. All
//! domains enumerated concurrently draw from the **same** budget, so running
//! 25 domains in parallel does not multiply the request rate against a
//! provider and burn through its quota.
//!
//! Window boundaries stay anchored to the limiter's creation time, even after
//! idle periods, so bursts cannot exceed `limit` within any aligned window.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

/// A `count/period` rate limit, e.g. `10/s` or `4/m`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Requests allowed per period. Must be > 0.
    pub max_count: u32,
    /// Window length.
    pub period: Duration,
}

impl RateLimit {
    /// `count` requests per second.
    pub fn per_second(count: u32) -> Self {
        Self {
            max_count: count,
            period: Duration::from_secs(1),
        }
    }
}

impl fmt::Display for RateLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let unit = match self.period.as_millis() {
            1 => "ms",
            1_000 => "s",
            60_000 => "m",
            3_600_000 => "h",
            ms => return write!(f, "{}/{}ms", self.max_count, ms),
        };
        write!(f, "{}/{}", self.max_count, unit)
    }
}

impl FromStr for RateLimit {
    type Err = String;

    /// Parse `N`, `N/ms`, `N/s`, `N/m` or `N/h`. A bare number means per second.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        let (count, unit) = value.split_once('/').unwrap_or((value, "s"));
        let max_count: u32 = count
            .trim()
            .parse()
            .map_err(|_| format!("invalid rate limit count in {value:?}"))?;
        if max_count == 0 {
            return Err(format!("rate limit count must be > 0 in {value:?}"));
        }
        let period = match unit.trim() {
            "ms" => Duration::from_millis(1),
            "s" | "sec" => Duration::from_secs(1),
            "m" | "min" => Duration::from_secs(60),
            "h" | "hour" => Duration::from_secs(3600),
            other => {
                return Err(format!(
                    "invalid rate limit unit {other:?} (use ms, s, m or h)"
                ))
            }
        };
        Ok(Self { max_count, period })
    }
}

/// Parse `source=limit` pairs (as given to `-rls`) into a map.
pub fn parse_rate_limits<S: AsRef<str>>(pairs: &[S]) -> Result<HashMap<String, RateLimit>, String> {
    let mut map = HashMap::new();
    for pair in pairs {
        let pair = pair.as_ref().trim();
        if pair.is_empty() {
            continue;
        }
        let (name, limit) = pair
            .split_once('=')
            .ok_or_else(|| format!("invalid rate limit {pair:?}, expected source=N/unit"))?;
        map.insert(name.trim().to_lowercase(), limit.parse()?);
    }
    Ok(map)
}

/// Built-in per-provider limits (from subfinder), applied unless overridden.
pub const DEFAULT_RATE_LIMITS: &[&str] = &[
    "github=83/m",
    "fullhunt=60/m",
    "pugrecon=10/s",
    "securitytrails=2/s",
    "shodan=1/s",
    "virustotal=4/m",
    "hackertarget=2/s",
    "waybackarchive=15/m",
    "whoisxmlapi=50/s",
    "sitedossier=8/m",
    "netlas=1/s",
    "hudsonrock=5/s",
    "urlscan=1/s",
];

#[derive(Debug)]
struct Budget {
    limit: u32,
    remaining: u32,
    period: Duration,
    start: Instant,
}

/// Shared per-source rate limiter. Cheap to share behind an `Arc`.
#[derive(Debug, Default)]
pub struct RateLimiter {
    /// `None` = unlimited for that source.
    budgets: HashMap<String, Option<Mutex<Budget>>>,
}

impl RateLimiter {
    /// Build a limiter for `sources`.
    ///
    /// For each source: a `custom` limit wins; otherwise `global_per_second`
    /// (`-rl`) applies when > 0; otherwise the source is unlimited.
    pub fn new<S: AsRef<str>>(
        sources: &[S],
        global_per_second: u32,
        custom: &HashMap<String, RateLimit>,
    ) -> Self {
        let now = Instant::now();
        let budgets = sources
            .iter()
            .map(|name| {
                let name = name.as_ref().to_string();
                let limit = custom.get(&name).copied().or_else(|| {
                    (global_per_second > 0).then(|| RateLimit::per_second(global_per_second))
                });
                let budget = limit.map(|l| {
                    Mutex::new(Budget {
                        limit: l.max_count,
                        remaining: l.max_count,
                        period: l.period,
                        start: now,
                    })
                });
                (name, budget)
            })
            .collect();
        Self { budgets }
    }

    /// Wait until `source` may send one request.
    ///
    /// Unknown sources are unlimited. Cancellation is handled by dropping the
    /// returned future (e.g. when the enumeration deadline passes).
    pub async fn wait(&self, source: &str) -> anyhow::Result<()> {
        let Some(Some(budget)) = self.budgets.get(source) else {
            return Ok(());
        };
        loop {
            let delay = {
                let mut b = budget
                    .lock()
                    .map_err(|_| anyhow::anyhow!("rate limiter lock poisoned"))?;
                let now = Instant::now();
                let mut elapsed = now.duration_since(b.start);
                if elapsed >= b.period {
                    // Re-anchor to the most recent window boundary.
                    let periods = elapsed.as_nanos() / b.period.as_nanos();
                    let offset = b.period.as_nanos() * periods;
                    b.start += Duration::from_nanos(offset.min(u64::MAX as u128) as u64);
                    b.remaining = b.limit;
                    elapsed = now.duration_since(b.start);
                }
                if b.remaining > 0 {
                    b.remaining -= 1;
                    return Ok(());
                }
                b.period.saturating_sub(elapsed)
            };
            tokio::time::sleep(delay.max(Duration::from_millis(1))).await;
        }
    }

    /// The configured limit for a source, if any (for diagnostics).
    pub fn limit_for(&self, source: &str) -> Option<RateLimit> {
        let budget = self.budgets.get(source)?.as_ref()?;
        let b = budget.lock().ok()?;
        Some(RateLimit {
            max_count: b.limit,
            period: b.period,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_limits() {
        assert_eq!(
            "10/s".parse::<RateLimit>().unwrap(),
            RateLimit::per_second(10)
        );
        assert_eq!(
            "4/m".parse::<RateLimit>().unwrap(),
            RateLimit {
                max_count: 4,
                period: Duration::from_secs(60)
            }
        );
        assert_eq!("7".parse::<RateLimit>().unwrap(), RateLimit::per_second(7));
        assert!("0/s".parse::<RateLimit>().is_err());
        assert!("5/d".parse::<RateLimit>().is_err());
        assert!("x/s".parse::<RateLimit>().is_err());
    }

    #[test]
    fn parses_pairs() {
        let map = parse_rate_limits(&["GitHub=80/m", " shodan = 1/s "]).unwrap();
        assert_eq!(map["github"].max_count, 80);
        assert_eq!(map["shodan"], RateLimit::per_second(1));
        assert!(parse_rate_limits(&["github"]).is_err());
    }

    #[test]
    fn defaults_parse() {
        parse_rate_limits(DEFAULT_RATE_LIMITS).unwrap();
    }

    #[test]
    fn display_round_trips() {
        for s in ["10/s", "4/m", "1/h", "3/ms"] {
            assert_eq!(s.parse::<RateLimit>().unwrap().to_string(), s);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn enforces_window() {
        let mut custom = HashMap::new();
        custom.insert("a".to_string(), "2/s".parse().unwrap());
        let limiter = RateLimiter::new(&["a", "b"], 0, &custom);

        let start = Instant::now();
        for _ in 0..5 {
            limiter.wait("a").await.unwrap();
        }
        // 2 in window 0, 2 in window 1, 1 in window 2 => at least 2s.
        assert!(start.elapsed() >= Duration::from_secs(2));
        assert!(start.elapsed() < Duration::from_secs(3));

        // Unlimited source never waits.
        let start = Instant::now();
        for _ in 0..1000 {
            limiter.wait("b").await.unwrap();
        }
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn global_limit_applies_without_custom() {
        let limiter = RateLimiter::new(&["x"], 3, &HashMap::new());
        assert_eq!(limiter.limit_for("x"), Some(RateLimit::per_second(3)));
        let start = Instant::now();
        for _ in 0..4 {
            limiter.wait("x").await.unwrap();
        }
        assert!(start.elapsed() >= Duration::from_secs(1));
    }
}
