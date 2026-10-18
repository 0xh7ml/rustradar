//! Offline tests of the HTTP layer (`Ctx` requests, status handling, body
//! cap, rate limiting) against a minimal local HTTP server.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rustradar::passive::{Agent, EnumerationOptions, ProviderKeys, RateLimit, RateLimiter};
use rustradar::subscraping::{Ctx, KeyRequirement, Source, SourceInfo, SourceResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Start a server that answers by path:
/// `/subs` -> 200 with two subdomains, `/missing` -> 404,
/// `/ua` -> 200 echoing the User-Agent and X-Test headers.
async fn server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut read = 0;
                loop {
                    let n = socket.read(&mut buf[read..]).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    read += n;
                    if buf[..read].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&buf[..read]).to_string();
                let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();
                let header = |name: &str| {
                    request
                        .lines()
                        .find_map(|l| {
                            l.split_once(':')
                                .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                                .map(|(_, v)| v.trim().to_string())
                        })
                        .unwrap_or_default()
                };
                let (status, body) = match path.as_str() {
                    "/subs" => (
                        "200 OK",
                        "api.example.com,1.1.1.1\nwww.example.com,2.2.2.2\n".to_string(),
                    ),
                    "/ua" => (
                        "200 OK",
                        format!("{}|{}", header("user-agent"), header("x-test")),
                    ),
                    _ => ("404 Not Found", "nope".to_string()),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

/// A test source that fetches `{base}{path}` `times` times and emits matches.
struct Probe {
    base: String,
    path: &'static str,
    times: usize,
}

static PROBE: SourceInfo = SourceInfo {
    name: "probe",
    is_default: true,
    recursive: false,
    key: KeyRequirement::None,
};

#[async_trait]
impl Source for Probe {
    fn info(&self) -> &'static SourceInfo {
        &PROBE
    }

    async fn run(&self, ctx: &Ctx) -> anyhow::Result<()> {
        for _ in 0..self.times {
            let body = ctx
                .get(&format!("{}{}", self.base, self.path))
                .header("X-Test", "yes")
                .text()
                .await?;
            if self.path == "/ua" {
                ctx.emit(format!("{body}.example.com")).await;
            } else {
                ctx.emit_extracted(&body).await;
            }
        }
        Ok(())
    }
}

async fn run(
    source: Probe,
    options: EnumerationOptions,
    limiter: Option<Arc<RateLimiter>>,
) -> (Vec<String>, Vec<String>) {
    let agent = Agent::with_sources(vec![Arc::new(source)], ProviderKeys::new());
    let client =
        rustradar::subscraping::session::build_client(None, Duration::from_secs(5)).unwrap();
    let mut rx = agent.enumerate("example.com", client, limiter, &options);
    let (mut subs, mut errors) = (Vec::new(), Vec::new());
    while let Some(result) = rx.recv().await {
        match result {
            SourceResult::Subdomain { value, .. } => subs.push(value),
            SourceResult::Error { error, .. } => errors.push(error),
        }
    }
    (subs, errors)
}

#[tokio::test]
async fn extracts_from_response_body() {
    let base = server().await;
    let (subs, errors) = run(
        Probe {
            base,
            path: "/subs",
            times: 1,
        },
        EnumerationOptions::default(),
        None,
    )
    .await;
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(subs, vec!["api.example.com", "www.example.com"]);
}

#[tokio::test]
async fn non_200_becomes_source_error() {
    let base = server().await;
    let (subs, errors) = run(
        Probe {
            base,
            path: "/missing",
            times: 1,
        },
        EnumerationOptions::default(),
        None,
    )
    .await;
    assert!(subs.is_empty());
    assert_eq!(errors.len(), 1);
    assert!(
        errors[0].contains("unexpected status code 404"),
        "{}",
        errors[0]
    );
}

#[tokio::test]
async fn caps_response_body() {
    let base = server().await;
    let mut options = EnumerationOptions::default();
    options.session.max_body_size = 20; // fits "api.example.com,1.1." only
    let (subs, _) = run(
        Probe {
            base,
            path: "/subs",
            times: 1,
        },
        options,
        None,
    )
    .await;
    assert_eq!(subs, vec!["api.example.com"]);
}

#[tokio::test]
async fn sends_browser_user_agent_and_custom_headers() {
    let base = server().await;
    let (subs, _) = run(
        Probe {
            base,
            path: "/ua",
            times: 1,
        },
        EnumerationOptions::default(),
        None,
    )
    .await;
    assert_eq!(subs.len(), 1);
    assert!(subs[0].starts_with("Mozilla/5.0"), "{}", subs[0]);
    assert!(subs[0].ends_with("|yes.example.com"), "{}", subs[0]);
}

#[tokio::test]
async fn shared_rate_limiter_paces_requests() {
    let base = server().await;
    let mut custom = HashMap::new();
    custom.insert(
        "probe".to_string(),
        RateLimit {
            max_count: 2,
            period: Duration::from_millis(500),
        },
    );
    let limiter = Arc::new(RateLimiter::new(&["probe"], 0, &custom));
    let started = Instant::now();
    let (subs, errors) = run(
        Probe {
            base,
            path: "/subs",
            times: 5,
        },
        EnumerationOptions::default(),
        Some(limiter),
    )
    .await;
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(subs.len(), 10);
    // 5 requests at 2 per 500ms need at least two full windows.
    assert!(
        started.elapsed() >= Duration::from_millis(1000),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn enumeration_deadline_cancels_slow_sources() {
    let base = server().await;
    let mut custom = HashMap::new();
    custom.insert(
        "probe".to_string(),
        RateLimit {
            max_count: 1,
            period: Duration::from_secs(60),
        },
    );
    let limiter = Arc::new(RateLimiter::new(&["probe"], 0, &custom));
    let options = EnumerationOptions {
        max_enumeration_time: Duration::from_millis(300),
        ..Default::default()
    };
    let started = Instant::now();
    let (subs, errors) = run(
        Probe {
            base,
            path: "/subs",
            times: 3,
        },
        options,
        Some(limiter),
    )
    .await;
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(subs.len(), 2); // first request only
    assert!(
        errors.iter().any(|e| e.contains("time limit")),
        "{errors:?}"
    );
}
