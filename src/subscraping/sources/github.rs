//! [GitHub code search](https://docs.github.com/en/rest/search): subdomains in public code (`-all`).
//!
//! Key: one or more personal access tokens. Tokens rotate when one hits the
//! search rate limit. For every search hit, both the text-match fragments and
//! the raw file are scanned.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use futures::StreamExt;
use regex::Regex;

use super::prelude::*;

source_info!("github", default: false, recursive: false, key: Required);

/// Raw files fetched concurrently per result page.
const FILE_CONCURRENCY: usize = 10;
/// Safety cap on search requests (GitHub returns at most 10 pages of 100).
const MAX_SEARCH_REQUESTS: usize = 50;

/// GitHub code search.
pub struct GitHub;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    items: Vec<Item>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Item {
    html_url: String,
    text_matches: Vec<TextMatch>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TextMatch {
    fragment: String,
}

/// Round-robin token pool that skips tokens until their rate-limit reset.
struct Tokens {
    pool: Vec<(String, Option<Instant>)>,
    current: usize,
}

impl Tokens {
    fn new(keys: &[String]) -> Self {
        Self {
            pool: keys.iter().map(|k| (k.clone(), None)).collect(),
            current: 0,
        }
    }

    /// Next usable token, or `None` when every token is rate limited.
    fn next(&mut self) -> Option<(usize, String)> {
        let now = Instant::now();
        for _ in 0..self.pool.len() {
            let idx = self.current % self.pool.len();
            self.current += 1;
            let (token, blocked_until) = &mut self.pool[idx];
            if blocked_until.is_some_and(|t| t <= now) {
                *blocked_until = None;
            }
            if blocked_until.is_none() {
                return Some((idx, token.clone()));
            }
        }
        None
    }

    fn block(&mut self, idx: usize, retry_after: Duration) {
        self.pool[idx].1 = Some(Instant::now() + retry_after);
    }
}

#[async_trait]
impl Source for GitHub {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        if ctx.keys().is_empty() {
            return Ok(());
        }
        let tokens = Mutex::new(Tokens::new(ctx.keys()));
        let pattern = Regex::new(&format!(
            r"(\w[a-zA-Z0-9][a-zA-Z0-9\-\.]*){}",
            regex::escape(&ctx.domain)
        ))?;
        let mut next_url = Some(format!(
            "https://api.github.com/search/code?per_page=100&q={}&sort=created&order=asc",
            url_encode(&ctx.domain)
        ));

        let mut requests = 0;
        while let Some(url) = next_url.take() {
            requests += 1;
            if requests > MAX_SEARCH_REQUESTS {
                break;
            }
            let picked = tokens
                .lock()
                .map_err(|_| anyhow::anyhow!("token lock poisoned"))?
                .next();
            let Some((idx, token)) = picked else {
                bail!("github rate limit reached on every token, results may be incomplete");
            };
            let response = ctx
                .get(&url)
                .header("Accept", "application/vnd.github.v3.text-match+json")
                .header("Authorization", &format!("token {token}"))
                .send_raw()
                .await?;

            let header = |name: &str| {
                response
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(String::from)
            };
            let status = response.status().as_u16();
            if status == 403 || status == 429 {
                let remaining = header("X-Ratelimit-Remaining").and_then(|v| v.parse::<u64>().ok());
                if remaining == Some(0) || status == 429 {
                    let retry = header("Retry-After")
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(60);
                    if let Ok(mut t) = tokens.lock() {
                        t.block(idx, Duration::from_secs(retry));
                    }
                    next_url = Some(url); // retry the same page with another token
                    continue;
                }
            }
            if status != 200 {
                bail!("unexpected status code {status} received from github search");
            }

            next_url = header("Link").and_then(|link| next_link(&link));
            let data: Response = ctx.read_json(response).await?;

            for item in &data.items {
                for m in &item.text_matches {
                    for sub in find(&pattern, &m.fragment) {
                        if !ctx.emit(sub).await {
                            return Ok(());
                        }
                    }
                }
            }

            let urls: Vec<String> = data
                .items
                .iter()
                .map(|item| raw_url(&item.html_url))
                .collect();
            let mut files = futures::stream::iter(urls)
                .map(|url| async move { ctx.get(&url).send_raw().await.map(|r| (url, r)) })
                .buffer_unordered(FILE_CONCURRENCY);
            while let Some(result) = files.next().await {
                let (url, response) = match result {
                    Ok(r) => r,
                    Err(err) => {
                        ctx.error(format!("{err:#}")).await;
                        continue;
                    }
                };
                match response.status().as_u16() {
                    200 => {}
                    404 => continue,
                    status => {
                        ctx.error(format!(
                            "unexpected status code {status} received from {url}"
                        ))
                        .await;
                        continue;
                    }
                }
                let Ok(body) = ctx.read_text(response).await else {
                    continue;
                };
                for line in body.lines().filter(|l| !l.is_empty()) {
                    for sub in find(&pattern, line) {
                        if !ctx.emit(sub).await {
                            return Ok(());
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Matches in content after URL-decoding and removing literal `\t` / `\n`.
fn find(pattern: &Regex, content: &str) -> Vec<String> {
    let normalized = url_decode(content).replace("\\t", "").replace("\\n", "");
    pattern
        .find_iter(&normalized)
        .map(|m| m.as_str().to_string())
        .collect()
}

/// `https://github.com/o/r/blob/sha/f` -> `https://raw.githubusercontent.com/o/r/sha/f`.
fn raw_url(html_url: &str) -> String {
    html_url
        .replace("https://github.com/", "https://raw.githubusercontent.com/")
        .replacen("/blob/", "/", 1)
}

/// The `rel="next"` URL from a `Link` header.
fn next_link(header: &str) -> Option<String> {
    header.split(',').find_map(|part| {
        let (url, params) = part.split_once(';')?;
        params
            .split(';')
            .any(|p| p.trim() == r#"rel="next""#)
            .then(|| {
                url.trim()
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .to_string()
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_link_header() {
        let h = r#"<https://api.github.com/search/code?page=2>; rel="next", <https://api.github.com/search/code?page=5>; rel="last""#;
        assert_eq!(
            next_link(h).as_deref(),
            Some("https://api.github.com/search/code?page=2")
        );
        assert_eq!(next_link(r#"<https://x>; rel="prev""#), None);
    }

    #[test]
    fn raw_urls() {
        assert_eq!(
            raw_url("https://github.com/o/r/blob/abc/dir/file.txt"),
            "https://raw.githubusercontent.com/o/r/abc/dir/file.txt"
        );
    }

    #[test]
    fn token_rotation() {
        let mut t = Tokens::new(&["a".into(), "b".into()]);
        let (i, tok) = t.next().unwrap();
        assert_eq!(tok, "a");
        t.block(i, Duration::from_secs(60));
        assert_eq!(t.next().unwrap().1, "b");
        assert_eq!(t.next().unwrap().1, "b");
        let (i, _) = t.next().unwrap();
        t.block(i, Duration::from_secs(60));
        assert!(t.next().is_none());
    }
}
