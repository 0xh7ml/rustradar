//! [Subdomain Center](https://www.subdomain.center): subdomain aggregator.
//!
//! Key optional. Without a key one page is returned; with a key results are
//! paginated (`X-Truncated` / `X-Next-Offset` headers). Append `:crawl` to the
//! key (`KEY:crawl`) to request a fresh crawl.

use super::prelude::*;

source_info!("subdomaincenter", default: true, recursive: true, key: Optional);

const PAGE_SIZE: usize = 10_000;
const MAX_PAGES: usize = 100;

/// Subdomain Center API.
pub struct SubdomainCenter;

#[async_trait]
impl Source for SubdomainCenter {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let (key, crawl) = match ctx.random_key() {
            Some(k) => match k.split_once(':') {
                Some((key, suffix)) if suffix.eq_ignore_ascii_case("crawl") => {
                    (Some(key.to_string()), true)
                }
                _ => (Some(k), false),
            },
            None => (None, false),
        };

        let mut offset = 0;
        for page in 0..MAX_PAGES {
            let mut url = format!(
                "https://api.subdomain.center/?domain={}&engine=cuttlefish",
                url_encode(&ctx.domain)
            );
            if key.is_some() {
                url.push_str(&format!("&limit={PAGE_SIZE}&offset={offset}"));
                if crawl && page == 0 {
                    url.push_str("&crawl=true");
                }
            }
            let mut request = ctx.get(&url).header("Accept", "application/json");
            if let Some(key) = &key {
                request = request.header("X-API-Key", key);
            }
            let response = request.send().await?;
            let header = |name: &str| {
                response
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(String::from)
            };
            let truncated = header("X-Truncated").is_some_and(|v| v.eq_ignore_ascii_case("true"));
            let next = header("X-Next-Offset").and_then(|v| v.parse::<usize>().ok());
            let names: Vec<String> = ctx.read_json(response).await?;

            let count = names.len();
            for name in &names {
                if !ctx.emit_extracted(name).await {
                    return Ok(());
                }
            }
            if key.is_none() || !truncated || count == 0 {
                break;
            }
            offset = next.filter(|n| *n > offset).unwrap_or(offset + count);
        }
        Ok(())
    }
}
