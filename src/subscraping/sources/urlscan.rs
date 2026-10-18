//! [urlscan.io](https://urlscan.io): website scan search.
//!
//! Key: urlscan API key (`api-key`). Fetches up to 5 pages of 100 results,
//! paginating with `search_after`.

use super::prelude::*;

source_info!("urlscan", default: true, recursive: true, key: Required);

const MAX_PAGES: usize = 5;
const PAGE_SIZE: usize = 100;

/// urlscan.io search API.
pub struct UrlScan;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    results: Vec<Hit>,
    has_more: bool,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Hit {
    task: Location,
    page: Location,
    sort: Vec<Value>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Location {
    domain: String,
    url: String,
}

#[async_trait]
impl Source for UrlScan {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let mut search_after: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut url = format!(
                "https://urlscan.io/api/v1/search/?q=domain:{}&size={PAGE_SIZE}",
                url_encode(&ctx.domain)
            );
            if let Some(after) = &search_after {
                url.push_str(&format!("&search_after={}", url_encode(after)));
            }
            let response: Response = ctx.get(&url).header("api-key", &key).decode().await?;

            for hit in &response.results {
                let candidates = [
                    hit.task.domain.clone(),
                    hit.page.domain.clone(),
                    host_of(&hit.task.url),
                    host_of(&hit.page.url),
                ];
                for candidate in candidates.iter().filter(|c| !c.is_empty()) {
                    if !ctx.emit_extracted(candidate).await {
                        return Ok(());
                    }
                }
            }

            let Some(last) = response.results.last() else {
                break;
            };
            if !response.has_more || last.sort.is_empty() {
                break;
            }
            let values: Vec<String> = last
                .sort
                .iter()
                .map(|v| match v {
                    Value::Number(n) => n
                        .as_f64()
                        .map(|f| format!("{f:.0}"))
                        .unwrap_or_else(|| n.to_string()),
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect();
            search_after = Some(values.join(","));
        }
        Ok(())
    }
}
