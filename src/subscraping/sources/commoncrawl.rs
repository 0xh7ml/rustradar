//! [Common Crawl](https://index.commoncrawl.org): URL index of web crawls (slow, `-all`). No key.
//!
//! Queries the first crawl index of each of the last five years.

use super::prelude::*;
use crate::subscraping::utils::current_year;

source_info!("commoncrawl", default: false, recursive: false, key: None);

const INDEX_URL: &str = "https://index.commoncrawl.org/collinfo.json";
const MAX_YEARS_BACK: i64 = 5;

/// Common Crawl CDX index.
pub struct CommonCrawl;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Index {
    id: String,
    #[serde(rename = "cdx-api")]
    api_url: String,
}

#[async_trait]
impl Source for CommonCrawl {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let indexes: Vec<Index> = ctx.get(INDEX_URL).decode().await?;
        let year = current_year();
        for y in (0..MAX_YEARS_BACK).map(|i| (year - i).to_string()) {
            // collinfo.json is newest-first, so this is the latest crawl of the year.
            let Some(index) = indexes.iter().find(|i| i.id.contains(&y)) else {
                continue;
            };
            let url = format!("{}?url=*.{}", index.api_url, ctx.domain);
            let body = match ctx.get(&url).text().await {
                Ok(body) => body,
                Err(err) => {
                    ctx.error(format!("{err:#}")).await;
                    continue;
                }
            };
            for line in body.lines().filter(|l| !l.is_empty()) {
                let line = url_decode(line);
                for sub in ctx.extract(&line) {
                    // Leftovers of %25 / %2f encodings glued to the hostname.
                    let sub = sub
                        .strip_prefix("25")
                        .or_else(|| sub.strip_prefix("2f"))
                        .map(String::from)
                        .unwrap_or(sub);
                    if !ctx.emit(sub).await {
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }
}
