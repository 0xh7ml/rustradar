//! [Merklemap](https://www.merklemap.com): certificate transparency search engine (`-all`).
//!
//! Key: Merklemap API key (Bearer).

use super::prelude::*;

source_info!("merklemap", default: false, recursive: true, key: Required);

/// Safety cap on pages.
const MAX_PAGES: usize = 1000;

/// Merklemap search.
pub struct MerkleMap;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    count: usize,
    results: Vec<Entry>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Entry {
    hostname: String,
}

#[async_trait]
impl Source for MerkleMap {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let base = format!(
            "https://api.merklemap.com/v1/search?query={}",
            url_encode(&format!("*.{}", ctx.domain))
        );
        let mut total = usize::MAX;
        let mut processed = 0;
        for page in 0..MAX_PAGES {
            if processed >= total {
                break;
            }
            let url = format!("{base}&page={page}");
            let response: Response = ctx
                .get(&url)
                .header("accept", "application/json")
                .header("User-Agent", "rustradar")
                .bearer(&key)
                .decode()
                .await?;
            if page == 0 {
                total = response.count;
            }
            if response.results.is_empty() {
                break;
            }
            processed += response.results.len();
            if !ctx
                .emit_all(response.results.into_iter().map(|e| e.hostname))
                .await
            {
                break;
            }
        }
        Ok(())
    }
}
