//! [Netlas](https://netlas.io): internet scan data, domains index (`-all`).
//!
//! Key: Netlas API key (`X-API-Key`). Counts matches first, then downloads up
//! to 200 results (community tier limit).

use super::prelude::*;

source_info!("netlas", default: false, recursive: false, key: Required);

const DOWNLOAD_CAP: u64 = 200;

/// Netlas domains API.
pub struct Netlas;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Count {
    count: u64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Item {
    data: ItemData,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ItemData {
    domain: String,
}

#[async_trait]
impl Source for Netlas {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let query = format!("domain:*.{} AND NOT domain:{}", ctx.domain, ctx.domain);

        let count_url = format!(
            "https://app.netlas.io/api/domains_count/?q={}",
            url_encode(&query)
        );
        let count: Count = ctx
            .get(&count_url)
            .header("accept", "application/json")
            .header("X-API-Key", &key)
            .decode()
            .await?;
        if count.count == 0 {
            return Ok(());
        }

        let body = json!({
            "q": query,
            "fields": ["*"],
            "source_type": "include",
            "size": count.count.min(DOWNLOAD_CAP),
        });
        let items: Vec<Item> = ctx
            .post("https://app.netlas.io/api/domains/download/")
            .header("accept", "application/json")
            .header("X-API-Key", &key)
            .json(&body)
            .decode()
            .await?;
        ctx.emit_all(items.into_iter().map(|i| i.data.domain)).await;
        Ok(())
    }
}
