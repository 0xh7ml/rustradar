//! [LeakIX](https://leakix.net): leak and exposure intelligence.
//!
//! Key: LeakIX API key (`api-key` header).

use super::prelude::*;

source_info!("leakix", default: true, recursive: true, key: Required);

/// LeakIX subdomains API.
pub struct LeakIx;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Entry {
    subdomain: String,
}

#[async_trait]
impl Source for LeakIx {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let url = format!("https://leakix.net/api/subdomains/{}", ctx.domain);
        let mut request = ctx.get(&url).header("accept", "application/json");
        if let Some(key) = ctx.random_key() {
            request = request.header("api-key", &key);
        }
        let entries: Vec<Entry> = request.decode().await?;
        ctx.emit_all(entries.into_iter().map(|e| e.subdomain)).await;
        Ok(())
    }
}
