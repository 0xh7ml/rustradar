//! [Profundis](https://profundis.io): subdomain data, streamed one per line.
//!
//! Key: Profundis API key (`X-API-KEY`).

use super::prelude::*;

source_info!("profundis", default: true, recursive: false, key: Required);

/// Profundis API.
pub struct Profundis;

#[async_trait]
impl Source for Profundis {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let body = ctx
            .post("https://api.profundis.io/api/v2/common/data/subdomains")
            .header("X-API-KEY", &key)
            .header("Accept", "text/event-stream")
            .json(&json!({ "domain": ctx.domain }))
            .text()
            .await?;
        // Event-stream lines may carry a "data:" prefix.
        let subs = body
            .lines()
            .map(|l| l.trim().trim_start_matches("data:").trim().to_string())
            .filter(|l| !l.is_empty())
            .collect::<Vec<String>>();
        ctx.emit_all(subs).await;
        Ok(())
    }
}
