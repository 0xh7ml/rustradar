//! [ThreatBook](https://x.threatbook.com): threat intelligence, sub-domains API (`-all`).
//!
//! Key: ThreatBook API key.

use super::prelude::*;

source_info!("threatbook", default: false, recursive: false, key: Required);

/// ThreatBook domain API.
pub struct ThreatBook;

#[async_trait]
impl Source for ThreatBook {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let url = format!(
            "https://api.threatbook.cn/v3/domain/sub_domains?apikey={}&resource={}",
            url_encode(&key),
            ctx.domain
        );
        let body: Value = ctx.get(&url).decode().await?;
        let code = body["response_code"].as_i64().unwrap_or(-1);
        if code != 0 {
            bail!(
                "code {code}, {}",
                body["verbose_msg"].as_str().unwrap_or_default()
            );
        }
        let subs = body["data"]["sub_domains"]["data"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let subs: Vec<String> = subs
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        ctx.emit_all(subs).await;
        Ok(())
    }
}
