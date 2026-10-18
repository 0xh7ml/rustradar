//! [AlienVault OTX](https://otx.alienvault.com): passive DNS records.
//!
//! Key: OTX API key (`alienvault: [key]`).

use super::prelude::*;

source_info!("alienvault", default: true, recursive: true, key: Required);

/// AlienVault OTX passive DNS.
pub struct AlienVault;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    detail: Option<String>,
    error: Option<String>,
    passive_dns: Vec<Record>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Record {
    hostname: String,
}

#[async_trait]
impl Source for AlienVault {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
            ctx.domain
        );
        let response: Response = ctx.get(&url).bearer(&key).decode().await?;
        if let Some(error) = response.error.filter(|e| !e.is_empty()) {
            bail!("{}, {}", response.detail.unwrap_or_default(), error);
        }
        ctx.emit_all(response.passive_dns.into_iter().map(|r| r.hostname))
            .await;
        Ok(())
    }
}
