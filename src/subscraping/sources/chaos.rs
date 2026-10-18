//! [Chaos](https://chaos.projectdiscovery.io): ProjectDiscovery's bug-bounty DNS dataset.
//!
//! Key: Chaos API key.

use super::prelude::*;

source_info!("chaos", default: true, recursive: false, key: Required);

/// ProjectDiscovery Chaos.
pub struct Chaos;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    domain: String,
    subdomains: Vec<String>,
}

#[async_trait]
impl Source for Chaos {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let url = format!(
            "https://dns.projectdiscovery.io/dns/{}/subdomains",
            ctx.domain
        );
        let response: Response = ctx.get(&url).header("Authorization", &key).decode().await?;
        let apex = if response.domain.is_empty() {
            ctx.domain.clone()
        } else {
            response.domain
        };
        // The API returns labels relative to the apex ("www", "api.dev").
        let subs = response
            .subdomains
            .into_iter()
            .filter(|s| !s.is_empty())
            .map(|s| format!("{s}.{apex}"));
        ctx.emit_all(subs).await;
        Ok(())
    }
}
