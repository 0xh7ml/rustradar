//! [Shodan](https://www.shodan.io): DNS domain information.
//!
//! Key: Shodan API key.

use super::prelude::*;

source_info!("shodan", default: true, recursive: false, key: Required);

/// Safety cap on pages.
const MAX_PAGES: u32 = 1000;

/// Shodan DNS API.
pub struct Shodan;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    domain: String,
    subdomains: Vec<String>,
    error: Option<String>,
    more: bool,
}

#[async_trait]
impl Source for Shodan {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        for page in 1..=MAX_PAGES {
            let url = format!(
                "https://api.shodan.io/dns/domain/{}?key={}&page={page}",
                ctx.domain,
                url_encode(&key)
            );
            let response: Response = ctx.get(&url).decode().await?;
            if let Some(error) = response.error.filter(|e| !e.is_empty()) {
                bail!("{error}");
            }
            let apex = if response.domain.is_empty() {
                ctx.domain.clone()
            } else {
                response.domain
            };
            let subs: Vec<String> = response
                .subdomains
                .iter()
                .filter(|s| !s.is_empty())
                .map(|s| format!("{s}.{apex}"))
                .collect();
            if !ctx.emit_all(subs).await {
                break;
            }
            if !response.more {
                break;
            }
        }
        Ok(())
    }
}
