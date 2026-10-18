//! [DNSRepo / DNS Archive](https://dnsarchive.net): DNS records database.
//!
//! Key: `token:apikey` (token sent as `X-API-Access`, key as query parameter).

use super::prelude::*;

source_info!("dnsrepo", default: true, recursive: false, key: Required);

/// DNSRepo (dnsarchive.net).
pub struct DnsRepo;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Entry {
    domain: String,
}

#[async_trait]
impl Source for DnsRepo {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some((token, api_key)) = ctx.random_key_pair() else {
            bail!("invalid key format, expected token:apikey");
        };
        let url = format!(
            "https://dnsarchive.net/api/?apikey={}&search={}",
            url_encode(&api_key),
            ctx.domain
        );
        let entries: Vec<Entry> = ctx
            .get(&url)
            .header("X-API-Access", &token)
            .decode()
            .await?;
        ctx.emit_all(
            entries
                .into_iter()
                .map(|e| e.domain.trim_end_matches('.').to_string()),
        )
        .await;
        Ok(())
    }
}
