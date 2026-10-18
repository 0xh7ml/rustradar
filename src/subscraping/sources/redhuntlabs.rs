//! [RedHunt Labs](https://devportal.redhuntlabs.com): recon API.
//!
//! Key: `<endpoint URL>:<api key>`, e.g.
//! `https://reconapi.redhuntlabs.com/community/v1/domains/subdomains:KEY`.

use super::prelude::*;

source_info!("redhuntlabs", default: true, recursive: false, key: Required);

const PAGE_SIZE: u64 = 1000;

/// RedHunt Labs recon API.
pub struct RedHuntLabs;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    subdomains: Vec<String>,
    metadata: Metadata,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Metadata {
    result_count: u64,
}

#[async_trait]
impl Source for RedHuntLabs {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(raw) = ctx.random_key() else {
            return Ok(());
        };
        // "https://host/path:KEY" -> split at the last ':'.
        let Some((base, key)) = raw
            .rsplit_once(':')
            .filter(|(b, k)| b.contains("://") && !k.is_empty())
        else {
            bail!("invalid key format, expected <endpoint url>:<api key>");
        };
        let fetch = |page: u64| {
            let url = format!(
                "{base}?domain={}&page={page}&page_size={PAGE_SIZE}",
                ctx.domain
            );
            async move {
                ctx.get(&url)
                    .header("X-BLOBR-KEY", key)
                    .header("User-Agent", "rustradar")
                    .decode::<Response>()
                    .await
            }
        };

        let first = fetch(1).await?;
        let total_pages = first.metadata.result_count.div_ceil(PAGE_SIZE);
        if !ctx.emit_all(first.subdomains).await {
            return Ok(());
        }
        for page in 2..=total_pages {
            match fetch(page).await {
                Ok(response) => {
                    if !ctx.emit_all(response.subdomains).await {
                        break;
                    }
                }
                Err(err) => ctx.error(format!("{err:#}")).await,
            }
        }
        Ok(())
    }
}
