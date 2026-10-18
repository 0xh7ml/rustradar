//! [RSECloud](https://rsecloud.com): active and passive subdomain datasets.
//!
//! Key: RSECloud API key (`X-API-Key`).

use super::prelude::*;

source_info!("rsecloud", default: true, recursive: false, key: Required);

/// Safety cap on pages per endpoint.
const MAX_PAGES: u64 = 1000;

/// RSECloud API.
pub struct RseCloud;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    data: Vec<String>,
    total_pages: u64,
}

#[async_trait]
impl Source for RseCloud {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        for endpoint in ["active", "passive"] {
            let mut page = 1;
            loop {
                let url = format!(
                    "https://api.rsecloud.com/api/v2/subdomains/{endpoint}/{}?page={page}",
                    ctx.domain
                );
                let response: Response = match ctx
                    .get(&url)
                    .header("Content-Type", "application/json")
                    .header("X-API-Key", &key)
                    .decode()
                    .await
                {
                    Ok(r) => r,
                    Err(err) => {
                        ctx.error(format!("{endpoint}: {err:#}")).await;
                        break;
                    }
                };
                if !ctx.emit_all(response.data).await {
                    return Ok(());
                }
                if page >= response.total_pages || page >= MAX_PAGES {
                    break;
                }
                page += 1;
            }
        }
        Ok(())
    }
}
