//! [DNSDumpster](https://dnsdumpster.com/developer/): DNS recon API.
//!
//! Key: DNSDumpster API key (`X-API-Key`).

use super::prelude::*;

source_info!("dnsdumpster", default: true, recursive: false, key: Required);

/// DNSDumpster API.
pub struct DnsDumpster;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    a: Vec<Record>,
    ns: Vec<Record>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Record {
    host: String,
}

#[async_trait]
impl Source for DnsDumpster {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let url = format!("https://api.dnsdumpster.com/domain/{}", ctx.domain);
        let response: Response = ctx.get(&url).header("X-API-Key", &key).decode().await?;
        ctx.emit_all(response.a.into_iter().chain(response.ns).map(|r| r.host))
            .await;
        Ok(())
    }
}
