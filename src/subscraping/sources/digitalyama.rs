//! [DigitalYama](https://digitalyama.com): subdomain finder API.
//!
//! Key: DigitalYama API key (`x-api-key`).

use super::prelude::*;

source_info!("digitalyama", default: true, recursive: false, key: Required);

/// DigitalYama subdomain finder.
pub struct DigitalYama;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    subdomains: Vec<String>,
}

#[async_trait]
impl Source for DigitalYama {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let url = format!(
            "https://api.digitalyama.com/subdomain_finder?domain={}",
            ctx.domain
        );
        let response = ctx.get(&url).header("x-api-key", &key).send_raw().await?;
        let status = response.status().as_u16();
        if status != 200 {
            // Errors look like {"detail":[{"msg":"..."}]}.
            let body: Value = ctx.read_json(response).await.unwrap_or_default();
            let msg = body["detail"][0]["msg"]
                .as_str()
                .unwrap_or("unexpected response");
            bail!("HTTP {status}: {msg}");
        }
        let response: Response = ctx.read_json(response).await?;
        ctx.emit_all(response.subdomains).await;
        Ok(())
    }
}
