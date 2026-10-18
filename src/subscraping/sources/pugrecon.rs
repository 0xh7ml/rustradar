//! [PugRecon](https://pugrecon.com): subdomain API (`-all`).
//!
//! Key: PugRecon API token (Bearer).

use super::prelude::*;

source_info!("pugrecon", default: false, recursive: false, key: Required);

/// PugRecon API.
pub struct PugRecon;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    results: Vec<Entry>,
    message: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Entry {
    name: String,
}

#[async_trait]
impl Source for PugRecon {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let response = ctx
            .post("https://pugrecon.com/api/v1/domains")
            .bearer(&key)
            .header("Accept", "application/json")
            .json(&json!({ "domain_name": ctx.domain }))
            .send_raw()
            .await?;
        let status = response.status().as_u16();
        let body: Response = ctx.read_json(response).await.unwrap_or_default();
        if status != 200 {
            bail!("received status code {status}: {}", body.message);
        }
        ctx.emit_all(body.results.into_iter().map(|e| e.name)).await;
        Ok(())
    }
}
