//! [BufferOver](https://tls.bufferover.run): TLS certificate and forward DNS datasets.
//!
//! Key: BufferOver API key (sent as `x-api-key`).

use super::prelude::*;

source_info!("bufferover", default: true, recursive: true, key: Required);

/// BufferOver TLS/DNS datasets.
pub struct BufferOver;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    #[serde(rename = "Meta")]
    meta: Meta,
    #[serde(rename = "FDNS_A")]
    fdns_a: Vec<String>,
    #[serde(rename = "RDNS")]
    rdns: Vec<String>,
    #[serde(rename = "Results")]
    results: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Meta {
    #[serde(rename = "Errors")]
    errors: Vec<String>,
}

#[async_trait]
impl Source for BufferOver {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let url = format!("https://tls.bufferover.run/dns?q=.{}", ctx.domain);
        let response: Response = ctx.get(&url).header("x-api-key", &key).decode().await?;
        if !response.meta.errors.is_empty() {
            bail!("{}", response.meta.errors.join(", "));
        }
        // Lines look like "1.2.3.4,host.example.com"; extract the hostnames.
        let lines = if response.fdns_a.is_empty() {
            response.results
        } else {
            [response.fdns_a, response.rdns].concat()
        };
        for line in lines {
            if !ctx.emit_extracted(&line).await {
                break;
            }
        }
        Ok(())
    }
}
