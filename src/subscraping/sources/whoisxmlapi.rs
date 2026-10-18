//! [WhoisXML API](https://subdomains.whoisxmlapi.com): subdomains lookup.
//!
//! Key: WhoisXML API key.

use super::prelude::*;

source_info!("whoisxmlapi", default: true, recursive: false, key: Required);

/// WhoisXML subdomains API.
pub struct WhoisXmlApi;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    result: ResultBody,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ResultBody {
    records: Vec<Record>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Record {
    domain: String,
}

#[async_trait]
impl Source for WhoisXmlApi {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let url = format!(
            "https://subdomains.whoisxmlapi.com/api/v1?apiKey={}&domainName={}",
            url_encode(&key),
            ctx.domain
        );
        let response: Response = ctx.get(&url).decode().await?;
        ctx.emit_all(response.result.records.into_iter().map(|r| r.domain))
            .await;
        Ok(())
    }
}
