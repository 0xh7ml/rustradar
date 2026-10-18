//! [Chinaz](https://data.chinaz.com): Alexa-style traffic data with contributing subdomains.
//!
//! Key: Chinaz API key.

use super::prelude::*;

source_info!("chinaz", default: true, recursive: false, key: Required);

/// Chinaz Alexa data API.
pub struct Chinaz;

#[async_trait]
impl Source for Chinaz {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let url = format!(
            "https://apidatav2.chinaz.com/single/alexa?key={}&domain={}",
            url_encode(&key),
            ctx.domain
        );
        let body: Value = ctx.get(&url).decode().await?;
        let Some(list) = body["Result"]["ContributingSubdomainList"].as_array() else {
            return Ok(());
        };
        let subs: Vec<String> = list
            .iter()
            .filter_map(|item| item["DataUrl"].as_str().map(String::from))
            .collect();
        ctx.emit_all(subs).await;
        Ok(())
    }
}
