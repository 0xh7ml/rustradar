//! [FullHunt](https://fullhunt.io): attack surface database.
//!
//! Key: FullHunt API key (`X-API-KEY`).

use super::prelude::*;

source_info!("fullhunt", default: true, recursive: false, key: Required);

/// FullHunt API.
pub struct FullHunt;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    hosts: Vec<String>,
}

#[async_trait]
impl Source for FullHunt {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let url = format!(
            "https://fullhunt.io/api/v1/domain/{}/subdomains",
            ctx.domain
        );
        let response: Response = ctx.get(&url).header("X-API-KEY", &key).decode().await?;
        ctx.emit_all(response.hosts).await;
        Ok(())
    }
}
