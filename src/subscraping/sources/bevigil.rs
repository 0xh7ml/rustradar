//! [BeVigil](https://bevigil.com/osint-api): subdomains seen in mobile apps.
//!
//! Key: BeVigil OSINT API key.

use super::prelude::*;

source_info!("bevigil", default: true, recursive: false, key: Required);

/// BeVigil OSINT API.
pub struct Bevigil;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    subdomains: Vec<String>,
}

#[async_trait]
impl Source for Bevigil {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let url = format!("https://osint.bevigil.com/api/{}/subdomains/", ctx.domain);
        let response: Response = ctx
            .get(&url)
            .header("X-Access-Token", &key)
            .decode()
            .await?;
        ctx.emit_all(response.subdomains).await;
        Ok(())
    }
}
