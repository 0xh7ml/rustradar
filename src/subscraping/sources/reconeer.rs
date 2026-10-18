//! [Reconeer](https://www.reconeer.com): recon database. Key optional (`X-API-KEY`).

use super::prelude::*;

source_info!("reconeer", default: true, recursive: false, key: Optional);

/// Reconeer domain API.
pub struct Reconeer;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    subdomains: Vec<Entry>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Entry {
    subdomain: String,
}

#[async_trait]
impl Source for Reconeer {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let url = format!("https://www.reconeer.com/api/domain/{}", ctx.domain);
        let mut request = ctx.get(&url).header("Accept", "application/json");
        if let Some(key) = ctx.random_key() {
            request = request.header("X-API-KEY", &key);
        }
        let response: Response = request.decode().await?;
        ctx.emit_all(response.subdomains.into_iter().map(|e| e.subdomain))
            .await;
        Ok(())
    }
}
