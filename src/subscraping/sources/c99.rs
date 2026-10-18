//! [C99](https://api.c99.nl): subdomain finder API.
//!
//! Key: C99 API key.

use super::prelude::*;

source_info!("c99", default: true, recursive: false, key: Required);

/// C99 subdomain finder.
pub struct C99;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    subdomains: Vec<Entry>,
    error: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Entry {
    subdomain: String,
}

#[async_trait]
impl Source for C99 {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let url = format!(
            "https://api.c99.nl/subdomainfinder?key={}&domain={}&json",
            url_encode(&key),
            ctx.domain
        );
        let response: Response = ctx.get(&url).decode().await?;
        if let Some(error) = response.error.filter(|e| !e.is_empty()) {
            bail!("{error}");
        }
        let subs = response
            .subdomains
            .into_iter()
            .map(|e| e.subdomain)
            .filter(|s| !s.starts_with('.'));
        ctx.emit_all(subs).await;
        Ok(())
    }
}
