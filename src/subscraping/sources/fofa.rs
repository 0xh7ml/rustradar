//! [FOFA](https://fofa.info): cyberspace search engine.
//!
//! Key: `email:key`.

use base64::Engine as _;

use super::prelude::*;

source_info!("fofa", default: true, recursive: false, key: Required);

/// FOFA search API.
pub struct Fofa;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    error: bool,
    errmsg: String,
    size: u64,
    results: Vec<String>,
}

#[async_trait]
impl Source for Fofa {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some((email, key)) = ctx.random_key_pair() else {
            bail!("invalid key format, expected email:key");
        };
        let query =
            base64::engine::general_purpose::STANDARD.encode(format!("domain=\"{}\"", ctx.domain));
        let url = format!(
            "https://fofa.info/api/v1/search/all?full=true&fields=host&page=1&size=10000&email={}&key={}&qbase64={}",
            url_encode(&email),
            url_encode(&key),
            url_encode(&query)
        );
        let response: Response = ctx.get(&url).decode().await?;
        if response.error {
            bail!("{}", response.errmsg);
        }
        if response.size > 0 {
            // Results are "host", "host:port" or "https://host:port".
            let hosts: Vec<String> = response.results.iter().map(|r| host_of(r)).collect();
            ctx.emit_all(hosts).await;
        }
        Ok(())
    }
}
