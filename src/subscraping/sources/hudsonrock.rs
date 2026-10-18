//! [Hudson Rock](https://www.hudsonrock.com/free-tools): infostealer intelligence,
//! URLs seen in compromised credentials (`-all`). No key.

use super::prelude::*;

source_info!("hudsonrock", default: false, recursive: false, key: None);

/// Hudson Rock Cavalier OSINT tools.
pub struct HudsonRock;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    data: Data,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Data {
    employees_urls: Vec<UrlEntry>,
    clients_urls: Vec<UrlEntry>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct UrlEntry {
    url: String,
}

#[async_trait]
impl Source for HudsonRock {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let url = format!(
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain?domain={}",
            ctx.domain
        );
        let response: Response = ctx.get(&url).decode().await?;
        for entry in response
            .data
            .employees_urls
            .iter()
            .chain(&response.data.clients_urls)
        {
            if !ctx.emit_extracted(&entry.url).await {
                break;
            }
        }
        Ok(())
    }
}
