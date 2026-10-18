//! [VirusTotal](https://www.virustotal.com): domain relationships (v3 API),
//! cursor-paginated. Free keys allow 4 requests/minute and 500/day.
//!
//! Key: VirusTotal API key (`x-apikey`).

use super::prelude::*;

source_info!("virustotal", default: true, recursive: true, key: Required);

/// Safety cap on pages.
const MAX_PAGES: usize = 1000;

/// VirusTotal v3 subdomains relationship.
pub struct VirusTotal;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    data: Vec<Object>,
    meta: Meta,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Object {
    id: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Meta {
    cursor: String,
}

#[async_trait]
impl Source for VirusTotal {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let base = format!(
            "https://www.virustotal.com/api/v3/domains/{}/subdomains?limit=40",
            ctx.domain
        );
        let mut cursor = String::new();
        for _ in 0..MAX_PAGES {
            let url = if cursor.is_empty() {
                base.clone()
            } else {
                format!("{base}&cursor={}", url_encode(&cursor))
            };
            let response: Response = match ctx.get(&url).header("x-apikey", &key).decode().await {
                Ok(r) => r,
                Err(err) if status_of(&err) == Some(429) => {
                    bail!("virustotal quota exhausted (HTTP 429); some subdomains for {} may be missing", ctx.domain)
                }
                Err(err) => return Err(err),
            };
            if !ctx.emit_all(response.data.into_iter().map(|o| o.id)).await {
                break;
            }
            if response.meta.cursor.is_empty() || response.meta.cursor == cursor {
                break;
            }
            cursor = response.meta.cursor;
        }
        Ok(())
    }
}
