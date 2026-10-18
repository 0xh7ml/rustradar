//! [ZoomEye](https://www.zoomeye.ai): cyberspace search, v2 API (`-all`).
//!
//! Key: `host:key`, where host is the API domain without the `api.` prefix,
//! e.g. `zoomeye.ai:KEY` or `zoomeye.hk:KEY`.

use base64::Engine as _;

use super::prelude::*;

source_info!("zoomeyeapi", default: false, recursive: false, key: Required);

const PAGE_SIZE: u64 = 1000;
const MAX_PAGES: u64 = 1000;

/// ZoomEye search API.
pub struct ZoomEyeApi;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    code: i64,
    total: u64,
    data: Vec<Entry>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Entry {
    domain: String,
}

#[async_trait]
impl Source for ZoomEyeApi {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some((host, key)) = ctx.random_key_pair() else {
            bail!("invalid key format, expected host:key (e.g. zoomeye.ai:KEY)");
        };
        let query =
            base64::engine::general_purpose::STANDARD.encode(format!("domain=\"{}\"", ctx.domain));
        let url = format!("https://api.{host}/v2/search");
        for page in 1..=MAX_PAGES {
            let body = json!({
                "qbase64": query,
                "page": page,
                "pagesize": PAGE_SIZE,
                "fields": "domain",
                "sub_type": "web",
            });
            let response: Response = ctx
                .post(&url)
                .header("API-KEY", &key)
                .header("Accept", "application/json")
                .json(&body)
                .decode()
                .await?;
            if response.code != 60000 {
                bail!("ZoomEye search failed with code {}", response.code);
            }
            let empty = response.data.is_empty();
            if !ctx
                .emit_all(response.data.into_iter().map(|e| e.domain))
                .await
            {
                break;
            }
            if empty || page > response.total.saturating_sub(1) / PAGE_SIZE {
                break;
            }
        }
        Ok(())
    }
}
