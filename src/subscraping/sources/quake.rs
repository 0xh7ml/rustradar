//! [360 Quake](https://quake.360.net): cyberspace search engine.
//!
//! Key: Quake API token (`X-QuakeToken`).

use super::prelude::*;

source_info!("quake", default: true, recursive: false, key: Required);

const PAGE_SIZE: u64 = 500;
/// Safety cap on pages.
const MAX_PAGES: usize = 1000;

/// 360 Quake service search.
pub struct Quake;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    code: Value,
    message: String,
    data: Vec<Record>,
    meta: Meta,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Record {
    service: Service,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Service {
    http: Http,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Http {
    host: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Meta {
    pagination: Pagination,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Pagination {
    total: u64,
}

#[async_trait]
impl Source for Quake {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let mut start = 0;
        let mut total: Option<u64> = None;
        for _ in 0..MAX_PAGES {
            let body = json!({
                "query": format!("domain: {}", ctx.domain),
                "include": ["service.http.host"],
                "latest": true,
                "size": PAGE_SIZE,
                "start": start,
            });
            let response: Response = ctx
                .post("https://quake.360.net/api/v3/search/quake_service")
                .header("X-QuakeToken", &key)
                .json(&body)
                .decode()
                .await?;
            let ok = response.code.as_i64() == Some(0) || response.code.as_str() == Some("0");
            if !ok {
                bail!("{}", response.message);
            }
            let total = *total.get_or_insert(response.meta.pagination.total);
            let empty = response.data.is_empty();
            if !ctx
                .emit_all(response.data.into_iter().map(|r| r.service.http.host))
                .await
            {
                break;
            }
            if empty || start + PAGE_SIZE >= total {
                break;
            }
            start += PAGE_SIZE;
        }
        Ok(())
    }
}
