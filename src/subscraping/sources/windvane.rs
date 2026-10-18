//! [Windvane](https://windvane.lichoin.com): OSINT subdomain service.
//!
//! Key: Windvane API key (`X-Api-Key`).

use super::prelude::*;

source_info!("windvane", default: true, recursive: false, key: Required);

const PAGE_SIZE: u64 = 1000;
const MAX_PAGES: u64 = 1000;

/// Windvane ListSubDomain API.
pub struct Windvane;

#[async_trait]
impl Source for Windvane {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        for page in 1..=MAX_PAGES {
            let body = json!({ "domain": ctx.domain, "page_request": { "page": page, "count": PAGE_SIZE } });
            let response: Value = ctx
                .post("https://windvane.lichoin.com/trpc.backendhub.public.WindvaneService/ListSubDomain")
                .header("X-Api-Key", &key)
                .json(&body)
                .decode()
                .await?;
            if let Some(code) = response["code"].as_i64().filter(|c| *c != 0) {
                bail!(
                    "code {code}: {}",
                    response["msg"].as_str().unwrap_or_default()
                );
            }
            let list = response["data"]["list"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if list.is_empty() {
                break;
            }
            let subs: Vec<String> = list
                .iter()
                .filter_map(|e| e["domain"].as_str().map(String::from))
                .collect();
            if !ctx.emit_all(subs).await {
                break;
            }
            // Pagination numbers are returned as strings.
            let total: u64 = as_u64(&response["data"]["page_response"]["total"]).unwrap_or(0);
            if page * PAGE_SIZE >= total {
                break;
            }
        }
        Ok(())
    }
}

fn as_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}
