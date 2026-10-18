//! [Censys Platform](https://platform.censys.io): certificate names search (v3 API).
//!
//! Key: a Personal Access Token, optionally with an organization ID:
//! `censys: ["PAT"]` or `censys: ["PAT:ORG_ID"]`.

use super::prelude::*;

source_info!("censys", default: true, recursive: false, key: Required);

const MAX_PAGES: usize = 10;
const PAGE_SIZE: usize = 100;
const SEARCH_URL: &str = "https://api.platform.censys.io/v3/global/search/query";

/// Censys Platform certificate search.
pub struct Censys;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    result: ResultBody,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ResultBody {
    hits: Vec<Hit>,
    next_page_token: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Hit {
    certificate_v1: Certificate,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Certificate {
    resource: Resource,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Resource {
    names: Vec<String>,
}

#[async_trait]
impl Source for Censys {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let (pat, org) = match key.split_once(':') {
            Some((pat, org)) => (pat.to_string(), Some(org.to_string())),
            None => (key, None),
        };

        let mut cursor = String::new();
        for _ in 0..MAX_PAGES {
            let mut body = json!({
                "query": format!("cert.names: {}", ctx.domain),
                "fields": ["cert.names"],
                "page_size": PAGE_SIZE,
            });
            if !cursor.is_empty() {
                body["cursor"] = json!(cursor);
            }
            let mut request = ctx.post(SEARCH_URL).bearer(&pat).json(&body);
            if let Some(org) = &org {
                request = request.header("X-Organization-ID", org);
            }
            let response: Response = request.decode().await?;
            for hit in response.result.hits {
                if !ctx.emit_all(hit.certificate_v1.resource.names).await {
                    return Ok(());
                }
            }
            cursor = response.result.next_page_token;
            if cursor.is_empty() {
                break;
            }
        }
        Ok(())
    }
}
