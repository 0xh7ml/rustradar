//! [THC](https://ip.thc.org): The Hacker's Choice reverse/sub-domain database (`-all`). No key.

use super::prelude::*;

source_info!("thc", default: false, recursive: false, key: None);

/// Safety cap on pages.
const MAX_PAGES: usize = 1000;

/// THC subdomain lookup.
pub struct Thc;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    domains: Vec<Entry>,
    next_page_state: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Entry {
    domain: String,
}

#[async_trait]
impl Source for Thc {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let mut page_state = String::new();
        for _ in 0..MAX_PAGES {
            let body = json!({ "domain": ctx.domain, "page_state": page_state, "limit": 1000 });
            let response: Response = ctx
                .post("https://ip.thc.org/api/v1/lookup/subdomains")
                .json(&body)
                .decode()
                .await?;
            if !ctx
                .emit_all(response.domains.into_iter().map(|e| e.domain))
                .await
            {
                break;
            }
            if response.next_page_state.is_empty() || response.next_page_state == page_state {
                break;
            }
            page_state = response.next_page_state;
        }
        Ok(())
    }
}
