//! [Intelligence X](https://intelx.io): phonebook search.
//!
//! Key: `host:key`, where host is your API host, e.g.
//! `2.intelx.io:00000000-0000-0000-0000-000000000000` (free tier:
//! `free.intelx.io`).

use std::time::Duration;

use super::prelude::*;

source_info!("intelx", default: true, recursive: false, key: Required);

/// Polls before giving up on a search.
const MAX_POLLS: usize = 60;

/// Intelligence X phonebook.
pub struct IntelX;

#[derive(Deserialize, Default)]
#[serde(default)]
struct SearchResponse {
    id: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ResultResponse {
    selectors: Vec<Selector>,
    status: i64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Selector {
    selectorvalue: String,
}

#[async_trait]
impl Source for IntelX {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some((host, key)) = ctx.random_key_pair() else {
            bail!("invalid key format, expected host:key");
        };
        let search_url = format!("https://{host}/phonebook/search?k={}", url_encode(&key));
        let body = json!({
            "Term": ctx.domain,
            "Maxresults": 100000,
            "Media": 0,
            "Target": 1,
            "Terminate": null,
            "Timeout": 20,
        });
        let search: SearchResponse = ctx.post(&search_url).json(&body).decode().await?;
        if search.id.is_empty() {
            bail!("search did not return an id");
        }

        let results_url = format!(
            "https://{host}/phonebook/search/result?k={}&id={}&limit=10000",
            url_encode(&key),
            url_encode(&search.id)
        );
        // status: 0 = results available, 1 = done, 2 = not found, 3 = no results yet.
        for _ in 0..MAX_POLLS {
            let page: ResultResponse = ctx.get(&results_url).decode().await?;
            let status = page.status;
            let empty = page.selectors.is_empty();
            if !ctx
                .emit_all(page.selectors.into_iter().map(|s| s.selectorvalue))
                .await
            {
                return Ok(());
            }
            match status {
                0 => {}
                3 => {
                    if empty {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
                _ => return Ok(()),
            }
        }
        Ok(())
    }
}
