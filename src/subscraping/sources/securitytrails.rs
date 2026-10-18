//! [SecurityTrails](https://securitytrails.com): historical DNS.
//!
//! Key: SecurityTrails API key (`APIKEY`). Uses the scroll-enabled domain
//! search; falls back to the plain subdomains endpoint when the account is
//! not allowed to use it (HTTP 403).

use super::prelude::*;

source_info!("securitytrails", default: true, recursive: true, key: Required);

/// Safety cap on scroll pages.
const MAX_PAGES: usize = 1000;

/// SecurityTrails API.
pub struct SecurityTrails;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    meta: Meta,
    records: Vec<Record>,
    subdomains: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Meta {
    scroll_id: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Record {
    hostname: String,
}

#[async_trait]
impl Source for SecurityTrails {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let mut scroll_id: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let result = match &scroll_id {
                None => {
                    ctx.post("https://api.securitytrails.com/v1/domains/list?include_ips=false&scroll=true")
                        .header("APIKEY", &key)
                        .json(&json!({ "query": format!("apex_domain='{}'", ctx.domain) }))
                        .decode::<Response>()
                        .await
                }
                Some(id) => {
                    ctx.get(&format!("https://api.securitytrails.com/v1/scroll/{id}"))
                        .header("APIKEY", &key)
                        .decode::<Response>()
                        .await
                }
            };
            let response = match result {
                Ok(r) => r,
                Err(err) if scroll_id.is_none() && status_of(&err) == Some(403) => {
                    ctx.get(&format!(
                        "https://api.securitytrails.com/v1/domain/{}/subdomains",
                        ctx.domain
                    ))
                    .header("APIKEY", &key)
                    .decode::<Response>()
                    .await?
                }
                Err(err) => return Err(err),
            };

            let mut values: Vec<String> =
                response.records.into_iter().map(|r| r.hostname).collect();
            values.extend(response.subdomains.into_iter().map(|s| {
                if s.ends_with('.') {
                    format!("{s}{}", ctx.domain)
                } else {
                    format!("{s}.{}", ctx.domain)
                }
            }));
            if !ctx.emit_all(values).await {
                break;
            }
            match response.meta.scroll_id.filter(|id| !id.is_empty()) {
                Some(id) => scroll_id = Some(id),
                None => break,
            }
        }
        Ok(())
    }
}
