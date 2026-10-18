//! [Robtex](https://www.robtex.com): passive DNS (forward lookup, then reverse
//! lookups of the IPs found).
//!
//! Key: Robtex Pro API key.

use super::prelude::*;

source_info!("robtex", default: true, recursive: false, key: Required);

const BASE: &str = "https://proapi.robtex.com/pdns";

/// Robtex Pro passive DNS.
pub struct Robtex;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Record {
    rrdata: String,
    rrtype: String,
}

#[async_trait]
impl Source for Robtex {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let key = url_encode(&key);
        let forward = lookup(ctx, &format!("{BASE}/forward/{}?key={key}", ctx.domain)).await?;
        for record in forward
            .iter()
            .filter(|r| r.rrtype == "A" || r.rrtype == "AAAA")
        {
            let reverse =
                match lookup(ctx, &format!("{BASE}/reverse/{}?key={key}", record.rrdata)).await {
                    Ok(r) => r,
                    Err(err) => {
                        ctx.error(format!("{err:#}")).await;
                        continue;
                    }
                };
            if !ctx.emit_all(reverse.into_iter().map(|r| r.rrdata)).await {
                break;
            }
        }
        Ok(())
    }
}

/// Fetch an NDJSON endpoint.
async fn lookup(ctx: &Ctx, url: &str) -> Result<Vec<Record>> {
    let body = ctx
        .get(url)
        .header("Content-Type", "application/x-ndjson")
        .text()
        .await?;
    Ok(body
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect())
}
