//! [HackerTarget](https://hackertarget.com/find-dns-host-records/): host search.
//! Key optional (free tier is limited to a few queries per day).

use super::prelude::*;

source_info!("hackertarget", default: true, recursive: true, key: Optional);

/// HackerTarget host search.
pub struct HackerTarget;

#[async_trait]
impl Source for HackerTarget {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let mut url = format!("https://api.hackertarget.com/hostsearch/?q={}", ctx.domain);
        if let Some(key) = ctx.random_key() {
            url.push_str(&format!("&apikey={}", url_encode(&key)));
        }
        let body = ctx.get(&url).text().await?;
        // Quota and errors come back as 200 with a plain-text message.
        let first = body.lines().next().unwrap_or_default();
        if first.starts_with("error") || first.starts_with("API count exceeded") {
            bail!("{first}");
        }
        // Lines are "host,ip".
        for line in body.lines().filter(|l| !l.is_empty()) {
            if !ctx.emit_extracted(line).await {
                break;
            }
        }
        Ok(())
    }
}
