//! [Wayback Machine](https://web.archive.org): archived URLs via the CDX API (`-all`). No key.

use super::prelude::*;

source_info!("waybackarchive", default: false, recursive: false, key: None);

/// Internet Archive Wayback Machine CDX.
pub struct WaybackArchive;

#[async_trait]
impl Source for WaybackArchive {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let url = format!(
            "http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=txt&fl=original&collapse=urlkey",
            ctx.domain
        );
        let body = ctx.get(&url).text().await?;
        for line in body.lines().filter(|l| !l.is_empty()) {
            let line = url_decode(line);
            for sub in ctx.extract(&line) {
                // Leftovers of %25 / %2f encodings glued to the hostname.
                let sub = sub
                    .strip_prefix("25")
                    .or_else(|| sub.strip_prefix("2f"))
                    .map(String::from)
                    .unwrap_or(sub);
                if !ctx.emit(sub).await {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}
