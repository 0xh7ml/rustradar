//! [sub.md](https://sub.md): subdomain search. Key optional (Bearer).

use super::prelude::*;

source_info!("submd", default: true, recursive: false, key: Optional);

/// sub.md search API.
pub struct SubMd;

#[async_trait]
impl Source for SubMd {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let url = format!(
            "https://api.sub.md/v1/search?apex={}",
            url_encode(&ctx.domain)
        );
        let mut request = ctx.get(&url);
        if let Some(key) = ctx.random_key() {
            request = request.bearer(&key);
        }
        let response = request.send_raw().await?;
        if response.status().as_u16() != 200 {
            // No data for this domain (or quota); not worth an error.
            return Ok(());
        }
        let body = ctx.read_text(response).await?;
        for line in body.lines().filter(|l| !l.is_empty()) {
            if !ctx.emit_extracted(line).await {
                break;
            }
        }
        Ok(())
    }
}
