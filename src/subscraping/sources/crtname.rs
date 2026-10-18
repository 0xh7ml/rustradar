//! [crt.name](https://crt.name): certificate SAN search. Key optional (Bearer token).

use super::prelude::*;

source_info!("crtname", default: true, recursive: false, key: Optional);

/// crt.name certificate search.
pub struct CrtName;

#[async_trait]
impl Source for CrtName {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let url = format!(
            "https://crt.name/v1/search?apex={}",
            url_encode(&ctx.domain)
        );
        let mut request = ctx.get(&url).header("User-Agent", "rustradar");
        if let Some(key) = ctx.random_key() {
            request = request.bearer(&key);
        }
        let body = request.text().await?;
        for line in body
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with("*."))
        {
            if !ctx.emit_extracted(line).await {
                break;
            }
        }
        Ok(())
    }
}
