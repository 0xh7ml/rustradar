//! [SiteDossier](http://www.sitedossier.com): paginated HTML listing of a
//! domain's subdomains (`-all`, slow: limited to 8 requests/minute). No key.

use regex::Regex;

use super::prelude::*;

source_info!("sitedossier", default: false, recursive: false, key: None);

/// Safety cap on pages.
const MAX_PAGES: usize = 200;

/// SiteDossier parent-domain pages.
pub struct SiteDossier;

#[async_trait]
impl Source for SiteDossier {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let next_link = Regex::new(r#"<a href="([A-Za-z0-9/.]+)"><b>"#)?;
        let mut url = format!("http://www.sitedossier.com/parentdomain/{}", ctx.domain);
        let mut visited = std::collections::HashSet::new();
        for _ in 0..MAX_PAGES {
            if !visited.insert(url.clone()) {
                break;
            }
            let response = ctx.get(&url).send_raw().await?;
            let status = response.status().as_u16();
            if status != 200 && status != 404 {
                bail!("unexpected status code {status} received from {url}");
            }
            let body = ctx.read_text(response).await?;
            if !ctx.emit_extracted(&body).await {
                break;
            }
            match next_link.captures(&body) {
                Some(c) => url = format!("http://www.sitedossier.com{}", &c[1]),
                None => break,
            }
        }
        Ok(())
    }
}
