//! [RapidDNS](https://rapiddns.io): DNS dataset, scraped from paginated HTML (`-all`). No key.

use regex::Regex;

use super::prelude::*;

source_info!("rapiddns", default: false, recursive: false, key: None);

/// Safety cap on pages.
const MAX_PAGES: u32 = 500;

/// RapidDNS subdomain pages.
pub struct RapidDns;

#[async_trait]
impl Source for RapidDns {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let page_link = Regex::new(r#"class="page-link" href="/subdomain/[^"]+\?page=(\d+)">"#)?;
        let mut page = 1;
        let mut max_pages = 1;
        loop {
            let url = format!(
                "https://rapiddns.io/subdomain/{}?page={page}&full=1",
                ctx.domain
            );
            let body = ctx.get(&url).text().await?;
            if !ctx.emit_extracted(&body).await {
                break;
            }
            if page == 1 {
                max_pages = page_link
                    .captures_iter(&body)
                    .filter_map(|c| c[1].parse::<u32>().ok())
                    .max()
                    .unwrap_or(1)
                    .min(MAX_PAGES);
            }
            if page >= max_pages {
                break;
            }
            page += 1;
        }
        Ok(())
    }
}
