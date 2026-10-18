//! [Digitorus](https://certificatedetails.com): certificate details pages. No key.

use super::prelude::*;

source_info!("digitorus", default: true, recursive: true, key: None);

/// Digitorus certificate details.
pub struct Digitorus;

#[async_trait]
impl Source for Digitorus {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let url = format!("https://certificatedetails.com/{}", ctx.domain);
        let response = ctx.get(&url).send_raw().await?;
        // The site answers 404 for unknown domains but still lists related names.
        let status = response.status().as_u16();
        if status != 200 && status != 404 {
            bail!("unexpected status code {status} received from {url}");
        }
        let body = ctx.read_text(response).await?;
        for line in body.lines().filter(|l| !l.is_empty()) {
            let subs = ctx
                .extract(line)
                .into_iter()
                .map(|s| s.trim_start_matches('.').to_string());
            if !ctx.emit_all(subs).await {
                break;
            }
        }
        Ok(())
    }
}
