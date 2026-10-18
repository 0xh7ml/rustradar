//! [ThreatCrowd](https://ci-www.threatcrowd.org): historical threat graph (`-all`). No key.

use super::prelude::*;

source_info!("threatcrowd", default: false, recursive: false, key: None);

/// ThreatCrowd domain report.
pub struct ThreatCrowd;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    subdomains: Vec<String>,
}

#[async_trait]
impl Source for ThreatCrowd {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let url = format!(
            "http://ci-www.threatcrowd.org/searchApi/v2/domain/report/?domain={}",
            ctx.domain
        );
        let response: Response = ctx.get(&url).decode().await?;
        ctx.emit_all(response.subdomains).await;
        Ok(())
    }
}
