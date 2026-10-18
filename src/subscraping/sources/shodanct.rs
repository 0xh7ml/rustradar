//! [Shodan CT](https://ctl.shodan.io): Shodan's certificate transparency hostname index. No key.

use super::prelude::*;

source_info!("shodanct", default: true, recursive: true, key: None);

/// Shodan certificate transparency index.
pub struct ShodanCt;

#[async_trait]
impl Source for ShodanCt {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let url = format!(
            "https://ctl.shodan.io/api/v1/domain/{}/hostnames",
            ctx.domain
        );
        let hostnames: Vec<String> = ctx.get(&url).decode().await?;
        for hostname in hostnames {
            if !ctx.emit_extracted(&hostname).await {
                break;
            }
        }
        Ok(())
    }
}
