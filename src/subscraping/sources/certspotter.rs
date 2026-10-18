//! [Cert Spotter](https://sslmate.com/certspotter/api/): CT log issuances.
//!
//! Key: Cert Spotter API token.

use super::prelude::*;

source_info!("certspotter", default: true, recursive: true, key: Required);

/// Safety cap on pages.
const MAX_PAGES: usize = 1000;

/// SSLMate Cert Spotter.
pub struct CertSpotter;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Issuance {
    id: String,
    dns_names: Vec<String>,
}

#[async_trait]
impl Source for CertSpotter {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let base = format!(
            "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
            ctx.domain
        );
        let mut after: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let url = match &after {
                Some(id) => format!("{base}&after={id}"),
                None => base.clone(),
            };
            let page: Vec<Issuance> = ctx.get(&url).bearer(&key).decode().await?;
            let Some(last) = page.last().map(|i| i.id.clone()) else {
                break;
            };
            for issuance in page {
                if !ctx.emit_all(issuance.dns_names).await {
                    return Ok(());
                }
            }
            if last.is_empty() || after.as_deref() == Some(last.as_str()) {
                break;
            }
            after = Some(last);
        }
        Ok(())
    }
}
