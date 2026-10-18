//! [Domains Project](https://domainsproject.org): internet domain dataset.
//!
//! Key: `username:password` (HTTP basic auth).

use super::prelude::*;

source_info!("domainsproject", default: true, recursive: false, key: Required);

/// Domains Project API.
pub struct DomainsProject;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    domains: Vec<String>,
    error: Option<String>,
}

#[async_trait]
impl Source for DomainsProject {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some((user, password)) = ctx.random_key_pair() else {
            bail!("invalid key format, expected username:password");
        };
        let url = format!(
            "https://api.domainsproject.org/api/tld/search?domain={}",
            ctx.domain
        );
        let response: Response = ctx.get(&url).basic_auth(&user, &password).decode().await?;
        if let Some(error) = response.error.filter(|e| !e.is_empty()) {
            bail!("{error}");
        }
        ctx.emit_all(response.domains.into_iter().filter(|d| !d.starts_with('.')))
            .await;
        Ok(())
    }
}
