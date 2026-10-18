//! [AnubisDB](https://anubisdb.com): public subdomain database. No key.

use super::prelude::*;

source_info!("anubis", default: true, recursive: false, key: None);

/// AnubisDB.
pub struct Anubis;

#[async_trait]
impl Source for Anubis {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let url = format!("https://anubisdb.com/anubis/subdomains/{}", ctx.domain);
        let subdomains: Vec<String> = ctx.get(&url).decode().await?;
        ctx.emit_all(subdomains).await;
        Ok(())
    }
}
