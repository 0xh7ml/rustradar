//! [crt.sh](https://crt.sh): certificate transparency search. No key.
//!
//! First queries crt.sh's public PostgreSQL replica (`guest@crt.sh:5432`,
//! feature `crtsh-sql`, on by default), which is faster and more complete.
//! Falls back to the JSON HTTP API when the database is unreachable or
//! returns nothing. Without `-all`, the SQL query is limited to 10,000 rows.

use super::prelude::*;

source_info!("crtsh", default: true, recursive: true, key: None);

/// crt.sh certificate transparency.
pub struct CrtSh;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Entry {
    name_value: String,
}

#[async_trait]
impl Source for CrtSh {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        #[cfg(feature = "crtsh-sql")]
        match sql::query(ctx).await {
            Ok(count) if count > 0 => return Ok(()),
            Ok(_) => crate::debug!("crtsh: SQL query returned no rows, falling back to HTTP"),
            Err(err) => crate::debug!("crtsh: SQL query failed ({err:#}), falling back to HTTP"),
        }

        let url = format!("https://crt.sh/?q=%25.{}&output=json", ctx.domain);
        let entries: Vec<Entry> = ctx.get(&url).decode().await?;
        for entry in entries {
            for line in entry.name_value.split('\n') {
                if !ctx.emit_extracted(line).await {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

#[cfg(feature = "crtsh-sql")]
mod sql {
    use super::*;
    use tokio_postgres::config::SslMode;
    use tokio_postgres::{NoTls, SimpleQueryMessage};

    /// Run the certwatch query; returns the number of rows read.
    pub(super) async fn query(ctx: &Ctx) -> Result<usize> {
        let domain = &ctx.domain;
        // The query is built as text (simple protocol works through crt.sh's
        // pooler); only allow hostname characters so nothing can be injected.
        if !domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            bail!("domain contains characters not allowed in the SQL query");
        }
        ctx.acquire().await?;

        let timeout = ctx.timeout();
        let mut config = tokio_postgres::Config::new();
        config
            .host("crt.sh")
            .port(5432)
            .user("guest")
            .dbname("certwatch")
            .ssl_mode(SslMode::Disable)
            .connect_timeout(timeout);
        let (client, connection) = tokio::time::timeout(timeout, config.connect(NoTls))
            .await
            .context("connect timeout")??;
        let driver = tokio::spawn(connection);

        let limit = if ctx.all_sources() { "" } else { "LIMIT 10000" };
        let statement = format!(
            "SET statement_timeout = {ms};\n\
             SELECT DISTINCT cai.NAME_VALUE FROM certificate_and_identities cai \
             WHERE plainto_tsquery('certwatch', '{domain}') @@ identities(cai.CERTIFICATE) \
             AND cai.NAME_VALUE ILIKE ('%' || '{domain}' || '%') {limit};",
            ms = timeout.as_millis()
        );
        let messages = tokio::time::timeout(timeout * 2, client.simple_query(&statement))
            .await
            .context("query timeout");
        drop(client);
        driver.abort();

        let mut count = 0;
        for message in messages?? {
            let SimpleQueryMessage::Row(row) = message else {
                continue;
            };
            count += 1;
            let Some(value) = row.get(0) else { continue };
            for line in value.split('\n') {
                if !ctx.emit_extracted(line).await {
                    return Ok(count);
                }
            }
        }
        Ok(count)
    }
}
