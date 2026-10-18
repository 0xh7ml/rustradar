//! [DNSDB](https://www.domaintools.com/products/farsight-dnsdb/) (Farsight/DomainTools):
//! passive DNS (`-all`).
//!
//! Key: DNSDB API key. Uses the v2 streaming (SAF) API and continues with
//! `offset` when the server reports a `limited` result.

use super::prelude::*;

source_info!("dnsdb", default: false, recursive: true, key: Required);

const BASE: &str = "https://api.dnsdb.info/dnsdb/v2";
/// Safety cap on offset pages.
const MAX_PAGES: usize = 1000;

/// Farsight DNSDB.
pub struct DnsDb;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Line {
    cond: String,
    obj: Obj,
    msg: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Obj {
    rrname: String,
}

#[async_trait]
impl Source for DnsDb {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let headers = [
            ("X-API-KEY", key.as_str()),
            ("Accept", "application/x-ndjson"),
        ];

        // How far we may page with `offset` on this account ("n/a" = not allowed).
        let rate: Value = with_headers(ctx.get(&format!("{BASE}/rate_limit")), &headers)
            .decode()
            .await?;
        let offset_max = match &rate["rate"]["offset_max"] {
            Value::Number(n) => n.as_u64().unwrap_or(0),
            Value::String(s) => s.parse().unwrap_or(0),
            _ => 0,
        };

        let base = format!(
            "{BASE}/lookup/rrset/name/*.{}?limit=0&swclient=rustradar",
            ctx.domain
        );
        let mut emitted: u64 = 0;
        let mut offset: Option<u64> = None;
        for _ in 0..MAX_PAGES {
            let url = match offset {
                Some(o) => format!("{base}&offset={o}"),
                None => base.clone(),
            };
            let body = with_headers(ctx.get(&url), &headers).text().await?;
            let mut cond = String::new();
            for raw in body.lines().filter(|l| !l.trim().is_empty()) {
                let line: Line = serde_json::from_str(raw).context("invalid DNSDB stream line")?;
                cond = line.cond;
                match cond.as_str() {
                    "" | "ongoing" => {
                        if !line.obj.rrname.is_empty() {
                            emitted += 1;
                            if !ctx.emit(line.obj.rrname.trim_end_matches('.')).await {
                                return Ok(());
                            }
                        }
                    }
                    "begin" => {}
                    _ => {
                        if !line.msg.is_empty() {
                            crate::debug!("dnsdb: {}", line.msg);
                        }
                        break;
                    }
                }
            }
            match cond.as_str() {
                "succeeded" => return Ok(()),
                // Continue from where we are, but only if this page made progress.
                "limited" if offset_max > 0 && emitted <= offset_max && offset != Some(emitted) => {
                    offset = Some(emitted)
                }
                "limited" => return Ok(()),
                other => bail!("dnsdb terminated with condition: {other}"),
            }
        }
        Ok(())
    }
}

fn with_headers<'a>(
    mut request: crate::subscraping::Request<'a>,
    headers: &[(&str, &str)],
) -> crate::subscraping::Request<'a> {
    for (name, value) in headers {
        request = request.header(name, value);
    }
    request
}
