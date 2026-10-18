//! [Driftnet](https://driftnet.io): internet scan data (CT logs, scans, rDNS).
//!
//! Key: Driftnet API token (Bearer). Queries four endpoints concurrently and
//! uses their host summaries.

use std::collections::HashSet;
use std::sync::Mutex;

use super::prelude::*;

source_info!("driftnet", default: true, recursive: true, key: Required);

const BASE: &str = "https://api.driftnet.io/v1/";
const SUMMARY_LIMIT: u32 = 10_000;

/// (endpoint, filter parameter, summary context)
const ENDPOINTS: &[(&str, &str, &str)] = &[
    ("ct/log", "field=host:", "cert-dns-name"),
    ("scan/protocols", "field=host:", "cert-dns-name"),
    ("scan/domains", "field=host:", "cert-dns-name"),
    ("domain/rdns", "host=", "dns-ptr"),
];

/// Driftnet API.
pub struct Driftnet;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Summary {
    summary: SummaryBody,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct SummaryBody {
    values: std::collections::HashMap<String, Value>,
}

#[async_trait]
impl Source for Driftnet {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let key = ctx.random_key();
        let seen = Mutex::new(HashSet::new());
        let suffix = format!(".{}", ctx.domain);

        let queries = ENDPOINTS.iter().map(|(endpoint, param, context)| {
            let key = key.clone();
            let seen = &seen;
            let suffix = &suffix;
            async move {
                let url = format!(
                    "{BASE}{endpoint}?{param}{}&summarize=host&summary_context={context}&summary_limit={SUMMARY_LIMIT}",
                    url_encode(&ctx.domain)
                );
                let mut request = ctx.get(&url).header("accept", "application/json");
                if let Some(key) = &key {
                    request = request.bearer(key);
                }
                let response = match request.send_raw().await {
                    Ok(r) => r,
                    Err(err) => return ctx.error(format!("{err:#}")).await,
                };
                match response.status().as_u16() {
                    200 => {}
                    204 => return, // no data
                    status => return ctx.error(format!("{endpoint}: unexpected status code {status}")).await,
                }
                let summary: Summary = match ctx.read_json(response).await {
                    Ok(s) => s,
                    Err(err) => return ctx.error(format!("{endpoint}: {err:#}")).await,
                };
                for host in summary.summary.values.into_keys() {
                    let fresh = host.ends_with(suffix.as_str()) && seen.lock().map(|mut s| s.insert(host.to_lowercase())).unwrap_or(false);
                    if fresh && !ctx.emit(host).await {
                        return;
                    }
                }
            }
        });
        futures::future::join_all(queries).await;
        Ok(())
    }
}
