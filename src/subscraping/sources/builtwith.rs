//! [BuiltWith](https://api.builtwith.com): technology profiling, domain paths.
//!
//! Key: BuiltWith API key.

use super::prelude::*;

source_info!("builtwith", default: true, recursive: false, key: Required);

/// BuiltWith domain API.
pub struct BuiltWith;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    #[serde(rename = "Results")]
    results: Vec<ResultItem>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ResultItem {
    #[serde(rename = "Result")]
    result: ResultBody,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ResultBody {
    #[serde(rename = "Paths")]
    paths: Vec<PathEntry>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PathEntry {
    #[serde(rename = "Domain")]
    domain: String,
    #[serde(rename = "SubDomain")]
    sub_domain: String,
}

#[async_trait]
impl Source for BuiltWith {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let url = format!(
            "https://api.builtwith.com/v21/api.json?KEY={}&HIDETEXT=yes&HIDEDL=yes&NOLIVE=yes&NOMETA=yes&NOPII=yes&NOATTR=yes&LOOKUP={}",
            url_encode(&key),
            ctx.domain
        );
        let response: Response = ctx.get(&url).decode().await?;
        for item in response.results {
            for path in item.result.paths {
                if path.sub_domain.is_empty() {
                    continue;
                }
                if !ctx
                    .emit(format!("{}.{}", path.sub_domain, path.domain))
                    .await
                {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}
