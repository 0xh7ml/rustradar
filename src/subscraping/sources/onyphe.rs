//! [ONYPHE](https://www.onyphe.io): cyber defense search engine, resolver category.
//!
//! Key: ONYPHE API key. Fields come back as strings, numbers or arrays
//! depending on the record, so the response is parsed leniently.

use super::prelude::*;

source_info!("onyphe", default: true, recursive: false, key: Required);

const PAGE_SIZE: u32 = 1000;
const MAX_PAGES: u64 = 1000;

/// ONYPHE search API.
pub struct Onyphe;

#[async_trait]
impl Source for Onyphe {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else {
            return Ok(());
        };
        let query = url_encode(&format!("category:resolver domain:{}", ctx.domain));
        let mut page: u64 = 1;
        loop {
            let url = format!(
                "https://www.onyphe.io/api/v2/search/?q={query}&page={page}&size={PAGE_SIZE}"
            );
            let body: Value = ctx
                .get(&url)
                .header("Content-Type", "application/json")
                .header("Authorization", &format!("bearer {key}"))
                .decode()
                .await?;

            let results = body["results"].as_array().cloned().unwrap_or_default();
            for record in &results {
                let mut values = strings(&record["subdomains"]);
                for field in ["hostname", "forward", "reverse"] {
                    values.extend(strings(&record[field]).into_iter().take(1));
                }
                if !ctx.emit_all(values).await {
                    return Ok(());
                }
            }

            let max_page = number(&body["max_page"]).unwrap_or(0);
            if results.is_empty() || page >= max_page || page >= MAX_PAGES {
                return Ok(());
            }
            page += 1;
        }
    }
}

/// A string or array of strings as a list.
fn strings(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => vec![s.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

/// A number given as JSON number or numeric string.
fn number(value: &Value) -> Option<u64> {
    match value {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lenient_fields() {
        assert_eq!(strings(&json!("a")), vec!["a"]);
        assert_eq!(strings(&json!(["a", "b"])), vec!["a", "b"]);
        assert!(strings(&json!(null)).is_empty());
        assert_eq!(number(&json!("7")), Some(7));
        assert_eq!(number(&json!(7)), Some(7));
    }
}
