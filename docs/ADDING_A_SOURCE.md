# Adding or fixing a source

A source is one file in `src/subscraping/sources/` with a unit struct that
implements the `Source` trait. The framework handles tasks, timeouts, rate
limiting, statistics, skipping when keys are missing, normalization,
validation and dedup. A source only has to fetch data and emit candidates.

## 1. Pick a template

| Provider shape | Copy |
|---|---|
| Simple JSON GET, no key | `anubis.rs` |
| JSON GET with an API key header | `fullhunt.rs` |
| Key in the query string | `shodan.rs` |
| Multi-part key (`user:secret`) | `fofa.rs`, `domainsproject.rs` |
| Cursor / page pagination | `virustotal.rs`, `certspotter.rs`, `rsecloud.rs` |
| POST with JSON body | `thc.rs`, `quake.rs` |
| Text or HTML scraping | `hackertarget.rs`, `rapiddns.rs` |
| Several endpoints in parallel | `driftnet.rs` |
| Unpredictable JSON shapes | `onyphe.rs` (uses `serde_json::Value`) |

## 2. Write the file

```rust
//! [Example Intel](https://example-intel.io): passive DNS API.
//!
//! Key: Example Intel API key (`X-Api-Key`).

use super::prelude::*;

source_info!("exampleintel", default: true, recursive: false, key: Required);

/// Safety cap on pages.
const MAX_PAGES: u32 = 100;

/// Example Intel passive DNS.
pub struct ExampleIntel;

#[derive(Deserialize, Default)]
#[serde(default)]                 // tolerate missing fields
struct Response {
    subdomains: Vec<String>,
    next_page: Option<u32>,
}

#[async_trait]
impl Source for ExampleIntel {
    fn info(&self) -> &'static SourceInfo {
        &INFO
    }

    async fn run(&self, ctx: &Ctx) -> Result<()> {
        let Some(key) = ctx.random_key() else { return Ok(()) };
        let mut page = 1;
        for _ in 0..MAX_PAGES {
            let url = format!("https://api.example-intel.io/v1/{}/subdomains?page={page}", ctx.domain);
            let response: Response = ctx.get(&url).header("X-Api-Key", &key).decode().await?;
            if !ctx.emit_all(response.subdomains).await {
                break; // receiver closed or -max-results reached
            }
            match response.next_page {
                Some(next) if next > page => page = next,
                _ => break,
            }
        }
        Ok(())
    }
}
```

Then register it in `src/subscraping/sources/mod.rs`:

```rust
mod exampleintel;
// ...
Arc::new(exampleintel::ExampleIntel),   // keep all() alphabetical
```

The `catalog_has_54_unique_sorted_sources` test checks the count, so update
the number there and in the docs.

## 3. `source_info!` fields

| Field | Meaning |
|---|---|
| name | Lowercase `[a-z0-9]`, unique. Used in `-s`, `-es`, `-rls`, provider config and `<NAME>_API_KEY`. |
| `default` | `true` if fast and cheap enough to run without `-all`. |
| `recursive` | `true` if querying `sub.example.com` returns its subdomains. |
| `key` | `None`, `Optional` or `Required`. Required sources are skipped without keys. |

## 4. `Ctx` API

| Method | Use |
|---|---|
| `ctx.domain` | Target apex domain (lowercase, clean). |
| `ctx.random_key()` | One configured key, or `None`. |
| `ctx.random_key_pair()` | One `a:b` key split in two, or `None`. |
| `ctx.keys()` | All keys (e.g. for token rotation). |
| `ctx.get(url)` / `ctx.post(url)` | Start a request. |
| `.header(k, v)`, `.bearer(t)`, `.basic_auth(u, p)`, `.json(&body)`, `.body(s)` | Build it. |
| `.decode::<T>()` | Send, require HTTP 200, parse JSON. |
| `.text()` | Send, require HTTP 200, return the body. |
| `.send()` | Send, require HTTP 200, return the response (for headers). |
| `.send_raw()` | Send and return the response with any status. |
| `ctx.read_text(resp)` / `ctx.read_json(resp)` | Read a response from `send`/`send_raw`. |
| `status_of(&err)` | HTTP status inside an error (e.g. fall back on 403). |
| `ctx.emit(value)` | Emit one candidate. Returns `false` = stop. |
| `ctx.emit_all(iter)` | Emit many. Collect into a `Vec` first if the iterator borrows (see below). |
| `ctx.emit_extracted(text)` | Find every `*.domain` in arbitrary text and emit it. |
| `ctx.extract(text)` | The same, returning the matches. |
| `ctx.error(msg)` | Record a non-fatal error and keep going. |
| `ctx.limit_reached()` / `ctx.max_results()` | `-max-results` handling. |
| `ctx.all_sources()` | `true` with `-all` (lift internal limits). |
| `ctx.timeout()` | `-timeout` as a `Duration`. |
| `ctx.acquire()` | Rate-limit wait and request count for non-HTTP calls. |

Helpers in the prelude: `url_encode`, `url_decode`, `host_of` (strip scheme
and port), `json!`, `Value`, `bail!`.

## 5. Rules

* **Do not deduplicate, lowercase or validate.** The runner does it. Emit raw
  values; `*.` prefixes are fine (they set the wildcard-certificate flag).
* **Prefer typed structs with `#[serde(default)]`** so a missing field does not
  break the source. Use `Value` only when types vary.
* **Use `emit_extracted` when the format is loose** (HTML, CSV, free text,
  URLs). It also protects against `example.com.evil.org`.
* **Cap every loop** (`MAX_PAGES`) and stop when a cursor repeats.
* **Return `Err` for failures that end the source**; use `ctx.error` for
  partial failures (one endpoint of several, one page).
* **Respect `emit`'s return value**: stop when it returns `false`.
* **Never log keys yourself.** Error messages are redacted, but avoid putting
  keys in messages anyway. Prefer headers over query strings when the
  provider supports both.
* **Strict providers** get a default in `passive::DEFAULT_RATE_LIMITS`.

### The `Send` gotcha

`run` must return a `Send` future. An iterator that borrows local data and is
held across `.await` breaks that, with an error like *"implementation of
`FnOnce` is not general enough"*. Collect first:

```rust
// error: borrows `list` across the await inside emit_all
ctx.emit_all(list.iter().filter_map(|v| v.as_str().map(String::from))).await;

// fine
let subs: Vec<String> = list.iter().filter_map(|v| v.as_str().map(String::from)).collect();
ctx.emit_all(subs).await;
```

## 6. Test it

```bash
cargo build
# Run only your source, with debug logs (shows failed responses):
rustradar -d example.com -s exampleintel -v -stats
# Without saving keys to the config file:
EXAMPLEINTEL_API_KEY=xxx rustradar -d example.com -s exampleintel -v
```

Add unit tests for any parsing helper (see `github.rs`, `onyphe.rs`). For
request logic, `tests/http.rs` shows how to run a source against a local
HTTP server.

## 7. Document it

* Row in [SOURCES.md](SOURCES.md) (keep it in sync with `source_info!`).
* Key format in the file's `//!` header.
* Line in [CHANGELOG.md](../CHANGELOG.md).

## Fixing a broken source

Providers change APIs often. When a source starts failing:

1. Reproduce: `rustradar -d <domain> -s <source> -v`. With `-v`, failed
   responses are logged at debug level with the first 200 bytes of the body.
2. Compare with the provider's current API docs (linked in the file header)
   and, if useful, the upstream subfinder implementation of the same source.
3. Typical fixes: new base URL, renamed JSON field (add `#[serde(alias = "...")]`
   to stay compatible with both), new auth header, changed pagination.
4. If a provider is gone or behind bot protection, set `default: false` and
   note it in SOURCES.md, or remove it (update the catalog test and docs).
