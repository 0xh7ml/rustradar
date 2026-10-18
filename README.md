# rustradar

**rustradar** is a fast, passive subdomain enumeration tool written in Rust. It
asks 54 passive data sources (certificate transparency logs, passive DNS,
search engines, threat-intelligence APIs and web archives) which subdomains
they know for a domain, instead of brute-forcing DNS against the target.

It re-implements the architecture of ProjectDiscovery's
[subfinder](https://github.com/projectdiscovery/subfinder) (the design is in
[`plans/`](plans/)), keeps its command-line flags, and works as both a CLI and
a Rust library.

```text
$ rustradar -d hackerone.com -silent | head -3
api.hackerone.com
docs.hackerone.com
gslink.hackerone.com
```

## Features

- **54 passive sources**, 17 of which can run without an API key.
- **Passive by default**: no traffic to the target. Optional active mode
  (`-nW`) resolves results and removes wildcard DNS artifacts.
- **Fast and polite**: every source runs concurrently; one shared rate limiter
  per run keeps provider quotas intact even with many domains in parallel.
- **Safe with untrusted data**: boundary-checked extraction (no
  `example.com.attacker.org` false positives), strict hostname validation,
  capped response bodies, API keys masked in logs.
- **Pipeline friendly**: results on stdout, logs on stderr, plain text or JSON
  Lines, reads domains from stdin.
- **subfinder-compatible flags**: `-d`, `-dL`, `-all`, `-nW`, `-oJ`, `-rls`
  and so on.

## Installation

Prebuilt binary (Linux and macOS, x86_64 and arm64; checksum-verified):

```bash
curl -sSfL https://raw.githubusercontent.com/0xh7ml/rustradar/main/install.sh | sh
```

Windows: download the `.zip` from the
[releases page](https://github.com/0xh7ml/rustradar/releases).

With Cargo (Rust 1.88 or newer, [rustup.rs](https://rustup.rs)):

```bash
cargo install --git https://github.com/0xh7ml/rustradar --locked   # like `go install`
cargo install rustradar --locked                                   # from crates.io
cargo binstall rustradar                                           # prebuilt, no compile
```

From a checkout:

```bash
cargo install --path .          # installs ~/.cargo/bin/rustradar

# Or just build
cargo build --release           # binary at target/release/rustradar

# Container
docker build -t rustradar .
docker run --rm rustradar -d example.com -silent
```

The crt.sh source can query crt.sh's public PostgreSQL database directly.
Build without that dependency with `cargo build --release --no-default-features`.

### Updating

```bash
rustradar -up        # download and install the latest release
```

Each normal run also checks for a newer release in the background and logs
`Current rustradar version vX.Y.Z (latest|outdated)`. Turn it off with `-duc`
(or `disable-update-check: true` in the flag config); `-silent` skips it too.
`-up` verifies the download against the release's `SHA256SUMS` before
replacing the binary. If the binary is in a system directory, run it with
`sudo`. Set `GITHUB_TOKEN` if you hit GitHub's anonymous API rate limit.

## Quick start

```bash
rustradar -d example.com                       # default sources
rustradar -d example.com -all -o subs.txt      # every source, save to file
rustradar -dL domains.txt -oD results/         # one file per domain
cat domains.txt | rustradar -silent            # read stdin, print only results
rustradar -d example.com -nW -oI               # resolve, drop wildcards, show IPs
rustradar -ls                                  # list sources (* = needs a key)
```

On first run rustradar creates `~/.config/rustradar/provider-config.yaml`. Add
API keys there to unlock more sources (see [Configuration](#configuration)).

## Usage

```text
rustradar [flags]
```

Every flag has a long form (`--list`). subfinder's single-dash spellings
(`-dL`, `-nW`, `-oJ`, `-silent`, ...) work too.

| Group | Flag | Description |
|---|---|---|
| **Input** | `-d, -domain` | Domains to enumerate (comma separated or repeated) |
| | `-dL, -list` | File with one domain per line |
| | *(stdin)* | Domains piped on stdin are read when `-d`/`-dL` are absent |
| **Source** | `-s, -sources` | Use only these sources (`-s crtsh,github`) |
| | `-es, -exclude-sources` | Never use these sources |
| | `-all` | Use every source, including slow ones |
| | `-recursive` | Use only sources that support subdomains of subdomains |
| **Filter** | `-m, -match` | Keep only hosts matching these globs (value or file) |
| | `-f, -filter` | Drop hosts matching these globs (value or file) |
| | `-match-regex` | Keep only hosts matching these regexes (value or file) |
| | `-filter-regex` | Drop hosts matching these regexes (value or file) |
| **Rate limit** | `-rl, -rate-limit` | Requests/second per source when no specific limit is set |
| | `-rls, -rate-limits` | Per-source limits, e.g. `-rls virustotal=4/m,shodan=1/s` |
| | `-t, -threads` | Domains processed in parallel and DNS lookups (default 10) |
| **Output** | `-o, -output` | Write results to a file |
| | `-oJ, -json` | JSON Lines output |
| | `-oD, -output-dir` | One file per domain in this directory |
| | `-cs, -collect-sources` | Include every source that reported each host |
| | `-oI, -ip` | Include the resolved IP (requires `-nW`) |
| **Config** | `-config` | Flag config file (default `~/.config/rustradar/config.yaml`) |
| | `-pc, -provider-config` | API key file (default `~/.config/rustradar/provider-config.yaml`) |
| | `-r, -resolvers` | DNS resolvers for `-nW` (`-r 1.1.1.1,8.8.8.8:53`) |
| | `-rL, -rlist` | File with DNS resolvers |
| | `-nW, -active` | Resolve results and remove wildcard DNS artifacts |
| | `-proxy` | HTTP or SOCKS5 proxy for source requests |
| | `-ei, -exclude-ip` | Skip IP addresses in the input |
| | `-mr, -max-results` | Max results per source (0 = unlimited) |
| **Debug** | `-silent` | Print only results |
| | `-v, -verbose` | Show each discovery (`[source] host`) and debug logs |
| | `-nc, -no-color` | No colors (also honors `NO_COLOR`) |
| | `-ls, -list-sources` | List sources (`-oJ` for JSON) |
| | `-stats` | Per-source statistics at the end |
| | `-version` | Version and config directory |
| **Optimization** | `-timeout` | Seconds per source request (default 30) |
| | `-max-time` | Minutes per domain before remaining sources are stopped (default 10) |
| | `-rsr, -response-size-read` | Max bytes read per response (0 = unlimited) |
| **Update** | `-up, -update` | Update to the latest release (checksum-verified) |
| | `-duc` | Disable the background check for a newer release |

Run `rustradar -h` for the full help text.

### Recipes

```bash
# Maximum coverage with a cap on response sizes (10 MiB)
rustradar -d example.com -all -rsr 10485760 -o all.txt

# Gentle on quotas
rustradar -d example.com -rl 20 -rls "hackertarget=2/s,virustotal=4/m,github=80/m"

# Only production/API hosts
rustradar -d example.com -match-regex '^(api|auth|vpn|portal)[0-9]*\.' -filter-regex '(dev|staging|test)'

# Many domains, per-domain JSON files with sources
rustradar -dL targets.txt -t 25 -oD out/ -oJ -cs

# Custom resolvers and a proxy
rustradar -d example.com -nW -r 1.1.1.1,9.9.9.9 -proxy http://127.0.0.1:8080
```

### Pipelines

```bash
rustradar -d example.com -silent | httpx -silent -title -status-code
cat domains.txt | rustradar -silent | anew inventory.txt | dnsx -silent -a -resp
```

## Output formats

| Mode | Plain text | JSON Lines (`-oJ`) |
|---|---|---|
| default | `host` | `{"host","input","source"}` |
| `-cs` | `host,[src1,src2]` | `{"host","input","sources":[...]}` |
| `-nW -oI` | `host,ip,source` | `{"host","ip","input","source"}` |

JSON objects get `"wildcard_certificate": true` when a source listed the host
as `*.host`. Results are written per domain, sorted, as soon as that domain
finishes.

## Configuration

**API keys** live in `~/.config/rustradar/provider-config.yaml`:

```yaml
shodan:
  - "SHODAN_KEY"
github:              # several keys: one is picked per run, tokens rotate on rate limits
  - "ghp_token1"
  - "ghp_token2"
fofa:
  - "you@example.com:FOFA_KEY"   # multi-part keys use ':'
```

Or as environment variables: `SHODAN_API_KEY=...`, `VIRUSTOTAL_API_KEY=k1,k2`.

**Flag defaults** can go in `~/.config/rustradar/config.yaml`:

```yaml
threads: 20
all: true
exclude-sources: [commoncrawl]
```

Details, including every source's key format: [docs/CONFIGURATION.md](docs/CONFIGURATION.md)
and [docs/SOURCES.md](docs/SOURCES.md).

## Library use

```rust
use rustradar::runner::{Options, Runner};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options = Options {
        sources: vec!["crtsh".into(), "hackertarget".into()],
        ..Default::default()
    };

    let runner = Runner::new(options)?
        .with_result_callback(|entry| eprintln!("found {}", entry.host));
    let results = runner.enumerate_single_domain("example.com").await?;
    println!("{:#?}", results.hosts());
    Ok(())
}
```

A fuller example is in [`examples/sdk.rs`](examples/sdk.rs)
(`cargo run --example sdk -- example.com`). API docs: `cargo doc --open`.

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Modules, data flow, concurrency, rate limiting, wildcard detection, design decisions |
| [docs/SOURCES.md](docs/SOURCES.md) | All 54 sources: provider, defaults, key formats, limits |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Provider keys, env vars, flag config, rate limits, resolvers |
| [docs/ADDING_A_SOURCE.md](docs/ADDING_A_SOURCE.md) | Step-by-step guide to add or fix a source |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Build, test, lint, release, maintenance and troubleshooting |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [plans/](plans/) | Original design specification (subfinder architecture) |

## Project layout

```text
src/
├── main.rs              CLI entry point
├── lib.rs               Library root
├── logger.rs            Leveled stderr logger with secret redaction
├── runner/              Options, config, batch dispatch, dedup, filters, output, stats
├── passive/             Source selection, shared rate limiter, concurrent fan-out
├── resolve/             DNS client, wildcard detection, resolution pool
└── subscraping/         Source trait, HTTP session, extractor
    └── sources/         One file per source (54)
tests/                   CLI and HTTP integration tests (offline)
examples/sdk.rs          Library usage example
```

## Legal

Only enumerate domains you own or are authorized to test, and respect the
terms and rate limits of each data provider. See [DISCLAIMER.md](DISCLAIMER.md).
Licensed under the [MIT License](LICENSE).
