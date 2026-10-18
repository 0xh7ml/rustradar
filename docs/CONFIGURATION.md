# Configuration

rustradar reads three kinds of configuration: API keys, flag defaults, and
command-line flags. All files live in the config directory:

| Platform | Directory |
|---|---|
| Linux | `$XDG_CONFIG_HOME/rustradar` or `~/.config/rustradar` |
| macOS | `~/Library/Application Support/rustradar` |
| Windows | `%APPDATA%\rustradar` |

`rustradar -version` prints the directory in use.

## 1. API keys (`provider-config.yaml`)

Created on first run with an empty entry for every source that accepts keys
(file mode 600 on Unix). Fill in the ones you have:

```yaml
virustotal:
  - "VT_KEY"
github:
  - "ghp_first_token"
  - "ghp_second_token"
censys:
  - "PAT:ORG_ID"
fofa:
  - "you@example.com:FOFA_KEY"
```

Rules:

* Keys are listed under the source name (case-insensitive). A single string
  instead of a list also works.
* With several keys, one is picked at random per domain to spread quota.
  `github` rotates through all tokens when one is rate limited.
* Multi-part keys are joined with `:`. The format per source is in
  [SOURCES.md](SOURCES.md). Sources whose key does not have the expected shape
  report an "invalid key format" warning.
* Use another file with `-pc path/to/file.yaml` or the
  `RUSTRADAR_PROVIDER_CONFIG` environment variable.

### Environment variables

`<SOURCE>_API_KEY` adds keys on top of the file. Separate several keys with
commas:

```bash
export SHODAN_API_KEY="key1"
export GITHUB_API_KEY="ghp_a,ghp_b"
export FOFA_API_KEY="you@example.com:key"
```

### Secret handling

Every key (and each half of multi-part keys) is registered with the logger at
load time and replaced by `[REDACTED]` in all log output, including error
messages that contain request URLs. Keys are never written to result files.

## 2. Flag defaults (`config.yaml`)

Default values for any CLI flag, using the long flag name as the key:

```yaml
# ~/.config/rustradar/config.yaml
threads: 20
timeout: 45
all: true
exclude-sources: [commoncrawl, waybackarchive]
rate-limits: ["virustotal=4/m", "github=60/m"]
silent: false        # false is the same as leaving it out
```

* The default file is loaded automatically when it exists. `-config path`
  loads another file (and fails if it does not exist).
* Booleans: `true` turns the flag on. A file cannot turn off a flag given on
  the command line.
* Scalar flags (`threads`, `timeout`, ...): the command line wins.
* List flags (`sources`, `domain`, `rate-limits`, ...): values from the file
  and the command line are combined.

Internally the file is converted into `--name=value` arguments that are
placed before the real ones (`runner/config.rs::parse_flag_config`).

## 3. Rate limits

| Flag | Meaning |
|---|---|
| `-rls source=N/unit,...` | Limit for specific sources. Units: `ms`, `s`, `m`, `h`. A bare number means per second. |
| `-rl N` | N requests per second for every source without a specific limit. |
| *(built-in)* | Defaults for strict providers, listed in [SOURCES.md](SOURCES.md#built-in-rate-limits). `-rls` overrides them. |

Limits are shared by all domains in a run: with `-dL` and `-t 25`, the
`virustotal=4/m` budget is still 4 requests per minute in total.

Precedence for one source: `-rls` > built-in default > `-rl` > unlimited.

## 4. DNS resolvers (active mode)

`-nW` resolves every result. Resolvers, in order of preference:

1. `-r 1.1.1.1,8.8.8.8:53` and/or `-rL resolvers.txt` (one `ip` or `ip:port`
   per line, `#` comments allowed; IPv6 as `[::1]:53`).
2. Otherwise the built-in public list: Cloudflare, Google, Quad9, Yandex and
   OpenDNS (`resolve::DEFAULT_RESOLVERS`).

Queries use UDP with 2 attempts and a timeout of `-timeout` clamped to 1-10
seconds. Concurrent lookups are limited to `-t` for the whole run.

## 5. Network

* `-proxy URL`: `http://`, `https://` or `socks5://` proxy for all source HTTP
  requests (not for DNS or the crt.sh PostgreSQL connection).
* `-timeout S`: connect and total timeout per request.
* `-max-time M`: per-domain deadline; sources still running are stopped and
  report "time limit reached".
* `-rsr BYTES`: read at most this many bytes of each response body.

## 6. Environment variables summary

| Variable | Effect |
|---|---|
| `<SOURCE>_API_KEY` | Extra API keys for a source |
| `RUSTRADAR_PROVIDER_CONFIG` | Provider config path (same as `-pc`) |
| `XDG_CONFIG_HOME` | Base of the config directory on Linux |
| `NO_COLOR` | Disable colors (same as `-nc`) |
