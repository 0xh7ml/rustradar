# Development and maintenance

## Prerequisites

* Rust 1.88+ (`rustup update stable`). The minimum comes from dependencies
  and is set as `rust-version` in `Cargo.toml`.
* No system libraries are needed: TLS is rustls, DNS is hickory, the crt.sh
  PostgreSQL client is pure Rust.

## Everyday commands

| Task | Command |
|---|---|
| Build (debug) | `cargo build` |
| Build (release) | `cargo build --release` → `target/release/rustradar` |
| Run | `cargo run -- -d example.com -v` |
| All tests (offline) | `cargo test` |
| One test | `cargo test extractor` |
| Lint | `cargo clippy --all-targets -- -D warnings` |
| Format | `cargo fmt` |
| API docs | `cargo doc --no-deps --open` |
| Everything CI runs | `make check` |
| Without crt.sh SQL | `cargo build --no-default-features` |
| SDK example | `cargo run --example sdk -- example.com` |

`make help` lists the Makefile targets.

## Code layout

```text
src/
├── main.rs                  CLI: fd limit, flag parsing + config merge, info flags, runtime, Ctrl-C
├── lib.rs                   Crate docs, module list, VERSION
├── logger.rs                Levels, colors, [REDACTED] secret masking, macros (info!, warn!, ...)
├── runner/
│   ├── mod.rs               Runner: construction, batch dispatch, output files, list_sources
│   ├── options.rs           clap Options, single-dash alias rewriting (normalize_args)
│   ├── config.rs            Config dir, provider keys (+ env), template, flag config → args
│   ├── enumerate.rs         Per-domain pipeline, DomainResults
│   ├── output.rs            Plain / JSON / sources / host,ip rendering
│   ├── stats.rs             -stats table
│   ├── util.rs              Input cleaning, normalization, hostname validation
│   ├── validate.rs          Option checks, glob/regex filters
│   └── banner.rs            Banner, update text
├── passive/
│   ├── mod.rs               select_sources, Agent (fan-out, skip, timeout, stats)
│   └── limiter.rs           RateLimit parsing, shared fixed-window RateLimiter, defaults
├── resolve/
│   ├── client.rs            Resolver (hickory), default resolvers, concurrency slots
│   └── pool.rs              Wildcard canaries, ResolutionPool, HostEntry/Resolved
└── subscraping/
    ├── mod.rs               Source trait, SourceInfo, SourceResult, Statistics
    ├── context.rs           Ctx (per-source context), Request builder, status errors
    ├── session.rs           HTTP client builder, Session, body cap, StatusError
    ├── extractor.rs         Boundary-safe subdomain regex extraction
    ├── utils.rs             Key helpers, URL helpers, current_year
    └── sources/             54 sources + registry (mod.rs)
tests/
├── cli.rs                   Runs the binary: -ls, -version, validation, config files
└── http.rs                  Local HTTP server: extraction, status errors, body cap, rate limit, deadline
```

## Testing strategy

| Layer | Where | Covers |
|---|---|---|
| Unit | `#[cfg(test)]` in each module | extractor boundaries, normalization, filters, rate-limit parsing and timing (tokio paused clock), options and aliases, config parsing, output formats, source selection, agent stats, helpers in sources |
| HTTP integration | `tests/http.rs` | real HTTP through `Ctx` against a local server |
| CLI integration | `tests/cli.rs` | the compiled binary, with `XDG_CONFIG_HOME` pointed at a temp dir |
| Live (manual) | your shell | real providers; not run in CI because results and availability change |

All automated tests are offline and deterministic. A quick live check before
a release:

```bash
rustradar -d hackerone.com -stats              # keyless default sources
rustradar -d hackerone.com -nW -oI -s crtsh,hackertarget,shodanct
rustradar -d hackerone.com -all -stats         # with your provider keys
```

Look at the `-stats` table: a source with errors and 0 results for a popular
domain probably needs fixing (see
[ADDING_A_SOURCE.md](ADDING_A_SOURCE.md#fixing-a-broken-source)).

## Conventions

* `cargo fmt` and `cargo clippy -D warnings` must be clean; CI enforces both.
* Public items have doc comments; `RUSTDOCFLAGS="-D warnings" cargo doc` is clean.
* Logs go through the logger macros (stderr). Only results go to stdout.
* No `unwrap()` on data from the network or the user; return errors with
  context (`anyhow::Context`).
* Keep `sources::all()` alphabetical.
* Comments explain *why*, not *what*.

## Releasing

Releases are built by `.github/workflows/release.yml` when a `vX.Y.Z` tag is
pushed. It:

1. checks that the tag matches `version` in `Cargo.toml` and runs the tests;
2. builds `x86_64`/`aarch64` Linux (static musl, via `cross`), `x86_64`/`aarch64`
   macOS and `x86_64` Windows;
3. publishes a GitHub release with `rustradar-vX.Y.Z-<target>.tar.gz` (`.zip`
   on Windows), `SHA256SUMS`, and the matching `CHANGELOG.md` section as notes
   (tags with a `-`, such as `v1.0.0-rc.1`, become prereleases);
4. runs `cargo publish` if the `CARGO_REGISTRY_TOKEN` repository secret is set.

To cut a release:

```bash
# 1. Bump `version` in Cargo.toml, move [Unreleased] notes in CHANGELOG.md to
#    a new "## [X.Y.Z] - YYYY-MM-DD" section.
make check                      # fmt, clippy, tests
cargo build --release && ./target/release/rustradar -d example.com   # smoke test
git commit -am "Release vX.Y.Z"
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin main vX.Y.Z     # the tag starts the release workflow
```

After it finishes, check from an older install: `rustradar -up` should
update, and `rustradar -version` should print the new version.

The asset names are a contract between four places; change them together:
`archive_name` in `src/runner/update.rs`, the Package step of
`release.yml`, `install.sh`, and `[package.metadata.binstall]` in
`Cargo.toml`. `REPOSITORY` in `src/runner/update.rs` (and `REPO` in
`install.sh`) must name the GitHub repository that publishes releases.

A bad release can be fixed by publishing a newer patch version. Deleting a
release makes `-up` fall back to the previous "latest" release; it never
downgrades a newer binary.

Versioning follows SemVer. For the library API, breaking changes are changes
to public items in `runner`, `passive`, `resolve` and `subscraping`
(including the `Source` trait and `Ctx`).

## Maintenance tasks

### Provider APIs change

This is the most common work. Run the live check regularly; fix sources as
described in [ADDING_A_SOURCE.md](ADDING_A_SOURCE.md#fixing-a-broken-source).
Upstream subfinder's source tree is a useful reference for API changes since
the source names and logic match.

### Dependency updates

```bash
cargo update            # within semver ranges
cargo outdated          # (cargo install cargo-outdated) see major updates
cargo audit             # (cargo install cargo-audit) security advisories
```

Known future migrations:

* **serde_yaml** is deprecated (still works). Replacement candidates:
  `serde_yml` or `serde_norway`. Only `runner/config.rs` uses it.
* **hickory-resolver 0.24 → 0.25+** changed the builder API
  (`Resolver::builder_with_config(config, TokioConnectionProvider::default())`)
  and moved error types. Only `resolve/client.rs` uses it.
* **rand 0.8 → 0.9+** renamed `thread_rng()` to `rng()` and
  `distributions` to `distr`. Used in `session.rs`, `utils.rs`, `resolve/pool.rs`.
* **reqwest 0.12 → 0.13**: check `danger_accept_invalid_certs`, proxy and
  feature names in `session.rs` and `Cargo.toml`.

### Updating built-in defaults

* Default rate limits: `passive::DEFAULT_RATE_LIMITS` (a test checks names).
* Default resolvers: `resolve::DEFAULT_RESOLVERS`.
* User-Agent strings: `subscraping/session.rs::USER_AGENTS` (refresh yearly).

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Many sources "skipped" in `-stats` | No keys configured; edit `provider-config.yaml`. |
| `unexpected status code 401/403` | Bad or expired key, or the provider blocks the request. Check with `-v`. |
| `429` / "quota exhausted" | Lower the source's limit with `-rls`, add keys, or wait. |
| Source hits "time limit reached" | Raise `-max-time`, or exclude it with `-es`. |
| crt.sh slow | The SQL query can take ~20 s for large domains; it then skips the HTTP API. Port 5432 blocked? It falls back to HTTP after `-timeout`. |
| `too many open files` | Lower `-t`, or raise `ulimit -n` (rustradar raises the soft limit to the hard limit automatically). |
| No colors / colors in files | Colors are only used when stderr is a terminal; `-nc` or `NO_COLOR` disables them. |
| Proxy not used for DNS | Expected: `-proxy` applies to HTTP sources only. |
