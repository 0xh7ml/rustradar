# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-18

First release: a Rust implementation of the subfinder architecture described
in `plans/`.

### Added

- CLI with subfinder-compatible flags, including single-dash aliases (`-dL`,
  `-nW`, `-oJ`, `-oD`, `-oI`, `-cs`, `-rls`, ...).
- 54 passive sources (see `docs/SOURCES.md`).
- Shared fixed-window rate limiter across all domains in a run, with
  subfinder's default per-provider limits, `-rl` and `-rls`.
- Active resolution (`-nW`) with three-probe wildcard detection and custom
  resolvers (`-r`, `-rL`).
- Output as plain text or JSON Lines, with sources (`-cs`) or IPs (`-oI`), to
  stdout, a file (`-o`) or one file per domain (`-oD`).
- Glob and regex match/filter rules (`-m`, `-f`, `-match-regex`,
  `-filter-regex`), as values or files.
- Provider config with template generation, `<SOURCE>_API_KEY` environment
  variables, and a YAML flag config file.
- crt.sh direct PostgreSQL query with HTTP fallback (feature `crtsh-sql`).
- Per-source statistics (`-stats`), summed over all domains.
- Library API (`Runner`, `Agent`, `Source` trait) and `examples/sdk.rs`.
- Security hardening: boundary-safe extraction, strict hostname validation,
  response body cap, API key redaction in logs, page caps on every paginating
  source.
- Documentation: README, architecture, sources, configuration, adding a
  source, development and maintenance guides.
- Self-update (`-up`) from GitHub releases with SHA-256 verification, and a
  background "latest/outdated" version check on each run (`-duc` disables it).
- Release workflow building Linux, macOS and Windows binaries on `vX.Y.Z`
  tags; `install.sh` installer; `cargo binstall` metadata.
- Offline unit and integration tests; GitHub Actions CI for Linux, macOS and
  Windows.
