//! # rustradar
//!
//! `rustradar` is a fast, passive subdomain enumeration engine written in Rust.
//! It follows the architecture of ProjectDiscovery's *subfinder*: it asks dozens
//! of passive data sources (certificate transparency logs, passive DNS, search
//! engines, threat-intel APIs, web archives) for the subdomains they know about,
//! instead of brute-forcing DNS against the target.
//!
//! The crate is both a CLI (`src/main.rs`) and a library. The modules mirror the
//! original Go packages so the design documents in `plans/` map one-to-one:
//!
//! | Module          | Responsibility                                                        |
//! |-----------------|-----------------------------------------------------------------------|
//! | [`runner`]      | Options, config files, batch dispatch, dedup, filtering, output, stats |
//! | [`passive`]     | Source registry, source selection, shared rate limiter, fan-out        |
//! | [`resolve`]     | Active DNS resolution and wildcard (canary) elimination                |
//! | [`subscraping`] | `Source` trait, HTTP session, subdomain extractor, the 54 sources      |
//! | [`logger`]      | Leveled, colorized stderr logger with secret redaction                 |
//!
//! ## Library example
//!
//! ```no_run
//! use rustradar::runner::{Options, Runner};
//!
//! # async fn demo() -> anyhow::Result<()> {
//! let options = Options {
//!     sources: vec!["crtsh".into(), "hackertarget".into()],
//!     ..Default::default()
//! };
//!
//! let runner = Runner::new(options)?;
//! let results = runner.enumerate_single_domain("example.com").await?;
//! for host in results.hosts() {
//!     println!("{host}");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! See `docs/ARCHITECTURE.md` for a full walkthrough of the data flow.

pub mod logger;
pub mod passive;
pub mod resolve;
pub mod runner;
pub mod subscraping;

/// Crate version, taken from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
