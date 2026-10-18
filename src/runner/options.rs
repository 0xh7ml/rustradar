//! Command-line options.
//!
//! Flags use the same names as subfinder. Because `clap` only supports
//! single-character short flags, subfinder's multi-letter single-dash flags
//! (`-dL`, `-nW`, `-oJ`, `-all`, `-silent`, ...) are rewritten to their long
//! form by [`normalize_args`] before parsing. Both spellings work:
//! `-dL targets.txt` == `--list targets.txt`.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::Parser;

/// Fast passive subdomain enumeration.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "rustradar",
    about = "rustradar is a fast passive subdomain enumeration tool.",
    long_about = None,
    disable_version_flag = true,
    args_override_self = true,
    after_help = "Single-dash aliases from subfinder are accepted, e.g. -dL, -nW, -oJ, -oD, -oI, -cs, -es, -rl, -rls, -rL, -ei, -pc, -mr, -rsr, -ls, -nc, -duc, -up.\nDocs: README.md and docs/ in the source tree."
)]
pub struct Options {
    // ----- Input -----
    /// Domains to find subdomains for (comma separated or repeated)
    #[arg(
        short = 'd',
        long = "domain",
        value_delimiter = ',',
        help_heading = "INPUT"
    )]
    pub domain: Vec<String>,

    /// File containing a list of domains, one per line [-dL]
    #[arg(long = "list", value_name = "FILE", help_heading = "INPUT")]
    pub list: Option<PathBuf>,

    // ----- Source -----
    /// Sources to use, e.g. -s crtsh,github (see -ls)
    #[arg(
        short = 's',
        long = "sources",
        value_delimiter = ',',
        help_heading = "SOURCE"
    )]
    pub sources: Vec<String>,

    /// Use only sources that can handle subdomains recursively
    #[arg(long = "recursive", help_heading = "SOURCE")]
    pub recursive: bool,

    /// Use all sources, including slow ones
    #[arg(long = "all", help_heading = "SOURCE")]
    pub all: bool,

    /// Sources to exclude, e.g. -es alienvault,zoomeyeapi [-es]
    #[arg(
        long = "exclude-sources",
        value_delimiter = ',',
        help_heading = "SOURCE"
    )]
    pub exclude_sources: Vec<String>,

    // ----- Filter -----
    /// Subdomains or glob patterns to match (value or file), e.g. -m 'api*'
    #[arg(
        short = 'm',
        long = "match",
        value_delimiter = ',',
        help_heading = "FILTER"
    )]
    pub r#match: Vec<String>,

    /// Subdomains or glob patterns to drop (value or file), e.g. -f '*.dev.*'
    #[arg(
        short = 'f',
        long = "filter",
        value_delimiter = ',',
        help_heading = "FILTER"
    )]
    pub filter: Vec<String>,

    /// Regular expressions subdomains must match (value or file)
    #[arg(long = "match-regex", help_heading = "FILTER")]
    pub match_regex: Vec<String>,

    /// Regular expressions of subdomains to drop (value or file)
    #[arg(long = "filter-regex", help_heading = "FILTER")]
    pub filter_regex: Vec<String>,

    // ----- Rate limit -----
    /// Maximum HTTP requests per second per source (global default) [-rl]
    #[arg(long = "rate-limit", default_value_t = 0, help_heading = "RATE-LIMIT")]
    pub rate_limit: u32,

    /// Per-source limits, e.g. -rls hackertarget=10/s,virustotal=4/m [-rls]
    #[arg(
        long = "rate-limits",
        value_delimiter = ',',
        help_heading = "RATE-LIMIT"
    )]
    pub rate_limits: Vec<String>,

    /// Maximum concurrent domains and active DNS lookups
    #[arg(
        short = 't',
        long = "threads",
        default_value_t = 10,
        help_heading = "RATE-LIMIT"
    )]
    pub threads: usize,

    // ----- Update -----
    /// Update rustradar to the latest release [-up]
    #[arg(long = "update", help_heading = "UPDATE")]
    pub update: bool,

    /// Disable the automatic update check [-duc]
    #[arg(long = "disable-update-check", help_heading = "UPDATE")]
    pub disable_update_check: bool,

    // ----- Output -----
    /// File to write output to
    #[arg(
        short = 'o',
        long = "output",
        value_name = "FILE",
        help_heading = "OUTPUT"
    )]
    pub output: Option<PathBuf>,

    /// Write output in JSON Lines format [-oJ]
    #[arg(long = "json", help_heading = "OUTPUT")]
    pub json: bool,

    /// Directory to write one output file per domain [-oD]
    #[arg(long = "output-dir", value_name = "DIR", help_heading = "OUTPUT")]
    pub output_dir: Option<PathBuf>,

    /// Include all sources for each subdomain in the output [-cs]
    #[arg(long = "collect-sources", help_heading = "OUTPUT")]
    pub collect_sources: bool,

    /// Include the resolved IP in the output (requires -nW) [-oI]
    #[arg(long = "ip", help_heading = "OUTPUT")]
    pub ip: bool,

    // ----- Configuration -----
    /// Flag config file (default: $CONFIG/rustradar/config.yaml)
    #[arg(long = "config", value_name = "FILE", help_heading = "CONFIGURATION")]
    pub config: Option<PathBuf>,

    /// Provider (API key) config file [-pc]
    #[arg(
        long = "provider-config",
        value_name = "FILE",
        env = "RUSTRADAR_PROVIDER_CONFIG",
        help_heading = "CONFIGURATION"
    )]
    pub provider_config: Option<PathBuf>,

    /// DNS resolvers to use, e.g. -r 1.1.1.1,8.8.8.8:53
    #[arg(
        short = 'r',
        long = "resolvers",
        value_delimiter = ',',
        help_heading = "CONFIGURATION"
    )]
    pub resolvers: Vec<String>,

    /// File containing DNS resolvers, one per line [-rL]
    #[arg(long = "rlist", value_name = "FILE", help_heading = "CONFIGURATION")]
    pub resolver_list: Option<PathBuf>,

    /// Show only subdomains that resolve, removing wildcards [-nW]
    #[arg(long = "active", help_heading = "CONFIGURATION")]
    pub active: bool,

    /// HTTP or SOCKS5 proxy for all source requests
    #[arg(long = "proxy", value_name = "URL", help_heading = "CONFIGURATION")]
    pub proxy: Option<String>,

    /// Skip IP addresses in the input list [-ei]
    #[arg(long = "exclude-ip", help_heading = "CONFIGURATION")]
    pub exclude_ip: bool,

    /// Maximum results per source, 0 = unlimited (paginating sources) [-mr]
    #[arg(
        long = "max-results",
        default_value_t = 0,
        help_heading = "CONFIGURATION"
    )]
    pub max_results: usize,

    // ----- Debug -----
    /// Show only subdomains in output
    #[arg(long = "silent", help_heading = "DEBUG")]
    pub silent: bool,

    /// Show version and config directory
    #[arg(long = "version", help_heading = "DEBUG")]
    pub version: bool,

    /// Show verbose output (per-source discoveries and debug logs)
    #[arg(short = 'v', long = "verbose", help_heading = "DEBUG")]
    pub verbose: bool,

    /// Disable colors in output [-nc]
    #[arg(long = "no-color", help_heading = "DEBUG")]
    pub no_color: bool,

    /// List all available sources (-oJ for JSON) [-ls]
    #[arg(long = "list-sources", help_heading = "DEBUG")]
    pub list_sources: bool,

    /// Report per-source statistics at the end
    #[arg(long = "stats", help_heading = "DEBUG")]
    pub stats: bool,

    // ----- Optimization -----
    /// Seconds to wait before a source request times out
    #[arg(long = "timeout", default_value_t = 30, help_heading = "OPTIMIZATION")]
    pub timeout: u64,

    /// Minutes to wait for enumeration results per domain
    #[arg(long = "max-time", default_value_t = 10, help_heading = "OPTIMIZATION")]
    pub max_time: u64,

    /// Maximum response body bytes read per request, 0 = unlimited [-rsr]
    #[arg(
        long = "response-size-read",
        default_value_t = 0,
        help_heading = "OPTIMIZATION"
    )]
    pub response_size_read: usize,

    /// Set automatically when input is piped on stdin.
    #[arg(skip)]
    pub stdin: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self::parse_from(["rustradar"])
    }
}

/// Single-dash spellings (without the dash) mapped to clap long names.
const ALIASES: &[(&str, &str)] = &[
    ("dL", "list"),
    ("list", "list"),
    ("domain", "domain"),
    ("sources", "sources"),
    ("es", "exclude-sources"),
    ("exclude-sources", "exclude-sources"),
    ("all", "all"),
    ("recursive", "recursive"),
    ("match", "match"),
    ("filter", "filter"),
    ("match-regex", "match-regex"),
    ("filter-regex", "filter-regex"),
    ("rl", "rate-limit"),
    ("rate-limit", "rate-limit"),
    ("rls", "rate-limits"),
    ("rate-limits", "rate-limits"),
    ("threads", "threads"),
    ("nW", "active"),
    ("active", "active"),
    ("oI", "ip"),
    ("ip", "ip"),
    ("resolvers", "resolvers"),
    ("rL", "rlist"),
    ("rlist", "rlist"),
    ("ei", "exclude-ip"),
    ("exclude-ip", "exclude-ip"),
    ("output", "output"),
    ("oJ", "json"),
    ("json", "json"),
    ("oD", "output-dir"),
    ("output-dir", "output-dir"),
    ("cs", "collect-sources"),
    ("collect-sources", "collect-sources"),
    ("silent", "silent"),
    ("nc", "no-color"),
    ("no-color", "no-color"),
    ("config", "config"),
    ("pc", "provider-config"),
    ("provider-config", "provider-config"),
    ("proxy", "proxy"),
    ("timeout", "timeout"),
    ("max-time", "max-time"),
    ("mr", "max-results"),
    ("max-results", "max-results"),
    ("rsr", "response-size-read"),
    ("response-size-read", "response-size-read"),
    ("verbose", "verbose"),
    ("version", "version"),
    ("ls", "list-sources"),
    ("list-sources", "list-sources"),
    ("stats", "stats"),
    ("up", "update"),
    ("update", "update"),
    ("duc", "disable-update-check"),
    ("disable-update-check", "disable-update-check"),
];

/// Rewrite subfinder-style single-dash flags (`-dL x`, `-oJ`, `-rl=5`) into
/// clap long flags (`--list x`, `--json`, `--rate-limit=5`).
///
/// Tokens that are not known aliases (including single-letter flags like `-d`)
/// pass through unchanged, and nothing after a bare `--` is touched.
pub fn normalize_args<I, T>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let mut out = Vec::new();
    let mut passthrough = false;
    for arg in args {
        let arg: OsString = arg.into();
        if passthrough {
            out.push(arg);
            continue;
        }
        let Some(text) = arg.to_str() else {
            out.push(arg);
            continue;
        };
        if text == "--" {
            passthrough = true;
            out.push(arg);
            continue;
        }
        if let Some(flag) = text
            .strip_prefix('-')
            .filter(|f| !f.starts_with('-') && f.len() > 1)
        {
            let (name, value) = match flag.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (flag, None),
            };
            if let Some((_, long)) = ALIASES.iter().find(|(alias, _)| *alias == name) {
                let rewritten = match value {
                    Some(v) => format!("--{long}={v}"),
                    None => format!("--{long}"),
                };
                out.push(OsString::from(rewritten));
                continue;
            }
        }
        out.push(arg);
    }
    out
}

/// Find the value of `--config` in already-normalized args (used to load the
/// flag config file before the full parse).
pub fn find_config_arg(args: &[OsString]) -> Option<PathBuf> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let text = arg.to_str()?;
        if text == "--" {
            break;
        }
        if text == "--config" {
            return iter.next().map(PathBuf::from);
        }
        if let Some(v) = text.strip_prefix("--config=") {
            return Some(PathBuf::from(v));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Options {
        let mut full = vec!["rustradar"];
        full.extend_from_slice(args);
        Options::parse_from(normalize_args(full))
    }

    #[test]
    fn defaults() {
        let o = Options::default();
        assert_eq!(o.threads, 10);
        assert_eq!(o.timeout, 30);
        assert_eq!(o.max_time, 10);
        assert!(!o.active && !o.json && o.domain.is_empty());
    }

    #[test]
    fn subfinder_style_flags() {
        let o = parse(&[
            "-d",
            "a.com,b.com",
            "-dL",
            "t.txt",
            "-nW",
            "-oJ",
            "-oI",
            "-cs",
            "-all",
            "-silent",
            "-rl",
            "5",
            "-rls",
            "github=80/m,shodan=1/s",
            "-es",
            "x,y",
            "-t",
            "20",
            "-rsr=1024",
            "-oD",
            "out",
        ]);
        assert_eq!(o.domain, vec!["a.com", "b.com"]);
        assert_eq!(o.list.unwrap().to_str(), Some("t.txt"));
        assert!(o.active && o.json && o.ip && o.collect_sources && o.all && o.silent);
        assert_eq!(o.rate_limit, 5);
        assert_eq!(o.rate_limits, vec!["github=80/m", "shodan=1/s"]);
        assert_eq!(o.exclude_sources, vec!["x", "y"]);
        assert_eq!(o.threads, 20);
        assert_eq!(o.response_size_read, 1024);
        assert_eq!(o.output_dir.unwrap().to_str(), Some("out"));
    }

    #[test]
    fn long_flags_still_work() {
        let o = parse(&["--domain", "a.com", "--active", "--json"]);
        assert!(o.active && o.json);
    }

    #[test]
    fn later_flags_override_earlier_ones() {
        // Used to let CLI flags override values from the config file.
        let o = parse(&["--threads", "3", "-t", "7"]);
        assert_eq!(o.threads, 7);
    }

    #[test]
    fn repeated_list_flags_accumulate() {
        let o = parse(&["-d", "a.com", "-d", "b.com,c.com"]);
        assert_eq!(o.domain, vec!["a.com", "b.com", "c.com"]);
    }

    #[test]
    fn passthrough_after_double_dash() {
        let args = normalize_args(["rustradar", "--", "-all"]);
        assert_eq!(args[2], OsString::from("-all"));
    }

    #[test]
    fn finds_config() {
        let args = normalize_args(["rustradar", "-config", "x.yaml"]);
        assert_eq!(find_config_arg(&args), Some(PathBuf::from("x.yaml")));
        let args = normalize_args(["rustradar", "--config=y.yaml"]);
        assert_eq!(find_config_arg(&args), Some(PathBuf::from("y.yaml")));
    }
}
