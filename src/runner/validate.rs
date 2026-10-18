//! Option validation and match/filter compilation.

use std::path::Path;

use regex::Regex;

use super::Options;
use crate::subscraping::sources;

/// Check option combinations before running. Mirrors subfinder's rules.
pub fn validate_options(options: &Options) -> anyhow::Result<()> {
    if options.domain.is_empty() && options.list.is_none() && !options.stdin {
        anyhow::bail!("no input list provided (use -d, -dL or pipe domains on stdin)");
    }
    if options.verbose && options.silent {
        anyhow::bail!("both verbose and silent mode specified");
    }
    if options.threads == 0 {
        anyhow::bail!("threads must be positive");
    }
    if options.timeout == 0 {
        anyhow::bail!("timeout cannot be zero");
    }
    if options.max_time == 0 {
        anyhow::bail!("max-time cannot be zero");
    }
    if options.ip && !options.active {
        anyhow::bail!("-oI/-ip must be used with -nW/-active");
    }
    let known: Vec<&str> = sources::all().iter().map(|s| s.name()).collect();
    for limit in crate::passive::parse_rate_limits(&options.rate_limits)
        .map_err(anyhow::Error::msg)?
        .keys()
    {
        if !known.contains(&limit.as_str()) {
            anyhow::bail!("invalid source {limit} specified in -rls flag");
        }
    }
    Ok(())
}

/// Compiled `-m/-f/-match-regex/-filter-regex` rules.
#[derive(Debug, Clone, Default)]
pub struct Filters {
    matchers: Vec<Regex>,
    filters: Vec<Regex>,
}

impl Filters {
    /// Compile the rules. Each value may be a pattern or a path to a file with
    /// one pattern per line. Globs (`-m`, `-f`) are anchored; `*` matches any
    /// run of characters. Regexes are unanchored.
    pub fn compile(
        match_globs: &[String],
        filter_globs: &[String],
        match_regexes: &[String],
        filter_regexes: &[String],
    ) -> anyhow::Result<Self> {
        Ok(Self {
            matchers: compile("match", match_globs, match_regexes)?,
            filters: compile("filter", filter_globs, filter_regexes)?,
        })
    }

    /// `true` when `host` should be kept: it matches no filter, and matches at
    /// least one matcher when matchers are configured.
    pub fn allows(&self, host: &str) -> bool {
        if self.filters.iter().any(|re| re.is_match(host)) {
            return false;
        }
        self.matchers.is_empty() || self.matchers.iter().any(|re| re.is_match(host))
    }

    /// `true` when no rules are configured.
    pub fn is_empty(&self) -> bool {
        self.matchers.is_empty() && self.filters.is_empty()
    }
}

fn compile(option: &str, globs: &[String], regexes: &[String]) -> anyhow::Result<Vec<Regex>> {
    let mut out = Vec::new();
    for glob in expand_file_values(globs) {
        let re = Regex::new(&glob_to_regex(&glob))
            .map_err(|e| anyhow::anyhow!("invalid value for {option} option {glob:?}: {e}"))?;
        out.push(re);
    }
    for pattern in expand_file_values(regexes) {
        let re = Regex::new(&pattern).map_err(|e| {
            anyhow::anyhow!("invalid value for {option}-regex option {pattern:?}: {e}")
        })?;
        out.push(re);
    }
    Ok(out)
}

/// `api.*` -> `^api\..*$`. Only `*` is special.
pub fn glob_to_regex(glob: &str) -> String {
    let escaped: Vec<String> = glob.split('*').map(regex::escape).collect();
    format!("^{}$", escaped.join(".*"))
}

/// Replace values that are paths to existing files with the file's
/// non-empty lines.
pub fn expand_file_values(values: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for value in values.iter().map(|v| v.trim()).filter(|v| !v.is_empty()) {
        let path = Path::new(value);
        if path.is_file() {
            if let Ok(text) = std::fs::read_to_string(path) {
                out.extend(
                    text.lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .map(String::from),
                );
                continue;
            }
        }
        out.push(value.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn globs() {
        assert_eq!(glob_to_regex("api.*"), r"^api\..*$");
        let f = Filters::compile(&s(&["api.*", "*.prod.example.com"]), &[], &[], &[]).unwrap();
        assert!(f.allows("api.example.com"));
        assert!(f.allows("x.prod.example.com"));
        assert!(!f.allows("www.example.com"));
        assert!(!f.allows("apix.example.com"));
    }

    #[test]
    fn filters_win_over_matchers() {
        let f = Filters::compile(
            &s(&["*"]),
            &s(&["*.dev.example.com"]),
            &[],
            &s(&["staging"]),
        )
        .unwrap();
        assert!(f.allows("www.example.com"));
        assert!(!f.allows("a.dev.example.com"));
        assert!(!f.allows("staging1.example.com"));
    }

    #[test]
    fn regexes_are_unanchored() {
        let f = Filters::compile(&[], &[], &s(&["^(api|auth)[0-9]*\\."]), &[]).unwrap();
        assert!(f.allows("api2.example.com"));
        assert!(!f.allows("www.example.com"));
    }

    #[test]
    fn invalid_regex_is_an_error() {
        assert!(Filters::compile(&[], &[], &s(&["("]), &[]).is_err());
    }

    #[test]
    fn values_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.txt");
        std::fs::write(&path, "api.*\n\nwww.*\n").unwrap();
        let values = expand_file_values(&[path.to_string_lossy().to_string(), "x.*".into()]);
        assert_eq!(values, vec!["api.*", "www.*", "x.*"]);
    }

    #[test]
    fn validation_rules() {
        let mut o = Options::default();
        assert!(validate_options(&o).is_err()); // no input
        o.domain = vec!["example.com".into()];
        assert!(validate_options(&o).is_ok());
        o.ip = true;
        assert!(validate_options(&o).is_err()); // -oI without -nW
        o.active = true;
        assert!(validate_options(&o).is_ok());
        o.rate_limits = vec!["nosuchsource=1/s".into()];
        assert!(validate_options(&o).is_err());
        o.rate_limits = vec!["shodan=1/s".into()];
        assert!(validate_options(&o).is_ok());
        o.verbose = true;
        o.silent = true;
        assert!(validate_options(&o).is_err());
    }
}
