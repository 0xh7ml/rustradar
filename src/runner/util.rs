//! Input and candidate normalization helpers.

/// Patterns removed from candidates, checked in this order at each position
/// (same semantics as Go's `strings.NewReplacer`).
const STRIP_PATTERNS: &[&str] = &["/", "•.", "•", "*.", "http://", "https://"];

/// Clean one line of input into an apex domain.
///
/// Trims quotes/whitespace, drops `#` comments, lowercases, strips an
/// `http(s)://` scheme and any path, query or fragment, and removes a leading
/// wildcard or bullet.
pub fn preprocess_domain(line: &str) -> String {
    let line = line.split('#').next().unwrap_or_default();
    let mut s = line
        .trim_matches(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`'))
        .to_lowercase();
    for scheme in ["https://", "http://"] {
        if let Some(rest) = s.strip_prefix(scheme) {
            s = rest.to_string();
        }
    }
    if let Some(idx) = s.find(['/', '?', '#']) {
        s.truncate(idx);
    }
    strip_patterns(&s).trim().trim_end_matches('.').to_string()
}

/// Lowercase and drop one trailing dot (`Api.Example.com.` -> `api.example.com`).
pub fn normalize_subdomain(value: &str) -> String {
    let lower = value.trim().to_lowercase();
    lower.strip_suffix('.').map(str::to_string).unwrap_or(lower)
}

/// Remove `*.`, `/`, bullets and `http(s)://` anywhere in `value`.
pub fn strip_patterns(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    'outer: while !rest.is_empty() {
        for pattern in STRIP_PATTERNS {
            if let Some(after) = rest.strip_prefix(pattern) {
                rest = after;
                continue 'outer;
            }
        }
        let mut chars = rest.chars();
        if let Some(c) = chars.next() {
            out.push(c);
        }
        rest = chars.as_str();
    }
    out
}

/// `true` when `host` only contains characters valid in DNS names
/// (`a-z 0-9 . - _`), has no empty labels, and fits DNS length limits.
///
/// Candidates come from untrusted third parties; this check stops terminal
/// escape sequences, spaces or other junk from reaching the output.
pub fn is_valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
}

/// `true` when `value` looks like an IPv4 address (used by `-exclude-ip`).
pub fn is_ip(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        || value.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preprocesses_input() {
        assert_eq!(preprocess_domain("  Example.COM \n"), "example.com");
        assert_eq!(
            preprocess_domain("https://example.com/path?q#f"),
            "example.com"
        );
        assert_eq!(preprocess_domain("http://example.com"), "example.com");
        assert_eq!(preprocess_domain("\"example.com\""), "example.com");
        assert_eq!(preprocess_domain("*.example.com"), "example.com");
        assert_eq!(preprocess_domain("• example.com"), "example.com");
        assert_eq!(preprocess_domain("example.com # comment"), "example.com");
        assert_eq!(preprocess_domain("# only comment"), "");
        assert_eq!(preprocess_domain("example.com."), "example.com");
    }

    #[test]
    fn normalizes_subdomains() {
        assert_eq!(normalize_subdomain("API.Example.com."), "api.example.com");
        assert_eq!(normalize_subdomain("a.example.com"), "a.example.com");
    }

    #[test]
    fn strips_patterns() {
        assert_eq!(strip_patterns("*.api.example.com"), "api.example.com");
        assert_eq!(
            strip_patterns("https://api.example.com/"),
            "api.example.com"
        );
        assert_eq!(strip_patterns("•.api.example.com"), "api.example.com");
        assert_eq!(strip_patterns("a/b.example.com"), "ab.example.com");
    }

    #[test]
    fn validates_hostnames() {
        assert!(is_valid_hostname("a-b_c.example.com"));
        assert!(!is_valid_hostname("a..example.com"));
        assert!(!is_valid_hostname("a b.example.com"));
        assert!(!is_valid_hostname("\x1b[31ma.example.com"));
        assert!(!is_valid_hostname("ünï.example.com"));
        assert!(!is_valid_hostname(&format!(
            "{}.example.com",
            "a".repeat(64)
        )));
    }

    #[test]
    fn detects_ips() {
        assert!(is_ip("1.2.3.4"));
        assert!(is_ip("2001:db8::1"));
        assert!(!is_ip("example.com"));
    }
}
