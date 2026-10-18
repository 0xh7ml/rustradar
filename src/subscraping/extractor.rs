//! Boundary-safe subdomain extraction from arbitrary text.
//!
//! Providers return JSON, HTML, CSV or plain text. Rather than trusting every
//! schema, many sources run the raw body through an [`Extractor`], which finds
//! every `<label>.<domain>` occurrence.
//!
//! A plain regex is not enough: `api.example.com.attacker.org` contains
//! `api.example.com`, and a naive match would report an attacker-controlled
//! name as a subdomain of the target. [`Extractor::extract`] drops any match
//! that the text continues past (another label character, or a dot followed by
//! a label start), which closes this cross-apex spoofing hole.

use regex::Regex;

/// Extracts candidate subdomains of a single apex domain from text.
#[derive(Debug, Clone)]
pub struct Extractor {
    regex: Regex,
}

impl Extractor {
    /// Build an extractor for `domain`. The domain is regex-escaped, so
    /// `example.com` never matches `exampleXcom`.
    pub fn new(domain: &str) -> Result<Self, regex::Error> {
        let pattern = format!(r"(?i)[a-zA-Z0-9\*_.\-]+\.{}", regex::escape(domain));
        Ok(Self {
            regex: Regex::new(&pattern)?,
        })
    }

    /// Return every lowercase candidate found in `text`, in order of
    /// appearance. Duplicates are kept; the runner deduplicates.
    pub fn extract(&self, text: &str) -> Vec<String> {
        self.regex
            .find_iter(text)
            .filter(|m| !hostname_continues(text.as_bytes(), m.end()))
            .map(|m| m.as_str().to_ascii_lowercase())
            .collect()
    }
}

/// `true` when the hostname that ends at byte `end` actually keeps going, i.e.
/// the match is only a prefix of a longer (different) domain.
fn hostname_continues(text: &[u8], end: usize) -> bool {
    match text.get(end) {
        None => false,
        Some(&b) if is_label_byte(b) => true,
        Some(b'.') => text.get(end + 1).is_some_and(|&next| is_label_start(next)),
        Some(_) => false,
    }
}

fn is_label_byte(b: u8) -> bool {
    is_label_start(b) || b == b'-' || b == b'_'
}

fn is_label_start(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ex(text: &str) -> Vec<String> {
        Extractor::new("example.com").unwrap().extract(text)
    }

    #[test]
    fn extracts_simple_subdomains() {
        assert_eq!(
            ex("found api.example.com and WWW.Example.COM here"),
            vec!["api.example.com", "www.example.com"]
        );
    }

    #[test]
    fn extracts_from_json_and_csv() {
        assert_eq!(
            ex(r#"{"host":"a.example.com"},b.example.com,1.2.3.4"#),
            vec!["a.example.com", "b.example.com"]
        );
    }

    #[test]
    fn rejects_cross_apex_spoofing() {
        assert!(ex("api.example.com.attacker.org").is_empty());
        assert!(ex("api.example.community").is_empty());
        assert!(ex("api.example.com-evil.org").is_empty());
    }

    #[test]
    fn allows_trailing_dot_and_punctuation() {
        assert_eq!(ex("api.example.com."), vec!["api.example.com"]);
        assert_eq!(ex("(api.example.com)"), vec!["api.example.com"]);
        assert_eq!(ex("api.example.com/path"), vec!["api.example.com"]);
        assert_eq!(ex("api.example.com:8443"), vec!["api.example.com"]);
    }

    #[test]
    fn dot_in_domain_is_literal() {
        assert!(ex("api.exampleXcom").is_empty());
    }

    #[test]
    fn keeps_wildcard_prefix_for_runner() {
        assert_eq!(ex("*.api.example.com"), vec!["*.api.example.com"]);
    }

    #[test]
    fn apex_alone_is_not_matched() {
        assert!(ex("example.com").is_empty());
    }
}
