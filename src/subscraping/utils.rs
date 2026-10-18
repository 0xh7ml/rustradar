//! Small helpers shared by sources.

use rand::seq::SliceRandom;

/// Pick a random element, or `None` when the slice is empty.
///
/// Sources call this once per run so that several configured keys spread the
/// request quota between them.
pub fn pick_random<T>(items: &[T]) -> Option<&T> {
    items.choose(&mut rand::thread_rng())
}

/// Split a `left:right` key (e.g. `user:secret`). Returns `None` unless the
/// key has exactly two non-empty parts, matching subfinder's behaviour.
pub fn split_key_pair(key: &str) -> Option<(String, String)> {
    let mut parts = key.split(':');
    let (a, b) = (parts.next()?, parts.next()?);
    if parts.next().is_some() || a.is_empty() || b.is_empty() {
        return None;
    }
    Some((a.to_string(), b.to_string()))
}

/// Strip an `http://` / `https://` scheme and any `:port` / path from a host or
/// URL string, returning just the hostname.
pub fn host_of(value: &str) -> String {
    let value = value.trim();
    let without_scheme = match value.find("://") {
        Some(idx) => &value[idx + 3..],
        None => value,
    };
    let host = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    // Drop credentials and port.
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = match host.rfind(':') {
        Some(idx) if host[idx + 1..].chars().all(|c| c.is_ascii_digit()) => &host[..idx],
        _ => host,
    };
    host.to_string()
}

/// Percent-decode a string (invalid sequences are kept as-is).
pub fn url_decode(value: &str) -> String {
    percent_encoding::percent_decode_str(value)
        .decode_utf8_lossy()
        .into_owned()
}

/// Percent-encode a query component.
pub fn url_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// Current calendar year (UTC), computed without a date library.
pub fn current_year() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    civil_year(secs.div_euclid(86_400))
}

/// Year of the civil date `days` after 1970-01-01 (Howard Hinnant's algorithm).
fn civil_year(days: i64) -> i64 {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    yoe + era * 400 + i64::from(month <= 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_pairs() {
        assert_eq!(split_key_pair("a:b"), Some(("a".into(), "b".into())));
        assert_eq!(split_key_pair("ab"), None);
        assert_eq!(split_key_pair("a:b:c"), None);
        assert_eq!(split_key_pair(":b"), None);
    }

    #[test]
    fn hosts() {
        assert_eq!(host_of("https://a.example.com:8443/x?y"), "a.example.com");
        assert_eq!(host_of("a.example.com:80"), "a.example.com");
        assert_eq!(host_of("http://user:pw@a.example.com/"), "a.example.com");
        assert_eq!(host_of("a.example.com"), "a.example.com");
    }

    #[test]
    fn years() {
        assert_eq!(civil_year(0), 1970);
        assert_eq!(civil_year(19_723), 2024); // 2024-01-01
        assert_eq!(civil_year(19_722), 2023); // 2023-12-31
        assert!(current_year() >= 2024);
    }
}
