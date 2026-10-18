//! Per-source statistics table (`-stats`).

use std::collections::BTreeMap;
use std::time::Duration;

use crate::subscraping::Statistics;

/// Render the statistics table printed by `-stats`.
pub fn render_statistics(stats: &BTreeMap<String, Statistics>) -> String {
    let mut out = String::new();
    let (skipped, ran): (Vec<_>, Vec<_>) = stats.iter().partition(|(_, s)| s.skipped);

    if !ran.is_empty() {
        out.push_str(&format!(
            "\n {:<20} {:<10} {:>10} {:>10} {:>10}\n{}\n",
            "Source",
            "Duration",
            "Results",
            "Requests",
            "Errors",
            "─".repeat(68)
        ));
        for (name, s) in ran {
            out.push_str(&format!(
                " {:<20} {:<10} {:>10} {:>10} {:>10}\n",
                name,
                format_duration(s.time_taken),
                s.results,
                s.requests,
                s.errors
            ));
        }
    }

    if !skipped.is_empty() {
        out.push_str("\n The following sources were included but skipped (no API key)...\n\n");
        for (name, _) in skipped {
            out.push_str(&format!(" {name}\n"));
        }
    }
    out
}

/// Short human-readable duration (`850ms`, `12.3s`, `2m5s`).
pub fn format_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms < 1_000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", d.as_secs_f64())
    } else {
        format!("{}m{}s", d.as_secs() / 60, d.as_secs() % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(format_duration(Duration::from_millis(850)), "850ms");
        assert_eq!(format_duration(Duration::from_millis(12_340)), "12.3s");
        assert_eq!(format_duration(Duration::from_secs(125)), "2m5s");
    }

    #[test]
    fn table() {
        let mut stats = BTreeMap::new();
        stats.insert(
            "crtsh".to_string(),
            Statistics {
                results: 10,
                requests: 1,
                ..Default::default()
            },
        );
        stats.insert(
            "shodan".to_string(),
            Statistics {
                skipped: true,
                ..Default::default()
            },
        );
        let out = render_statistics(&stats);
        assert!(out.contains("crtsh"));
        assert!(out.contains("skipped"));
        assert!(out.contains(" shodan\n"));
    }
}
