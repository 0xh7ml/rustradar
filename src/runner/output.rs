//! Result formatting: plain text or JSON Lines, with optional IPs or sources.
//!
//! | Mode                  | Plain line             | JSON object keys                         |
//! |-----------------------|------------------------|------------------------------------------|
//! | default               | `host`                 | `host, input, source`                    |
//! | `-cs`                 | `host,[src1,src2]`     | `host, input, sources`                   |
//! | `-nW -oI`             | `host,ip,source`       | `host, ip, input, source`                |
//!
//! `wildcard_certificate: true` is added to JSON objects when a source
//! reported the host as `*.host`. Hosts are written in sorted order.

use serde::Serialize;

use super::enumerate::DomainResults;
use super::Options;

/// Chooses the output format and renders [`DomainResults`].
#[derive(Debug, Clone, Copy, Default)]
pub struct OutputWriter {
    /// JSON Lines instead of plain text.
    pub json: bool,
    /// Include resolved IPs (only meaningful with active resolution).
    pub host_ip: bool,
    /// Include every source that reported each host.
    pub collect_sources: bool,
}

#[derive(Serialize)]
struct JsonHost<'a> {
    host: &'a str,
    input: &'a str,
    source: &'a str,
    #[serde(skip_serializing_if = "is_false")]
    wildcard_certificate: bool,
}

#[derive(Serialize)]
struct JsonHostIp<'a> {
    host: &'a str,
    ip: &'a str,
    input: &'a str,
    source: &'a str,
    #[serde(skip_serializing_if = "is_false")]
    wildcard_certificate: bool,
}

#[derive(Serialize)]
struct JsonSources<'a> {
    host: &'a str,
    input: &'a str,
    sources: Vec<&'a str>,
    #[serde(skip_serializing_if = "is_false")]
    wildcard_certificate: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl OutputWriter {
    /// Build from CLI options.
    pub fn from_options(options: &Options) -> Self {
        Self {
            json: options.json,
            host_ip: options.ip && options.active,
            collect_sources: options.collect_sources,
        }
    }

    /// File extension for per-domain output files (`-oD`).
    pub fn extension(&self) -> &'static str {
        if self.json {
            "json"
        } else {
            "txt"
        }
    }

    /// Render all results for one domain, one line per host, each line ending
    /// in `\n`.
    pub fn render(&self, results: &DomainResults) -> String {
        let mut out = String::new();
        let input = results.domain.as_str();

        if let (true, Some(resolved)) = (self.host_ip, &results.resolved) {
            for r in resolved.values() {
                if self.json {
                    push_json(
                        &mut out,
                        &JsonHostIp {
                            host: &r.host,
                            ip: &r.ip,
                            input,
                            source: &r.source,
                            wildcard_certificate: r.wildcard_certificate,
                        },
                    );
                } else {
                    out.push_str(&format!("{},{},{}\n", r.host, r.ip, r.source));
                }
            }
            return out;
        }

        for host in results.hosts() {
            let entry = results.entry(host);
            let source = entry.map(|e| e.source.as_str()).unwrap_or_default();
            let wildcard = entry.is_some_and(|e| e.wildcard_certificate);
            if self.collect_sources {
                let sources: Vec<&str> = results
                    .sources
                    .get(host)
                    .map(|s| s.iter().map(String::as_str).collect())
                    .unwrap_or_default();
                if self.json {
                    push_json(
                        &mut out,
                        &JsonSources {
                            host,
                            input,
                            sources,
                            wildcard_certificate: wildcard,
                        },
                    );
                } else {
                    out.push_str(&format!("{host},[{}]\n", sources.join(",")));
                }
            } else if self.json {
                push_json(
                    &mut out,
                    &JsonHost {
                        host,
                        input,
                        source,
                        wildcard_certificate: wildcard,
                    },
                );
            } else {
                out.push_str(host);
                out.push('\n');
            }
        }
        out
    }
}

fn push_json<T: Serialize>(out: &mut String, value: &T) {
    if let Ok(line) = serde_json::to_string(value) {
        out.push_str(&line);
        out.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::{HostEntry, Resolved};
    use std::collections::{BTreeMap, BTreeSet};

    fn sample(active: bool) -> DomainResults {
        let mut hosts = BTreeMap::new();
        let mut sources = BTreeMap::new();
        for (h, s, w) in [
            ("b.example.com", "crtsh", true),
            ("a.example.com", "anubis", false),
        ] {
            hosts.insert(
                h.to_string(),
                HostEntry {
                    domain: "example.com".into(),
                    host: h.into(),
                    source: s.into(),
                    wildcard_certificate: w,
                },
            );
            sources.insert(
                h.to_string(),
                BTreeSet::from([s.to_string(), "zz".to_string()]),
            );
        }
        let resolved = active.then(|| {
            BTreeMap::from([(
                "a.example.com".to_string(),
                Resolved {
                    host: "a.example.com".into(),
                    ip: "1.2.3.4".into(),
                    source: "anubis".into(),
                    wildcard_certificate: false,
                },
            )])
        });
        DomainResults {
            domain: "example.com".into(),
            hosts,
            sources,
            resolved,
            elapsed: Default::default(),
        }
    }

    #[test]
    fn plain_sorted() {
        let out = OutputWriter::default().render(&sample(false));
        assert_eq!(out, "a.example.com\nb.example.com\n");
    }

    #[test]
    fn json_lines() {
        let w = OutputWriter {
            json: true,
            ..Default::default()
        };
        let out = w.render(&sample(false));
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines[0],
            r#"{"host":"a.example.com","input":"example.com","source":"anubis"}"#
        );
        assert_eq!(
            lines[1],
            r#"{"host":"b.example.com","input":"example.com","source":"crtsh","wildcard_certificate":true}"#
        );
    }

    #[test]
    fn collect_sources() {
        let out = OutputWriter {
            collect_sources: true,
            ..Default::default()
        }
        .render(&sample(false));
        assert_eq!(out, "a.example.com,[anubis,zz]\nb.example.com,[crtsh,zz]\n");
        let out = OutputWriter {
            collect_sources: true,
            json: true,
            ..Default::default()
        }
        .render(&sample(false));
        assert!(out.starts_with(
            r#"{"host":"a.example.com","input":"example.com","sources":["anubis","zz"]}"#
        ));
    }

    #[test]
    fn active_modes() {
        let out = OutputWriter::default().render(&sample(true));
        assert_eq!(out, "a.example.com\n");
        let out = OutputWriter {
            host_ip: true,
            ..Default::default()
        }
        .render(&sample(true));
        assert_eq!(out, "a.example.com,1.2.3.4,anubis\n");
        let out = OutputWriter {
            host_ip: true,
            json: true,
            ..Default::default()
        }
        .render(&sample(true));
        assert_eq!(
            out.trim(),
            r#"{"host":"a.example.com","ip":"1.2.3.4","input":"example.com","source":"anubis"}"#
        );
    }
}
