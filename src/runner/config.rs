//! Configuration files and API keys.
//!
//! * **Provider config** (`provider-config.yaml`): API keys per source, as a
//!   YAML map of `source: [key, key, ...]`. A template listing every source
//!   that accepts keys is created on first run.
//! * **Environment variables**: `<SOURCE>_API_KEY` (comma separated for several
//!   keys) is added to the keys from the file, e.g. `SHODAN_API_KEY=...`.
//! * **Flag config** (`config.yaml`): default values for CLI flags, as a YAML
//!   map of long flag names, e.g. `threads: 20` or `sources: [crtsh, github]`.
//!   Flags given on the command line override it.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde_yaml::Value;

use crate::passive::ProviderKeys;
use crate::subscraping::{sources, KeyRequirement};

/// Directory holding rustradar's config files (`$XDG_CONFIG_HOME/rustradar` or
/// the platform equivalent).
pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("rustradar")
}

/// Default flag config path.
pub fn default_config_path() -> PathBuf {
    config_dir().join("config.yaml")
}

/// Default provider config path.
pub fn default_provider_config_path() -> PathBuf {
    config_dir().join("provider-config.yaml")
}

/// Load API keys from `path` (if it exists) and from `<SOURCE>_API_KEY`
/// environment variables. Every key is registered for log redaction.
pub fn load_provider_keys(path: &Path) -> anyhow::Result<ProviderKeys> {
    let mut keys = if path.exists() {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?;
        parse_provider_config(&text)
            .with_context(|| format!("invalid provider config {}", path.display()))?
    } else {
        ProviderKeys::new()
    };

    for source in sources::all() {
        if source.key_requirement() == KeyRequirement::None {
            continue;
        }
        let var = format!("{}_API_KEY", source.name().to_uppercase());
        if let Ok(value) = std::env::var(&var) {
            let entry = keys.entry(source.name().to_string()).or_default();
            for key in value.split(',').map(str::trim).filter(|k| !k.is_empty()) {
                if !entry.iter().any(|k| k == key) {
                    entry.push(key.to_string());
                }
            }
        }
    }

    for list in keys.values() {
        for key in list {
            crate::logger::register_secret(key);
            // Also mask each half of multi-part keys (user:secret).
            for part in key.split(':') {
                crate::logger::register_secret(part);
            }
        }
    }
    Ok(keys)
}

/// Parse provider config YAML. Values may be a list or a single string;
/// empty entries are dropped and names are lowercased.
pub fn parse_provider_config(text: &str) -> anyhow::Result<ProviderKeys> {
    let mut keys = ProviderKeys::new();
    if text.trim().is_empty() {
        return Ok(keys);
    }
    let map: BTreeMap<String, Value> = serde_yaml::from_str(text)?;
    for (name, value) in map {
        let list: Vec<String> = match value {
            Value::Sequence(items) => items.into_iter().filter_map(scalar_to_string).collect(),
            Value::Null => Vec::new(),
            other => scalar_to_string(other).into_iter().collect(),
        };
        let list: Vec<String> = list
            .into_iter()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .collect();
        if !list.is_empty() {
            keys.insert(name.to_lowercase(), list);
        }
    }
    Ok(keys)
}

fn scalar_to_string(value: Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Write a provider config template listing every source that accepts keys.
/// Does nothing if the file already exists. On Unix the file is `chmod 600`.
pub fn create_provider_config_template(path: &Path) -> anyhow::Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("could not create {}", dir.display()))?;
    }
    let mut text = String::from(
        "# rustradar provider configuration\n\
         # Add one or more API keys per source. With several keys, one is picked\n\
         # at random per run to spread quota. Multi-part keys use ':' (see docs/SOURCES.md).\n\
         # Keys can also be set as environment variables: <SOURCE>_API_KEY=key1,key2\n\
         #\n\
         # Example:\n\
         # shodan:\n\
         #   - \"your-shodan-key\"\n\n",
    );
    for source in sources::all() {
        if source.key_requirement() != KeyRequirement::None {
            text.push_str(&format!("{}: []\n", source.name()));
        }
    }
    std::fs::write(path, text).with_context(|| format!("could not write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(true)
}

/// Convert a flag config file into CLI arguments (`--name value`).
///
/// Booleans become bare flags when `true` and are skipped when `false`;
/// lists repeat the flag; `null` is skipped.
pub fn flag_config_args(path: &Path) -> anyhow::Result<Vec<OsString>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("could not read {}", path.display()))?;
    parse_flag_config(&text).with_context(|| format!("invalid config file {}", path.display()))
}

/// See [`flag_config_args`].
pub fn parse_flag_config(text: &str) -> anyhow::Result<Vec<OsString>> {
    let mut args = Vec::new();
    if text.trim().is_empty() {
        return Ok(args);
    }
    let map: BTreeMap<String, Value> = serde_yaml::from_str(text)?;
    for (name, value) in map {
        let flag = format!("--{}", name.trim_start_matches('-'));
        match value {
            Value::Bool(true) => args.push(OsString::from(flag)),
            Value::Bool(false) | Value::Null => {}
            Value::Sequence(items) => {
                for item in items.into_iter().filter_map(scalar_to_string) {
                    args.push(OsString::from(format!("{flag}={item}")));
                }
            }
            other => {
                let value = scalar_to_string(other)
                    .with_context(|| format!("unsupported value for {name}"))?;
                args.push(OsString::from(format!("{flag}={value}")));
            }
        }
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_provider_config() {
        let keys = parse_provider_config(
            "shodan:\n  - k1\n  - k2\nGitHub: single\nempty: []\nnothing:\ncensys:\n  - ''\n",
        )
        .unwrap();
        assert_eq!(keys["shodan"], vec!["k1", "k2"]);
        assert_eq!(keys["github"], vec!["single"]);
        assert!(!keys.contains_key("empty"));
        assert!(!keys.contains_key("nothing"));
        assert!(!keys.contains_key("censys"));
    }

    #[test]
    fn empty_provider_config() {
        assert!(parse_provider_config("").unwrap().is_empty());
        assert!(parse_provider_config("# only comments\n")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn flag_config_to_args() {
        let args = parse_flag_config(
            "threads: 20\nsilent: true\nverbose: false\nsources: [crtsh, github]\n",
        )
        .unwrap();
        let args: Vec<String> = args.into_iter().map(|a| a.into_string().unwrap()).collect();
        assert_eq!(
            args,
            vec![
                "--silent",
                "--sources=crtsh",
                "--sources=github",
                "--threads=20"
            ]
        );
    }

    #[test]
    fn template_is_valid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/provider-config.yaml");
        assert!(create_provider_config_template(&path).unwrap());
        assert!(!create_provider_config_template(&path).unwrap());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("shodan: []"));
        assert!(parse_provider_config(&text).unwrap().is_empty());
    }
}
