//! Leveled stderr logger (the Rust counterpart of `gologger`).
//!
//! * All log lines go to **stderr**, so stdout carries only results and stays
//!   safe to pipe into other tools.
//! * Levels are ordered `Fatal < Error < Warning < Info < Debug < Verbose`.
//!   `--silent` keeps only `Fatal`; `--verbose` enables everything.
//! * Every API key loaded from config is registered with [`register_secret`]
//!   and scrubbed from log output, so keys that appear in request URLs never
//!   reach the terminal or log files.
//!
//! Use the exported macros: [`info!`](crate::info), [`warn!`](crate::warn),
//! [`error!`](crate::error), [`debug!`](crate::debug),
//! [`verbose!`](crate::verbose) and [`fatal!`](crate::fatal).

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::RwLock;

/// Log severity. Lower values are more important.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    /// Unrecoverable error; the process exits after logging it.
    Fatal = 0,
    /// An operation failed.
    Error = 1,
    /// Something went wrong but the run continues (e.g. a source failed).
    Warning = 2,
    /// Normal progress messages.
    Info = 3,
    /// Diagnostic details for troubleshooting.
    Debug = 4,
    /// Per-result discovery events (`[source] host`).
    Verbose = 5,
}

static MAX_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static COLOR: AtomicBool = AtomicBool::new(true);
static SECRETS: RwLock<Vec<String>> = RwLock::new(Vec::new());

/// Configure the global logger.
///
/// `color` is ignored (treated as `false`) when stderr is not a terminal.
pub fn init(max_level: Level, color: bool) {
    MAX_LEVEL.store(max_level as u8, Ordering::Relaxed);
    COLOR.store(color && std::io::stderr().is_terminal(), Ordering::Relaxed);
}

/// Returns `true` when messages at `level` would be printed.
pub fn enabled(level: Level) -> bool {
    level as u8 <= MAX_LEVEL.load(Ordering::Relaxed)
}

/// Register a secret (API key, token, password) to be masked in all log output.
/// Very short values are ignored to avoid masking ordinary words.
pub fn register_secret(secret: &str) {
    let secret = secret.trim();
    if secret.len() < 6 {
        return;
    }
    if let Ok(mut secrets) = SECRETS.write() {
        if !secrets.iter().any(|s| s == secret) {
            secrets.push(secret.to_string());
            // Longest first so a key that contains another key is fully masked.
            secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        }
    }
}

/// Replace every registered secret in `text` with `[REDACTED]`.
pub fn redact(text: &str) -> String {
    let Ok(secrets) = SECRETS.read() else {
        return text.to_string();
    };
    let mut out = text.to_string();
    for secret in secrets.iter() {
        if out.contains(secret.as_str()) {
            out = out.replace(secret.as_str(), "[REDACTED]");
        }
    }
    out
}

fn paint(code: &str, text: &str) -> String {
    if COLOR.load(Ordering::Relaxed) {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// Write a log line. Prefer the macros over calling this directly.
pub fn log(level: Level, label: Option<&str>, message: &str) {
    if !enabled(level) {
        return;
    }
    let tag = match (level, label) {
        (_, Some(label)) => paint("1;36", label),
        (Level::Fatal, _) => paint("1;35", "FTL"),
        (Level::Error, _) => paint("1;31", "ERR"),
        (Level::Warning, _) => paint("1;33", "WRN"),
        (Level::Info, _) => paint("1;34", "INF"),
        (Level::Debug, _) => paint("1;35", "DBG"),
        (Level::Verbose, _) => paint("1;37", "VER"),
    };
    let message = redact(message.trim_end());
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "[{tag}] {message}");
}

/// Write raw text to stderr unless the logger is silenced (used for the banner
/// and the statistics table).
pub fn print(message: &str) {
    if MAX_LEVEL.load(Ordering::Relaxed) == Level::Fatal as u8 {
        return;
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{}", redact(message));
}

/// Log at `Info` level.
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => { $crate::logger::log($crate::logger::Level::Info, None, &format!($($arg)*)) };
}

/// Log at `Warning` level.
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => { $crate::logger::log($crate::logger::Level::Warning, None, &format!($($arg)*)) };
}

/// Log at `Error` level.
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => { $crate::logger::log($crate::logger::Level::Error, None, &format!($($arg)*)) };
}

/// Log at `Debug` level.
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => { $crate::logger::log($crate::logger::Level::Debug, None, &format!($($arg)*)) };
}

/// Log at `Verbose` level with a custom label, e.g. `verbose!("crtsh", "{host}")`.
#[macro_export]
macro_rules! verbose {
    ($label:expr, $($arg:tt)*) => { $crate::logger::log($crate::logger::Level::Verbose, Some($label), &format!($($arg)*)) };
}

/// Log at `Fatal` level and exit the process with status 1.
#[macro_export]
macro_rules! fatal {
    ($($arg:tt)*) => {{
        $crate::logger::log($crate::logger::Level::Fatal, None, &format!($($arg)*));
        ::std::process::exit(1)
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_registered_secrets() {
        register_secret("super-secret-token-123");
        let out = redact("GET https://api.example/?key=super-secret-token-123 failed");
        assert_eq!(out, "GET https://api.example/?key=[REDACTED] failed");
    }

    #[test]
    fn ignores_short_secrets() {
        register_secret("abc");
        assert_eq!(redact("abc"), "abc");
    }
}
