//! Tests that run the compiled `rustradar` binary (no network access needed).

use std::process::{Command, Output, Stdio};

fn rustradar(args: &[&str], config_home: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rustradar"))
        .args(args)
        .env("XDG_CONFIG_HOME", config_home)
        .env("HOME", config_home)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .output()
        .expect("failed to run rustradar")
}

#[test]
fn lists_sources_as_text() {
    let home = tempfile::tempdir().unwrap();
    let out = rustradar(&["-ls"], home.path());
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("[54]"), "{stdout}");
    assert!(stdout.contains("crtsh\n"));
    assert!(stdout.contains("shodan *\n"));
    assert!(stdout.contains("waybackarchive ~\n"));
}

#[test]
fn lists_sources_as_json() {
    let home = tempfile::tempdir().unwrap();
    let out = rustradar(&["-ls", "-oJ"], home.path());
    assert!(out.status.success());
    let sources: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let list = sources.as_array().unwrap();
    assert_eq!(list.len(), 54);
    assert!(list
        .iter()
        .any(|s| s["name"] == "virustotal" && s["key"] == "required" && s["recursive"] == true));
}

#[test]
fn prints_version() {
    let home = tempfile::tempdir().unwrap();
    let out = rustradar(&["-version"], home.path());
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn rejects_ip_output_without_active_mode() {
    let home = tempfile::tempdir().unwrap();
    let out = rustradar(&["-d", "example.com", "-oI"], home.path());
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("-nW"));
}

#[test]
fn rejects_unknown_rate_limit_source() {
    let home = tempfile::tempdir().unwrap();
    let out = rustradar(&["-d", "example.com", "-rls", "nosuch=1/s"], home.path());
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("nosuch"));
}

#[test]
fn creates_provider_config_template() {
    let home = tempfile::tempdir().unwrap();
    // Any run that gets past the informational flags creates the template.
    let _ = rustradar(&["-d", "example.com", "-oI"], home.path());
    let path = home.path().join("rustradar/provider-config.yaml");
    let text = std::fs::read_to_string(&path).expect("template not created");
    assert!(text.contains("virustotal: []"));
}

#[test]
fn flag_config_file_is_applied() {
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join("custom.yaml");
    // `ip: true` without `active` must trip validation, proving the file was read.
    std::fs::write(&config, "domain: [example.com]\nip: true\n").unwrap();
    let out = rustradar(&["-config", config.to_str().unwrap()], home.path());
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("-nW"));
}

#[test]
fn missing_explicit_config_is_fatal() {
    let home = tempfile::tempdir().unwrap();
    let out = rustradar(
        &[
            "-config",
            "/nonexistent/rustradar.yaml",
            "-d",
            "example.com",
        ],
        home.path(),
    );
    assert_eq!(out.status.code(), Some(1));
}
