//! Update check and self-update (`-up`), backed by GitHub releases.
//!
//! Every release (built by `.github/workflows/release.yml`) publishes one
//! archive per target, named `rustradar-vX.Y.Z-<target>.tar.gz` (`.zip` on
//! Windows), plus a `SHA256SUMS` file. `-up` downloads the archive for the
//! running platform, checks it against `SHA256SUMS`, and swaps the running
//! binary in place.
//!
//! This uses its own HTTP client with normal TLS certificate checks, not the
//! source client (which accepts invalid certificates).

use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context as _};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{debug, info, VERSION};

/// GitHub `owner/name` that publishes rustradar releases.
pub const REPOSITORY: &str = "0xh7ml/rustradar";

/// Name of the binary inside a release archive.
const BIN_NAME: &str = if cfg!(windows) {
    "rustradar.exe"
} else {
    "rustradar"
};

/// Upper bound for any download (archive, checksums, extracted binary).
const MAX_DOWNLOAD: u64 = 64 * 1024 * 1024;

/// The fields of a GitHub release that the updater uses.
#[derive(Debug, Deserialize)]
pub struct Release {
    pub tag_name: String,
    #[serde(default)]
    pub assets: Vec<Asset>,
}

/// One downloadable file of a release.
#[derive(Debug, Deserialize)]
pub struct Asset {
    pub name: String,
    pub browser_download_url: String,
}

/// The release target to download for this build.
pub fn current_target() -> String {
    release_target(env!("RUSTRADAR_TARGET"))
}

/// Map a build target to a published release target. Linux releases are
/// static musl binaries, which also run on glibc systems.
fn release_target(build_target: &str) -> String {
    if build_target.contains("-linux-") {
        build_target.replace("-gnu", "-musl")
    } else {
        build_target.to_string()
    }
}

/// Archive name for a release tag (`v1.2.3`) and target.
pub fn archive_name(tag: &str, target: &str) -> String {
    let ext = if target.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    format!("rustradar-{tag}-{target}.{ext}")
}

/// Parse `v1.2.3`, `1.2.3` or `1.2.3-rc.1` into a comparable key. The last
/// element is `true` for a final release, so `1.2.3 > 1.2.3-rc.1`.
fn version_key(version: &str) -> Option<(u64, u64, u64, bool)> {
    let version = version.trim().trim_start_matches('v');
    let version = version.split('+').next()?;
    let (core, final_release) = match version.split_once('-') {
        Some((core, _)) => (core, false),
        None => (version, true),
    };
    let mut parts = core.split('.').map(str::parse::<u64>);
    let major = parts.next()?.ok()?;
    let minor = parts.next()?.ok()?;
    let patch = parts.next()?.ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch, final_release))
}

/// `true` when `latest` is a strictly newer version than `current`.
pub fn is_newer(latest: &str, current: &str) -> bool {
    match (version_key(latest), version_key(current)) {
        (Some(latest), Some(current)) => latest > current,
        _ => false,
    }
}

fn http_client(proxy: Option<&str>, timeout: Duration) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .user_agent(format!("rustradar/{VERSION}"))
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .timeout(timeout);
    if let Some(proxy) = proxy.filter(|p| !p.is_empty()) {
        let proxy =
            reqwest::Proxy::all(proxy).with_context(|| format!("invalid proxy URL {proxy}"))?;
        builder = builder.proxy(proxy);
    }
    builder.build().context("could not build HTTP client")
}

/// Fetch the latest published (non-prerelease) release. `GITHUB_TOKEN`, when
/// set, is sent to avoid the anonymous API rate limit.
pub async fn latest_release(client: &reqwest::Client) -> anyhow::Result<Release> {
    let url = format!("https://api.github.com/repos/{REPOSITORY}/releases/latest");
    let mut request = client
        .get(&url)
        .header("Accept", "application/vnd.github+json");
    if let Some(token) = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty()) {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.context("could not reach GitHub")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        bail!("no published release found for github.com/{REPOSITORY}");
    }
    let response = response
        .error_for_status()
        .context("GitHub API request failed")?;
    response
        .json()
        .await
        .context("invalid GitHub release response")
}

async fn download(client: &reqwest::Client, url: &str) -> anyhow::Result<Vec<u8>> {
    let mut response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("could not download {url}"))?
        .error_for_status()
        .with_context(|| format!("could not download {url}"))?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.context("download interrupted")? {
        body.extend_from_slice(&chunk);
        if body.len() as u64 > MAX_DOWNLOAD {
            bail!("download from {url} is larger than {MAX_DOWNLOAD} bytes");
        }
    }
    Ok(body)
}

/// Find the hash for `file` in `sha256sum`-style output.
fn expected_checksum(sums: &str, file: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let hash = fields.next()?;
        let name = fields.next()?.trim_start_matches('*');
        (name == file).then(|| hash.to_ascii_lowercase())
    })
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Read the rustradar binary out of a release archive, in memory. Nothing is
/// written to paths taken from the archive.
fn extract_binary(archive: &[u8], archive_name: &str) -> anyhow::Result<Vec<u8>> {
    if archive_name.ends_with(".zip") {
        extract_zip(archive)
    } else {
        extract_tar_gz(archive)
    }
}

fn extract_tar_gz(archive: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    for entry in tar.entries().context("invalid release archive")? {
        let mut entry = entry.context("invalid release archive")?;
        let is_binary = entry.header().entry_type().is_file()
            && entry
                .path()
                .ok()
                .and_then(|p| p.file_name().map(|n| n == BIN_NAME))
                .unwrap_or(false);
        if is_binary {
            return read_capped(&mut entry);
        }
    }
    bail!("{BIN_NAME} not found in the release archive")
}

#[cfg(windows)]
fn extract_zip(archive: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut zip =
        zip::ZipArchive::new(std::io::Cursor::new(archive)).context("invalid release archive")?;
    for i in 0..zip.len() {
        let mut file = zip.by_index(i).context("invalid release archive")?;
        let is_binary = file.is_file()
            && std::path::Path::new(file.name())
                .file_name()
                .is_some_and(|n| n == BIN_NAME);
        if is_binary {
            return read_capped(&mut file);
        }
    }
    bail!("{BIN_NAME} not found in the release archive")
}

#[cfg(not(windows))]
fn extract_zip(_archive: &[u8]) -> anyhow::Result<Vec<u8>> {
    bail!("zip release archives are only used on Windows")
}

fn read_capped(reader: &mut impl Read) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    reader
        .take(MAX_DOWNLOAD + 1)
        .read_to_end(&mut out)
        .context("could not read binary from the release archive")?;
    if out.len() as u64 > MAX_DOWNLOAD {
        bail!("binary in the release archive is larger than {MAX_DOWNLOAD} bytes");
    }
    Ok(out)
}

/// Replace the running executable with `binary`. Returns its path.
fn install(binary: &[u8]) -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe().context("could not locate the running executable")?;
    let exe = exe.canonicalize().unwrap_or(exe);

    let staged = std::env::temp_dir().join(format!(".rustradar-update-{}", std::process::id()));
    std::fs::write(&staged, binary)
        .with_context(|| format!("could not write {}", staged.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
    }

    let result = self_replace::self_replace(&staged);
    let _ = std::fs::remove_file(&staged);
    result.with_context(|| {
        format!(
            "could not replace {} (if it is in a system directory, run the update with sudo)",
            exe.display()
        )
    })?;
    Ok(exe)
}

/// `-up`: install the latest release if it is newer than this binary.
pub async fn self_update(proxy: Option<&str>) -> anyhow::Result<()> {
    info!("Current rustradar version v{VERSION}");
    let api = http_client(proxy, Duration::from_secs(15))?;
    let release = latest_release(&api).await?;
    if !is_newer(&release.tag_name, VERSION) {
        info!("rustradar is already the latest version (v{VERSION})");
        return Ok(());
    }

    let target = current_target();
    let name = archive_name(&release.tag_name, &target);
    let archive_asset = release
        .assets
        .iter()
        .find(|a| a.name == name)
        .with_context(|| {
            format!(
                "release {} has no build for {target} (expected {name})",
                release.tag_name
            )
        })?;
    let sums_asset = release
        .assets
        .iter()
        .find(|a| a.name == "SHA256SUMS")
        .context("release has no SHA256SUMS file; refusing to install an unverified binary")?;

    let downloads = http_client(proxy, Duration::from_secs(300))?;
    info!("Downloading {name}");
    let archive = download(&downloads, &archive_asset.browser_download_url).await?;
    let sums = download(&downloads, &sums_asset.browser_download_url).await?;
    let sums = String::from_utf8_lossy(&sums);

    let expected = expected_checksum(&sums, &name)
        .with_context(|| format!("SHA256SUMS has no entry for {name}"))?;
    let actual = sha256_hex(&archive);
    if expected != actual {
        bail!("checksum mismatch for {name}: expected {expected}, got {actual}");
    }

    let binary = extract_binary(&archive, &name)?;
    let path = install(&binary)?;
    info!(
        "Updated rustradar v{VERSION} -> {} ({})",
        release.tag_name,
        path.display()
    );
    Ok(())
}

/// Startup check: log whether this binary is the latest release, like
/// subfinder's `Current subfinder version vX (latest|outdated)`. Failures are
/// only shown at debug level so offline use stays quiet.
pub async fn report_version_status(proxy: Option<&str>) {
    let latest = async {
        let client = http_client(proxy, Duration::from_secs(5))?;
        latest_release(&client).await
    }
    .await;
    match latest {
        Ok(release) if is_newer(&release.tag_name, VERSION) => info!(
            "Current rustradar version v{VERSION} (outdated, latest is {}). Run `rustradar -up` to update",
            release.tag_name
        ),
        Ok(_) => info!("Current rustradar version v{VERSION} (latest)"),
        Err(err) => debug!("Could not check for updates: {err:#}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_versions() {
        assert!(is_newer("v0.2.0", "0.1.0"));
        assert!(is_newer("v1.0.0", "0.9.9"));
        assert!(is_newer("v0.1.1", "0.1.0"));
        assert!(is_newer("v0.1.0", "0.1.0-rc.1"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("v0.1.0", "0.2.0"));
        assert!(!is_newer("v0.1.0-rc.1", "0.1.0"));
        assert!(!is_newer("garbage", "0.1.0"));
        assert!(!is_newer("v1.2", "0.1.0"));
    }

    #[test]
    fn maps_targets_and_names() {
        assert_eq!(
            release_target("x86_64-unknown-linux-gnu"),
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(
            release_target("aarch64-apple-darwin"),
            "aarch64-apple-darwin"
        );
        assert_eq!(
            archive_name("v1.2.3", "x86_64-unknown-linux-musl"),
            "rustradar-v1.2.3-x86_64-unknown-linux-musl.tar.gz"
        );
        assert_eq!(
            archive_name("v1.2.3", "x86_64-pc-windows-msvc"),
            "rustradar-v1.2.3-x86_64-pc-windows-msvc.zip"
        );
    }

    #[test]
    fn finds_checksums() {
        let sums = "ABC123  rustradar-v1.0.0-a.tar.gz\ndef456 *rustradar-v1.0.0-b.zip\n";
        assert_eq!(
            expected_checksum(sums, "rustradar-v1.0.0-a.tar.gz").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            expected_checksum(sums, "rustradar-v1.0.0-b.zip").as_deref(),
            Some("def456")
        );
        assert_eq!(expected_checksum(sums, "other"), None);
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn extracts_binary_from_tar_gz() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        {
            let mut tar = tar::Builder::new(&mut gz);
            for (path, data) in [("README.md", &b"readme"[..]), (BIN_NAME, &b"binary"[..])] {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o755);
                header.set_cksum();
                tar.append_data(&mut header, path, data).unwrap();
            }
            tar.finish().unwrap();
        }
        let archive = gz.finish().unwrap();
        let binary = extract_binary(&archive, "rustradar-v1.0.0-x.tar.gz").unwrap();
        assert_eq!(binary, b"binary");
        assert!(extract_binary(b"not an archive", "x.tar.gz").is_err());
    }
}
