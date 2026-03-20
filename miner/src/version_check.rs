//! Version checking and auto-update against GitHub releases.
//!
//! Runs a periodic background loop (every 5 minutes) that compares the
//! running binary version against the latest GitHub release. When a newer
//! version is available, downloads the new binary, verifies it, replaces
//! the current binary, and restarts the systemd service.
//!
//! Auto-update can be disabled via `AUTO_UPDATE_DISABLED=true` env var
//! or by placing a `.no-auto-update` file in the miner data directory.
//!
//! Non-blocking — failures are logged and retried next cycle.

use crate::constants::VERSION_CHECK_TIMEOUT_SECS;
use semver::Version;
use std::path::{Path, PathBuf};
use tracing::{debug, error, info};

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const GITHUB_API_URL: &str = "https://api.github.com/repos/thenervelab/arion/releases/latest";
const ASSET_NAME: &str = "miner-linux-x86_64";
const UPDATE_CHECK_INTERVAL_SECS: u64 = 300; // 5 minutes

/// Spawn the periodic auto-update loop. Runs forever in the background.
pub async fn auto_update_loop(data_dir: PathBuf) {
    // Run an initial check immediately at startup.
    run_update_cycle(&data_dir).await;

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(
        UPDATE_CHECK_INTERVAL_SECS,
    ));
    // The first tick fires immediately, but we already ran above — skip it.
    interval.tick().await;

    loop {
        interval.tick().await;
        run_update_cycle(&data_dir).await;
    }
}

/// Single update cycle: check, download, verify, replace, restart.
async fn run_update_cycle(data_dir: &Path) {
    if is_auto_update_disabled(data_dir) {
        debug!("Auto-update is disabled, skipping check");
        return;
    }

    match check_and_update(data_dir).await {
        Ok(updated) => {
            if updated {
                info!("Update applied — restarting miner service");
                if let Err(e) = restart_service() {
                    error!(error = %e, "Failed to restart miner service after update");
                }
            }
        }
        Err(e) => {
            debug!(error = %e, "Update check failed, will retry next cycle");
        }
    }
}

/// Returns true if auto-update is disabled via env var or sentinel file.
fn is_auto_update_disabled(data_dir: &Path) -> bool {
    if std::env::var("AUTO_UPDATE_DISABLED")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false)
    {
        return true;
    }
    data_dir.join(".no-auto-update").exists()
}

/// Check for a newer version and apply the update if available.
/// Returns `Ok(true)` if an update was applied, `Ok(false)` if already up to date.
async fn check_and_update(
    data_dir: &Path,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let current = Version::parse(CURRENT_VERSION)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(VERSION_CHECK_TIMEOUT_SECS))
        .build()?;

    let resp = client
        .get(GITHUB_API_URL)
        .header("User-Agent", "hippius-miner")
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(format!("GitHub API returned {}", resp.status()).into());
    }

    let body: serde_json::Value = resp.json().await?;

    let tag = body["tag_name"].as_str().ok_or("missing tag_name")?;
    let tag_clean = tag.strip_prefix('v').unwrap_or(tag);
    let latest = Version::parse(tag_clean)?;

    if current >= latest {
        info!(version = %current, "Miner is up to date");
        return Ok(false);
    }

    info!(
        current = %current,
        latest = %latest,
        "Newer version available — starting auto-update"
    );

    // Find the download URL for our asset.
    let download_url = find_asset_url(&body)?;

    // Download the new binary to a temp file in the data directory.
    let temp_path = data_dir.join(".miner-update-tmp");
    download_binary(&client, &download_url, &temp_path).await?;

    // Make executable.
    set_executable(&temp_path).await?;

    // Verify the downloaded binary by running --version.
    verify_binary(&temp_path, tag_clean).await?;

    // Replace the current binary: back up old, rename new into place.
    let current_exe = std::env::current_exe()?;
    let backup_path = current_exe.with_extension("bak");

    replace_binary(&current_exe, &backup_path, &temp_path).await?;

    info!(
        new_version = %latest,
        binary = %current_exe.display(),
        backup = %backup_path.display(),
        "Binary replaced successfully"
    );

    Ok(true)
}

/// Find the browser_download_url for the miner asset in the release JSON.
fn find_asset_url(release: &serde_json::Value) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let assets = release["assets"]
        .as_array()
        .ok_or("missing assets array")?;

    for asset in assets {
        if asset["name"].as_str() == Some(ASSET_NAME) {
            let url = asset["browser_download_url"]
                .as_str()
                .ok_or("missing browser_download_url")?;
            return Ok(url.to_string());
        }
    }

    Err(format!("asset '{}' not found in release", ASSET_NAME).into())
}

/// Download a binary from `url` to `dest`.
async fn download_binary(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!(url = url, dest = %dest.display(), "Downloading new binary");

    let resp = client
        .get(url)
        .header("User-Agent", "hippius-miner")
        .timeout(std::time::Duration::from_secs(300))
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(format!("Download failed: HTTP {}", resp.status()).into());
    }

    let bytes = resp.bytes().await?;
    tokio::fs::write(dest, &bytes).await?;

    info!(
        size_bytes = bytes.len(),
        "Download complete"
    );
    Ok(())
}

/// Set the executable bit on a file.
async fn set_executable(path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o755);
    tokio::fs::set_permissions(path, perms).await?;
    Ok(())
}

/// Run the downloaded binary with `--version` and verify the output contains
/// the expected version string.
async fn verify_binary(
    path: &Path,
    expected_version: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!(path = %path.display(), expected = expected_version, "Verifying downloaded binary");

    let output = tokio::process::Command::new(path)
        .arg("--version")
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{} {}", stdout, stderr);

    if !output.status.success() {
        return Err(format!(
            "Binary --version exited with {}: {}",
            output.status, combined
        )
        .into());
    }

    if !combined.contains(expected_version) {
        return Err(format!(
            "Version mismatch: expected '{}' in output: {}",
            expected_version,
            combined.trim()
        )
        .into());
    }

    info!("Binary verification passed");
    Ok(())
}

/// Replace the running binary: rename current → .bak, rename temp → current.
/// On failure, attempts to restore the backup.
async fn replace_binary(
    current: &Path,
    backup: &Path,
    temp: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Remove old backup if it exists.
    if backup.exists() {
        tokio::fs::remove_file(backup).await.ok();
    }

    // Rename current binary to .bak
    if let Err(e) = tokio::fs::rename(current, backup).await {
        return Err(format!(
            "Failed to back up current binary to {}: {}",
            backup.display(),
            e
        )
        .into());
    }

    // Rename temp to current binary path.
    if let Err(e) = tokio::fs::rename(temp, current).await {
        // Try to restore from backup.
        error!(error = %e, "Failed to move new binary into place, restoring backup");
        if let Err(restore_err) = tokio::fs::rename(backup, current).await {
            error!(error = %restore_err, "Failed to restore backup — manual intervention required");
        }
        return Err(format!("Failed to install new binary: {}", e).into());
    }

    Ok(())
}

/// Restart the miner systemd service.
fn restart_service() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let service_name =
        std::env::var("MINER_SERVICE_NAME").unwrap_or_else(|_| "arion-miner".to_string());

    info!(service = %service_name, "Restarting systemd service");

    std::process::Command::new("systemctl")
        .args(["restart", &service_name])
        .spawn()?;

    Ok(())
}
