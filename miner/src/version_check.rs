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

    let mut interval =
        tokio::time::interval(std::time::Duration::from_secs(UPDATE_CHECK_INTERVAL_SECS));
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

    match check_and_update().await {
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
async fn check_and_update() -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
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

    // Stage the download next to the executable it will replace so the final
    // rename(2) stays on a single filesystem. The service working directory
    // may live on a different volume than the installed binary, and a
    // cross-device rename fails with EXDEV (os error 18).
    let current_exe = std::env::current_exe()?;
    let exe_dir = current_exe
        .parent()
        .ok_or("current executable has no parent directory")?;
    let temp_path = exe_dir.join(".miner-update-tmp");
    let backup_path = current_exe.with_extension("bak");

    let staged = stage_and_install(
        &client,
        &download_url,
        tag_clean,
        &temp_path,
        &current_exe,
        &backup_path,
    )
    .await;

    if staged.is_err() {
        // Never leave a partial or unused download behind — at ~80 MB per
        // 5-minute cycle these accumulate fast when updates fail repeatedly.
        tokio::fs::remove_file(&temp_path).await.ok();
    }
    staged?;

    info!(
        new_version = %latest,
        binary = %current_exe.display(),
        backup = %backup_path.display(),
        "Binary replaced successfully"
    );

    Ok(true)
}

/// Download, verify, and swap in the new binary. The staging file lives in
/// the destination directory; the caller cleans it up on failure.
async fn stage_and_install(
    client: &reqwest::Client,
    download_url: &str,
    expected_version: &str,
    temp_path: &Path,
    current_exe: &Path,
    backup_path: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    download_binary(client, download_url, temp_path).await?;

    // Make executable.
    set_executable(temp_path).await?;

    // Verify the downloaded binary by running --version — this must pass
    // before the running binary is touched.
    verify_binary(temp_path, expected_version).await?;

    // Replace the current binary: back up old, rename new into place.
    replace_binary(current_exe, backup_path, temp_path).await
}

/// Find the browser_download_url for the miner asset in the release JSON.
fn find_asset_url(
    release: &serde_json::Value,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let assets = release["assets"].as_array().ok_or("missing assets array")?;

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

    info!(size_bytes = bytes.len(), "Download complete");
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

    // Move temp into the current binary path.
    if let Err(e) = install_new_binary(temp, current).await {
        // Try to restore from backup.
        error!(error = %e, "Failed to move new binary into place, restoring backup");
        if let Err(restore_err) = tokio::fs::rename(backup, current).await {
            error!(error = %restore_err, "Failed to restore backup — manual intervention required");
        }
        return Err(format!("Failed to install new binary: {}", e).into());
    }

    Ok(())
}

/// `rename(2)` cannot cross filesystems.
const EXDEV: i32 = 18;

#[cfg(test)]
static FORCE_EXDEV: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Rename wrapper; tests can force an EXDEV failure to exercise the fallback.
async fn rename_file(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if FORCE_EXDEV.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(std::io::Error::from_raw_os_error(EXDEV));
    }
    tokio::fs::rename(from, to).await
}

/// Install the staged binary at `current`. Prefers an atomic rename — staging
/// happens in the destination directory, so this is the normal path. If the
/// rename still crosses filesystems (EXDEV), falls back to a durable
/// copy + fsync + rename entirely inside the destination directory.
async fn install_new_binary(temp: &Path, current: &Path) -> std::io::Result<()> {
    match rename_file(temp, current).await {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(EXDEV) => {
            info!("Staging file is on a different filesystem — installing via copy + fsync");
            copy_install(temp, current).await
        }
        Err(e) => Err(e),
    }
}

/// Copy-based install: copy the staged binary to a scratch file in the
/// destination directory, fsync the file and the directory, then rename
/// within that directory. Never leaves a torn destination binary.
async fn copy_install(temp: &Path, current: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let dest_dir = current
        .parent()
        .ok_or_else(|| std::io::Error::other("destination binary has no parent directory"))?;
    let stage = dest_dir.join(".miner-update-stage");

    let result: std::io::Result<()> = async {
        tokio::fs::copy(temp, &stage).await?;
        tokio::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o755)).await?;

        // fsync the file contents before the rename makes it visible.
        let staged = tokio::fs::File::open(&stage).await?;
        staged.sync_all().await?;

        tokio::fs::rename(&stage, current).await?;

        // fsync the directory so the rename itself is durable.
        let dir = std::fs::File::open(dest_dir)?;
        dir.sync_all()?;
        Ok(())
    }
    .await;

    if result.is_err() {
        tokio::fs::remove_file(&stage).await.ok();
        return result;
    }

    // The rename did not consume the cross-device staging file.
    tokio::fs::remove_file(temp).await.ok();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::Ordering;

    /// FORCE_EXDEV is process-global; serialize the tests that install binaries.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[tokio::test]
    async fn replace_binary_renames_within_same_fs() {
        let _guard = TEST_LOCK.lock().unwrap();
        FORCE_EXDEV.store(false, Ordering::Relaxed);

        let dir = tempfile::tempdir().unwrap();
        let current = dir.path().join("miner");
        let backup = current.with_extension("bak");
        let temp = dir.path().join(".miner-update-tmp");
        std::fs::write(&current, b"old-binary").unwrap();
        std::fs::write(&temp, b"new-binary").unwrap();

        replace_binary(&current, &backup, &temp).await.unwrap();

        assert_eq!(std::fs::read(&current).unwrap(), b"new-binary");
        assert_eq!(std::fs::read(&backup).unwrap(), b"old-binary");
        assert!(!temp.exists());
    }

    #[tokio::test]
    async fn exdev_rename_falls_back_to_durable_copy() {
        let _guard = TEST_LOCK.lock().unwrap();
        FORCE_EXDEV.store(true, Ordering::Relaxed);

        let dir = tempfile::tempdir().unwrap();
        let current = dir.path().join("miner");
        let backup = current.with_extension("bak");
        let temp = dir.path().join(".miner-update-tmp");
        std::fs::write(&current, b"old-binary").unwrap();
        std::fs::write(&temp, b"new-binary-contents").unwrap();

        let result = replace_binary(&current, &backup, &temp).await;
        FORCE_EXDEV.store(false, Ordering::Relaxed);
        result.unwrap();

        // Complete, correct, and executable.
        assert_eq!(std::fs::read(&current).unwrap(), b"new-binary-contents");
        let mode = std::fs::metadata(&current).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
        // Old binary preserved as backup; no staging debris left behind.
        assert_eq!(std::fs::read(&backup).unwrap(), b"old-binary");
        assert!(!temp.exists());
        assert!(!dir.path().join(".miner-update-stage").exists());
    }
}
