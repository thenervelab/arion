use semver::Version;
use tracing::{debug, info, warn};

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const GITHUB_API_URL: &str = "https://api.github.com/repos/thenervelab/arion/releases/latest";

pub async fn check_for_updates() {
    if let Err(e) = check_for_updates_inner().await {
        debug!(error = %e, "Version check skipped");
    }
}

async fn check_for_updates_inner() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let current = Version::parse(CURRENT_VERSION)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
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

    if current < latest {
        let url = body["html_url"]
            .as_str()
            .unwrap_or("https://github.com/thenervelab/arion/releases");
        warn!(
            current = %current,
            latest = %latest,
            url = url,
            "A newer miner version is available — please update"
        );
    } else {
        info!(version = %current, "Miner is up to date");
    }

    Ok(())
}
