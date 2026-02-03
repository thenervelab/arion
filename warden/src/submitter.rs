//! Client for submitting attestations to chain-submitter service.

use anyhow::Result;
use std::sync::OnceLock;
use tracing::{debug, error, info, warn};

use crate::attestation::SignedAttestation;

/// Default API key (should be overridden via ARION_API_KEY)
const DEFAULT_API_KEY: &str = "Arion";

/// Cached API key to avoid reading env var on every request
static CACHED_API_KEY: OnceLock<String> = OnceLock::new();

/// Get API key, caching the result and warning if using default
fn get_api_key() -> &'static str {
    CACHED_API_KEY.get_or_init(|| match std::env::var("ARION_API_KEY") {
        Ok(key) if !key.is_empty() => key,
        _ => {
            warn!(
                "ARION_API_KEY not set, using default. \
                     Set ARION_API_KEY environment variable for production."
            );
            DEFAULT_API_KEY.to_string()
        }
    })
}

/// Client for the chain-submitter service.
#[derive(Clone)]
pub struct ChainSubmitter {
    base_url: String,
    client: reqwest::Client,
}

impl ChainSubmitter {
    /// Create a new submitter client.
    ///
    /// # Arguments
    /// * `base_url` - Chain submitter endpoint URL
    /// * `insecure_tls` - If true, skip TLS certificate verification (dev only)
    pub fn new(base_url: &str, insecure_tls: bool) -> Self {
        let mut builder = reqwest::Client::builder();

        if insecure_tls {
            warn!(
                "TLS certificate verification disabled for chain-submitter. \
                 This is insecure and should only be used in development."
            );
            builder = builder.danger_accept_invalid_certs(true);
        }

        let client = builder.build().unwrap_or_else(|_| reqwest::Client::new());

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        }
    }

    /// Submit an attestation to the chain-submitter.
    ///
    /// The chain-submitter will batch attestations and submit them on-chain.
    pub async fn submit_attestation(&self, attestation: &SignedAttestation) -> Result<bool> {
        let url = format!("{}/attestations", self.base_url);

        debug!(
            shard = %attestation.attestation.shard_hash,
            miner = attestation.attestation.miner_uid,
            result = ?attestation.attestation.result,
            "Submitting attestation"
        );

        let response = self
            .client
            .post(&url)
            .header("X-API-Key", get_api_key())
            .json(attestation)
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                info!(
                    shard = %attestation.attestation.shard_hash,
                    "Attestation submitted successfully"
                );
                Ok(true)
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                error!(
                    status = %status,
                    body = %body,
                    "Attestation submission failed"
                );
                Ok(false)
            }
            Err(e) => {
                error!(error = %e, "Failed to connect to chain-submitter");
                Err(e.into())
            }
        }
    }

    /// Submit multiple attestations in a batch.
    ///
    /// Returns the count of successfully submitted attestations.
    pub async fn submit_batch(&self, attestations: &[SignedAttestation]) -> Result<usize> {
        let mut success_count = 0;
        let mut error_count = 0;
        for attestation in attestations {
            match self.submit_attestation(attestation).await {
                Ok(true) => success_count += 1,
                Ok(false) => {
                    // Server rejected but connection succeeded - already logged
                }
                Err(e) => {
                    error_count += 1;
                    debug!(error = %e, "Batch submission error for attestation");
                }
            }
        }
        if error_count > 0 {
            debug!(
                success = success_count,
                errors = error_count,
                total = attestations.len(),
                "Batch submission completed with errors"
            );
        }
        Ok(success_count)
    }
}

// ============================================================================
// Validator Client (Reputation System)
// ============================================================================

/// Client for pushing audit results to the validator (reputation system).
#[derive(Clone)]
pub struct ValidatorClient {
    base_url: String,
    api_key: Option<String>,
    client: reqwest::Client,
}

impl ValidatorClient {
    /// Create a new validator client.
    ///
    /// # Arguments
    /// * `base_url` - Validator endpoint URL
    /// * `api_key` - Optional API key for authentication
    /// * `insecure_tls` - If true, skip TLS certificate verification (dev only)
    pub fn new(base_url: &str, api_key: Option<String>, insecure_tls: bool) -> Self {
        let mut builder = reqwest::Client::builder();

        if insecure_tls {
            warn!(
                "TLS certificate verification disabled for validator client. \
                 This is insecure and should only be used in development."
            );
            builder = builder.danger_accept_invalid_certs(true);
        }

        let client = builder.build().unwrap_or_else(|_| reqwest::Client::new());

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key,
            client,
        }
    }

    /// Push audit results to the validator for reputation updates.
    pub async fn push_audit_results(&self, batch: &common::WardenAuditBatch) -> Result<bool> {
        let url = format!("{}/audit-results", self.base_url);

        debug!(
            reports = batch.reports.len(),
            "Pushing audit results to validator"
        );

        let mut request = self.client.post(&url).json(batch);

        if let Some(key) = &self.api_key {
            request = request.header("X-API-Key", key);
        }

        let response = request.send().await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                info!(
                    reports = batch.reports.len(),
                    "Audit results pushed to validator"
                );
                Ok(true)
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                error!(
                    status = %status,
                    body = %body,
                    "Failed to push audit results to validator"
                );
                Ok(false)
            }
            Err(e) => {
                error!(error = %e, "Failed to connect to validator");
                Err(e.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submitter_client_creation() {
        let client = ChainSubmitter::new("http://localhost:3004", false);
        assert!(client.base_url.ends_with("3004"));
    }

    #[test]
    fn test_submitter_client_insecure() {
        let client = ChainSubmitter::new("https://localhost:3004", true);
        assert!(client.base_url.ends_with("3004"));
    }

    #[test]
    fn test_validator_client_creation() {
        let client = ValidatorClient::new("http://localhost:3002", None, false);
        assert!(client.base_url.ends_with("3002"));
    }
}
