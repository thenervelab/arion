//! TLS certificate configuration for Hippius Arion services.
//!
//! Loads certificates from environment variables or default paths,
//! with automatic self-signed certificate generation for development.

use convert_case::{Case, Casing};
use std::path::Path;
use tracing::{info, warn};

/// TLS configuration holding paths to certificate and key files.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Path to PEM-encoded certificate file
    pub cert_path: String,
    /// Path to PEM-encoded private key file
    pub key_path: String,
}

impl TlsConfig {
    /// Create TLS configuration for a service.
    ///
    /// Loading priority:
    /// 1. Environment variables: `ARION_{SERVICE}_TLS_CERT`, `ARION_{SERVICE}_TLS_KEY`
    /// 2. Default paths: `/etc/arion/{service}/cert.pem`, `/etc/arion/{service}/key.pem`
    /// 3. Fallback: Auto-generate self-signed in `/tmp/arion-{service}-{cert,key}.pem`
    ///
    /// # Errors
    ///
    /// Returns an error if TLS configuration cannot be loaded and self-signed certificate
    /// generation fails (e.g., openssl not available, permission denied).
    pub fn new(service_name: &str) -> Result<Self, String> {
        match Self::from_env(service_name) {
            Ok(config) => {
                info!(
                    service = service_name,
                    cert_path = %config.cert_path,
                    "Using TLS certificate"
                );
                Ok(config)
            }
            Err(e) => {
                warn!(
                    service = service_name,
                    error = %e,
                    "TLS configuration error, generating self-signed certificate"
                );

                let service_kebab = service_name.to_case(Case::Kebab);
                let cert_path = format!("/tmp/arion-{}-cert.pem", service_kebab);
                let key_path = format!("/tmp/arion-{}-key.pem", service_kebab);

                Self::generate_self_signed(&cert_path, &key_path, service_name)?;

                Ok(Self {
                    cert_path,
                    key_path,
                })
            }
        }
    }

    /// Load TLS configuration from environment variables.
    fn from_env(service_name: &str) -> Result<Self, String> {
        let service_upper = service_name.to_case(Case::UpperSnake);
        let service_kebab = service_name.to_case(Case::Kebab);

        let cert_path = std::env::var(format!("ARION_{}_TLS_CERT", service_upper))
            .unwrap_or_else(|_| format!("/etc/arion/{}/cert.pem", service_kebab));

        let key_path = std::env::var(format!("ARION_{}_TLS_KEY", service_upper))
            .unwrap_or_else(|_| format!("/etc/arion/{}/key.pem", service_kebab));

        // Verify files exist
        let verify_exists = |path: &str, desc: &str| -> Result<(), String> {
            if Path::new(path).exists() {
                Ok(())
            } else {
                Err(format!("TLS {} not found at: {}", desc, path))
            }
        };

        verify_exists(&cert_path, "certificate")?;
        verify_exists(&key_path, "private key")?;

        Ok(Self {
            cert_path,
            key_path,
        })
    }

    /// Generate a self-signed certificate for development/testing.
    fn generate_self_signed(
        cert_path: &str,
        key_path: &str,
        service_name: &str,
    ) -> Result<(), String> {
        // Check if certificates already exist (avoid race conditions and unnecessary regeneration)
        if Path::new(cert_path).exists() && Path::new(key_path).exists() {
            info!(
                cert_path = cert_path,
                key_path = key_path,
                "Using existing self-signed certificate"
            );
            return Ok(());
        }

        warn!("Generating self-signed certificate - DO NOT USE IN PRODUCTION");

        // Create parent directories if needed
        if let Some(parent) = Path::new(cert_path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create cert directory: {}", e))?;
        }

        let service_kebab = service_name.to_case(Case::Kebab);
        let subject = format!("/CN=arion-{}/O=Hippius/C=US", service_kebab);

        // Generate to temporary files first, then atomically rename to avoid races
        let temp_cert = format!("{}.tmp.{}", cert_path, std::process::id());
        let temp_key = format!("{}.tmp.{}", key_path, std::process::id());

        let output = std::process::Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:4096", "-keyout", &temp_key, "-out", &temp_cert,
                "-days", "365", "-nodes", "-subj", &subject,
            ])
            .output()
            .map_err(|e| format!("Failed to run openssl: {}", e))?;

        if !output.status.success() {
            // Clean up temp files on failure
            let _ = std::fs::remove_file(&temp_cert);
            let _ = std::fs::remove_file(&temp_key);
            return Err(format!(
                "Certificate generation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Atomically move temp files to final paths (rename is atomic on most filesystems)
        std::fs::rename(&temp_cert, cert_path)
            .map_err(|e| format!("Failed to rename temp cert: {}", e))?;
        std::fs::rename(&temp_key, key_path)
            .map_err(|e| format!("Failed to rename temp key: {}", e))?;

        info!(
            cert_path = cert_path,
            key_path = key_path,
            "Generated self-signed certificate"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_name_conversion() {
        assert_eq!("gateway".to_case(Case::UpperSnake), "GATEWAY");
        assert_eq!("gateway".to_case(Case::Kebab), "gateway");
        assert_eq!(
            "chain_submitter".to_case(Case::UpperSnake),
            "CHAIN_SUBMITTER"
        );
        assert_eq!("chain_submitter".to_case(Case::Kebab), "chain-submitter");
    }
}
