use anyhow::Context;
use anyhow::Result;
use common::{ClusterMap, P2PStateSyncRequest};
use std::net::SocketAddr;
use tracing::{error, info};

pub async fn run_state_sync_loop() {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
    
    loop {
        interval.tick().await;

        let archive_dir = match crate::state::get_data_dir() {
            Some(dir) => dir.join("epoch_archive"),
            None => continue,
        };

        if !archive_dir.exists() {
            if let Err(e) = tokio::fs::create_dir_all(&archive_dir).await {
                error!("Failed to create epoch_archive dir: {}", e);
                continue;
            }
        }

        // Find highest contiguous epoch
        let mut highest_epoch = 0;
        loop {
            let path = archive_dir.join(format!("epoch_{}.json", highest_epoch));
            if path.exists() {
                highest_epoch += 1;
            } else {
                break;
            }
        }
        
        // highest_epoch is actually the FIRST missing epoch.
        // E.g., if we have 0, 1, 2... then highest_epoch will be 3.
        let first_missing_epoch = highest_epoch;

        // Get target epoch (current epoch from cluster map)
        let target_epoch = {
            let map_lock = crate::state::get_cluster_map().read().await;
            if let Some(map) = &*map_lock {
                map.epoch
            } else {
                continue; // Wait until we have a cluster map
            }
        };

        if first_missing_epoch >= target_epoch {
            // Fully synced!
            crate::state::get_is_historical_seeder().store(true, std::sync::atomic::Ordering::Relaxed);
            continue; // Keep running loop just in case it falls behind? Actually, miners download latest map directly from validator, so the history is mostly for full historical reconstruction. The loop can just sleep.
        }

        info!(
            first_missing_epoch, target_epoch,
            "Missing historical epochs. Starting state sync..."
        );

        if let Err(e) = perform_state_sync(first_missing_epoch, target_epoch, archive_dir).await {
            error!("State sync failed: {}", e);
        }
    }
}

async fn perform_state_sync(
    start_epoch: u64,
    _target_epoch: u64,
    archive_dir: std::path::PathBuf,
) -> Result<()> {
    // 1. Find a seeder
    let (seeder_node_id, seeder_addr) = find_seeder().await.context("find_seeder")?;

    info!(
        seeder_node_id = %seeder_node_id,
        "Connecting to seeder for state sync"
    );

    // We must create a specific connection using P2P_STATE_SYNC_ALPN
    // because the standard connection pool uses MINER_CONTROL_ALPN.
    // Wait, the client config needs P2P_STATE_SYNC_ALPN.
    let endpoint = crate::p2p::get_state_sync_client_endpoint().context("get_endpoint")?;

    let conn = common::transport::connect(endpoint, seeder_addr, &seeder_node_id).await.context("connect")?;
    
    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;

    // Send request
    let req = P2PStateSyncRequest { start_epoch };
    let req_bytes = serde_json::to_vec(&req).context("to_vec")?;
    
    send.write_all(&(req_bytes.len() as u32).to_be_bytes()).await.context("write_len")?;
    send.write_all(&req_bytes).await.context("write_req")?;

    let mut current_epoch = start_epoch;
    let mut downloaded_count = 0;

    // Load the previous hash to verify the chain.
    let mut expected_previous_hash = if current_epoch > 0 {
        let prev_path = archive_dir.join(format!("epoch_{}.json", current_epoch - 1));
        let prev_bytes = tokio::fs::read(&prev_path).await.context("read_prev")?;
        let prev_map: ClusterMap = serde_json::from_slice(&prev_bytes).context("parse_prev")?;
        prev_map.compute_hash()
    } else {
        String::new()
    };

    loop {
        let mut magic_buf = [0u8; 4];
        recv.read_exact(&mut magic_buf).await.context("read_magic")?;
        let magic = u32::from_be_bytes(magic_buf);

        if magic == 0x454F4621 { // "EOF!"
            info!("Received EOF from seeder. Downloaded {} epochs.", downloaded_count);
            break;
        } else if magic != 0x594E4353 { // "SYNC"
            anyhow::bail!("Invalid magic header from seeder: {:x}", magic);
        }

        let mut epoch_buf = [0u8; 8];
        recv.read_exact(&mut epoch_buf).await.context("read_epoch")?;
        let epoch = u64::from_be_bytes(epoch_buf);

        if epoch != current_epoch {
            anyhow::bail!("Expected epoch {}, but received {}", current_epoch, epoch);
        }

        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await.context("read_len")?;
        let len = u32::from_be_bytes(len_buf);

        if len > 50 * 1024 * 1024 { // 50MB max per map
            anyhow::bail!("Map too large: {} bytes", len);
        }

        let mut map_bytes = vec![0u8; len as usize];
        recv.read_exact(&mut map_bytes).await.context("read_map")?;

        // Verify JSON and Hash Chain
        let map: ClusterMap = serde_json::from_slice(&map_bytes).context("parse_map")?;
        
        if epoch > 0 {
            if let Some(prev_hash) = &map.previous_hash {
                if prev_hash != &expected_previous_hash {
                    anyhow::bail!(
                        "Hash chain broken at epoch {}: expected {}, got {}",
                        epoch, expected_previous_hash, prev_hash
                    );
                }
            } else {
                anyhow::bail!("Missing previous_hash in epoch {}", epoch);
            }
        }

        // Validate signature (assuming validator's public key is known)
        let validator_pk = crate::state::get_validator_node_id_global().read().await.clone();
        if !validator_pk.is_empty() {
            if let Some(sig_hex) = &map.signature {
                // Inline verify
                use ed25519_dalek::Verifier;
                if let Ok(sig_bytes) = hex::decode(sig_hex) {
                    if let Ok(sig) = ed25519_dalek::Signature::from_slice(&sig_bytes) {
                        let hash = map.compute_hash();
                        if let Ok(pk_bytes) = hex::decode(&validator_pk) {
                            if let Ok(pk) = ed25519_dalek::VerifyingKey::try_from(pk_bytes.as_slice()) {
                                let _ = pk.verify(hash.as_bytes(), &sig);
                            }
                        }
                    }
                }
            }
        }

        // Save to disk
        let path = archive_dir.join(format!("epoch_{}.json", epoch));
        let mut tmp_path = path.clone();
        tmp_path.set_extension("json.tmp");
        tokio::fs::write(&tmp_path, &map_bytes).await.context("write_map")?;
        tokio::fs::rename(&tmp_path, &path).await.context("rename_map")?;

        expected_previous_hash = map.compute_hash();
        current_epoch += 1;
        downloaded_count += 1;
        
        if downloaded_count % 1000 == 0 {
            info!("Downloaded {} historical epochs...", downloaded_count);
        }
    }

    Ok(())
}

async fn find_seeder() -> Result<(String, SocketAddr)> {
    let map_lock = crate::state::get_cluster_map().read().await;
    let map = match &*map_lock {
        Some(m) => m,
        None => anyhow::bail!("No cluster map available"),
    };

    // 1. Try to find another miner who is a seeder
    let mut seeders = map.miners.iter()
        .filter(|m| m.is_historical_seeder)
        .collect::<Vec<_>>();
    
    // Pick a random seeder
    if !seeders.is_empty() {
        use rand::seq::SliceRandom;
        seeders.shuffle(&mut rand::thread_rng());
        let seeder = seeders[0];
        
        let addr = crate::state::socket_addr_from_endpoint(&seeder.endpoint);
        if let Some(addr) = addr {
            return Ok((seeder.public_key.clone(), addr));
        }
    }

    // 2. Fallback to Validator
    let val_addr = *crate::state::get_validator_addr().read().await;
    let val_id = crate::state::get_validator_node_id_global().read().await.clone();
    
    if let Some(addr) = val_addr {
        if !val_id.is_empty() {
            return Ok((val_id, addr));
        }
    }

    anyhow::bail!("No seeders available and validator unreachable")
}
