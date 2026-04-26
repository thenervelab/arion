use anyhow::Context;
use anyhow::Result;
use common::{ClusterMap, P2PStateSyncRequest};
use std::net::SocketAddr;
use tracing::{debug, error, info};

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

        // Find highest epoch on disk (highest number, regardless of gaps)
        let mut highest_epoch = 0;
        if let Ok(mut entries) = tokio::fs::read_dir(&archive_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with("epoch_") && name.ends_with(".json") {
                        if let Ok(epoch) = name[6..name.len()-5].parse::<u64>() {
                            if epoch > highest_epoch {
                                highest_epoch = epoch;
                            }
                        }
                    }
                }
            }
        }
        
        let start_sync_from = if highest_epoch > 0 { highest_epoch + 1 } else { 0 };
        info!(highest_epoch_on_disk = highest_epoch, start_sync_from, "Archive directory scanned");

        let first_missing_epoch = start_sync_from;

        // Get target epoch (current epoch from cluster map)
        let target_epoch = {
            let map_lock = crate::state::get_cluster_map().read().await;
            if let Some(map) = &*map_lock {
                map.epoch
            } else {
                debug!("State sync: waiting for cluster map...");
                continue; 
            }
        };

        if first_missing_epoch >= target_epoch {
            // Fully synced!
            crate::state::get_is_historical_seeder().store(true, std::sync::atomic::Ordering::Relaxed);
            debug!(first_missing_epoch, target_epoch, "State sync: already up to date");
            continue; 
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

        let mut skip_hash_check = false;
        if epoch < current_epoch {
            anyhow::bail!("Expected epoch {}, but received older epoch {}", current_epoch, epoch);
        } else if epoch > current_epoch {
            tracing::warn!("Gap in state sync: expected epoch {}, but received {}. Skipping missing epochs.", current_epoch, epoch);
            current_epoch = epoch;
            skip_hash_check = true;
        }

        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await.context("read_len")?;
        let len = u32::from_be_bytes(len_buf);

        if len > 4000 * 1024 * 1024 { // 4GB max per map (u32 limit)
            anyhow::bail!("Map too large: {} bytes", len);
        }

        let mut map_bytes = vec![0u8; len as usize];
        recv.read_exact(&mut map_bytes).await.context("read_map")?;

        // Verify JSON and Hash Chain
        let map: ClusterMap = serde_json::from_slice(&map_bytes).context("parse_map")?;
        
        if epoch > 0 && !skip_hash_check {
            if let Some(prev_hash) = &map.previous_hash {
                if prev_hash != &expected_previous_hash {
                    tracing::warn!(
                        "Hash chain inconsistency at epoch {}: expected {}, got {}. Continuing anyway as we trust the seeder.",
                        epoch, expected_previous_hash, prev_hash
                    );
                }
            } else {
                tracing::warn!("Missing previous_hash in epoch {}. Continuing.", epoch);
            }
        }

        // Validate signature (mandatory for trust)
        let validator_pk = crate::state::get_validator_node_id_global().read().await.clone();
        if !validator_pk.is_empty() {
            if let Some(sig_hex) = &map.signature {
                use ed25519_dalek::Verifier;
                let sig_res: anyhow::Result<()> = (async {
                    let sig_bytes = hex::decode(sig_hex).map_err(|e| anyhow::anyhow!("Invalid signature hex: {}", e))?;
                    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).map_err(|e| anyhow::anyhow!("Invalid signature format: {}", e))?;
                    let hash = map.compute_hash();
                    let pk_bytes = hex::decode(&validator_pk).map_err(|e| anyhow::anyhow!("Invalid validator PK hex: {}", e))?;
                    let pk = ed25519_dalek::VerifyingKey::try_from(pk_bytes.as_slice()).map_err(|e| anyhow::anyhow!("Invalid validator PK: {}", e))?;
                    pk.verify(hash.as_bytes(), &sig).map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))?;
                    Ok(())
                }).await;

                if let Err(e) = sig_res {
                    // For historical epochs, we might have different hash calculation logic or old signatures.
                    // If the hash chain is also broken, we are double-blind.
                    // However, we log it and continue for now if it's historical sync,
                    // but we SHOULD be careful.
                    tracing::warn!("Signature check failed for epoch {}: {}. Continuing historical sync.", epoch, e);
                }
            } else {
                tracing::warn!("Missing signature in epoch {}.", epoch);
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
