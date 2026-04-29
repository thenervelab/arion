use anyhow::Context;
use anyhow::Result;
use common::{ClusterMap, P2PStateSyncRequest};
use std::collections::HashSet;
use std::net::SocketAddr;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
enum SyncSourceKind {
    Validator,
    HistoricalSeeder,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SyncSource {
    node_id: String,
    addr: SocketAddr,
    kind: SyncSourceKind,
}

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
    let sources = find_sync_sources().await.context("find_sync_sources")?;
    let endpoint = crate::p2p::get_state_sync_client_endpoint().context("get_endpoint")?;
    let mut last_error = None;
    for source in sources {
        info!(
            source_kind = ?source.kind,
            source_node_id = %source.node_id,
            source_addr = %source.addr,
            "Connecting to state sync source"
        );
        match perform_state_sync_from_source(endpoint, &source, start_epoch, &archive_dir).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                warn!(
                    source_kind = ?source.kind,
                    source_node_id = %source.node_id,
                    source_addr = %source.addr,
                    error = %err,
                    "State sync source failed, trying next candidate"
                );
                last_error = Some(err);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No usable state sync source found")))
}

async fn perform_state_sync_from_source(
    endpoint: &quinn::Endpoint,
    source: &SyncSource,
    start_epoch: u64,
    archive_dir: &std::path::Path,
) -> Result<()> {
    let conn = common::transport::connect(endpoint, source.addr, &source.node_id)
        .await
        .context("connect")?;

    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;

    let req = P2PStateSyncRequest { start_epoch };
    let req_bytes = serde_json::to_vec(&req).context("to_vec")?;
    send.write_all(&(req_bytes.len() as u32).to_be_bytes())
        .await
        .context("write_len")?;
    send.write_all(&req_bytes).await.context("write_req")?;

    let mut current_epoch = start_epoch;
    let mut downloaded_count = 0;
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

        if magic == 0x454F4621 {
            info!(
                source_kind = ?source.kind,
                source_node_id = %source.node_id,
                downloaded_count,
                "Received EOF from state sync source"
            );
            break;
        } else if magic != 0x594E4353 {
            anyhow::bail!("Invalid magic header from seeder: {:x}", magic);
        }

        let mut epoch_buf = [0u8; 8];
        recv.read_exact(&mut epoch_buf).await.context("read_epoch")?;
        let epoch = u64::from_be_bytes(epoch_buf);

        let mut skip_hash_check = false;
        if epoch < current_epoch {
            anyhow::bail!("Expected epoch {}, but received older epoch {}", current_epoch, epoch);
        } else if epoch > current_epoch {
            warn!(
                expected_epoch = current_epoch,
                received_epoch = epoch,
                "Gap in state sync, skipping missing epochs"
            );
            current_epoch = epoch;
            skip_hash_check = true;
        }

        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await.context("read_len")?;
        let len = u32::from_be_bytes(len_buf);

        if len > 4000 * 1024 * 1024 {
            anyhow::bail!("Map too large: {} bytes", len);
        }

        let mut map_bytes = vec![0u8; len as usize];
        recv.read_exact(&mut map_bytes).await.context("read_map")?;

        let map: ClusterMap = serde_json::from_slice(&map_bytes).context("parse_map")?;

        if epoch > 0 && !skip_hash_check {
            if let Some(prev_hash) = &map.previous_hash {
                if prev_hash != &expected_previous_hash {
                    warn!(
                        epoch,
                        expected_previous_hash,
                        received_previous_hash = %prev_hash,
                        "Hash chain inconsistency during historical sync"
                    );
                }
            } else {
                warn!(epoch, "Missing previous_hash during historical sync");
            }
        }

        let validator_pk = crate::state::get_validator_node_id_global().read().await.clone();
        if !validator_pk.is_empty() {
            if let Some(sig_hex) = &map.signature {
                use ed25519_dalek::Verifier;
                let sig_res: anyhow::Result<()> = (async {
                    let sig_bytes = hex::decode(sig_hex)
                        .map_err(|e| anyhow::anyhow!("Invalid signature hex: {}", e))?;
                    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
                        .map_err(|e| anyhow::anyhow!("Invalid signature format: {}", e))?;
                    let hash = map.compute_hash();
                    let pk_bytes = hex::decode(&validator_pk)
                        .map_err(|e| anyhow::anyhow!("Invalid validator PK hex: {}", e))?;
                    let pk = ed25519_dalek::VerifyingKey::try_from(pk_bytes.as_slice())
                        .map_err(|e| anyhow::anyhow!("Invalid validator PK: {}", e))?;
                    pk.verify(hash.as_bytes(), &sig)
                        .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))?;
                    Ok(())
                })
                .await;

                if let Err(e) = sig_res {
                    warn!(epoch, error = %e, "Signature check failed during historical sync");
                }
            } else {
                warn!(epoch, "Missing signature during historical sync");
            }
        }

        let path = archive_dir.join(format!("epoch_{}.json", epoch));
        let mut tmp_path = path.clone();
        tmp_path.set_extension("json.tmp");
        tokio::fs::write(&tmp_path, &map_bytes).await.context("write_map")?;
        tokio::fs::rename(&tmp_path, &path).await.context("rename_map")?;

        expected_previous_hash = map.compute_hash();
        current_epoch += 1;
        downloaded_count += 1;

        if downloaded_count % 1000 == 0 {
            info!(downloaded_count, "Downloaded historical epochs");
        }
    }

    Ok(())
}

async fn find_sync_sources() -> Result<Vec<SyncSource>> {
    let map_lock = crate::state::get_cluster_map().read().await;
    let map = match &*map_lock {
        Some(m) => m,
        None => anyhow::bail!("No cluster map available"),
    };
    let val_addr = *crate::state::get_validator_addr().read().await;
    let val_id = crate::state::get_validator_node_id_global().read().await.clone();
    let sources = build_sync_sources(map, &val_id, val_addr);
    if sources.is_empty() {
        anyhow::bail!("No seeders available and validator unreachable");
    }
    Ok(sources)
}

fn build_sync_sources(
    map: &common::ClusterMap,
    validator_node_id: &str,
    validator_addr: Option<SocketAddr>,
) -> Vec<SyncSource> {
    let mut sources = Vec::new();
    let mut seen = HashSet::new();

    if let Some(addr) = validator_addr
        && !validator_node_id.is_empty()
    {
        seen.insert((validator_node_id.to_string(), addr));
        sources.push(SyncSource {
            node_id: validator_node_id.to_string(),
            addr,
            kind: SyncSourceKind::Validator,
        });
    }

    let mut seeders = map
        .miners
        .iter()
        .filter(|m| m.is_historical_seeder)
        .collect::<Vec<_>>();
    use rand::seq::SliceRandom;
    let mut rng = rand::rng();
    seeders.shuffle(&mut rng);

    for seeder in seeders {
        if let Some(addr) = crate::state::socket_addr_from_endpoint(&seeder.endpoint) {
            let key = (seeder.public_key.clone(), addr);
            if seen.insert(key.clone()) {
                sources.push(SyncSource {
                    node_id: key.0,
                    addr: key.1,
                    kind: SyncSourceKind::HistoricalSeeder,
                });
            }
        }
    }
    sources
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::TransportAddr;

    fn test_miner(
        uid: u32,
        pubkey: &str,
        node_id: &str,
        addr: &str,
        is_historical_seeder: bool,
    ) -> common::MinerNode {
        common::MinerNode {
            uid,
            endpoint: iroh::EndpointAddr::from_parts(
                node_id.parse().unwrap(),
                vec![TransportAddr::Ip(addr.parse().unwrap())],
            ),
            is_historical_seeder,
            weight: 1,
            ip_subnet: "0.0.0.0/0".to_string(),
            ip_address: Some(addr.split(':').next().unwrap().to_string()),
            http_addr: "http://127.0.0.1:3001".to_string(),
            public_key: pubkey.to_string(),
            base_weight: 1,
            total_storage: 0,
            available_storage: 0,
            family_id: "f".to_string(),
            last_seen: 0,
            strikes: 0,
            heartbeat_count: 0,
            registration_time: 0,
            bandwidth_total: 0,
            bandwidth_window_start: 0,
            weight_manual_override: false,
            reputation: 0.0,
            consecutive_audit_passes: 0,
            integrity_fails: 0,
            version: "0.1.23".to_string(),
            warden_challenges_total: 0,
            warden_challenges_passed: 0,
            fetch_timeout_count: 0,
            expected_shards: 0,
            actual_shards: 0,
            trust_score: 0.0,
            earned_capacity_bytes: 0,
            draining: false,
            p2p_reliability_score: 1.0,
            balancer_reweight: 1.0,
        }
    }

    #[test]
    fn build_sync_sources_prefers_validator_over_seeders() {
        let map = common::ClusterMap {
            miners: vec![
                test_miner(
                    1,
                    "peer-pub-1",
                    "372af6558dd5d388d739c9b2f3e34cd1c78fa10c23ceb77221d5eb3869eadb88",
                    "141.94.253.155:11220",
                    true,
                ),
                test_miner(
                    2,
                    "peer-pub-2",
                    "6d6ce0a9f8e0f5aaf7fa6f4cffb4d2a5068374d36d5e40b355748dcbf0fe8cf5",
                    "51.178.74.105:11220",
                    true,
                ),
            ],
            epoch: 1,
            previous_hash: None,
            signature: None,
            pg_count: 16384,
            ec_k: 10,
            ec_m: 20,
            pg_upmap: std::collections::HashMap::new(),
        };
        let validator_addr: SocketAddr = "51.210.230.161:11220".parse().unwrap();
        let sources = build_sync_sources(
            &map,
            "185651f2fb19c919d40c3c58660cf463ebe7ded1c1a326eef4dad28292171cdb",
            Some(validator_addr),
        );

        assert_eq!(sources.first().unwrap().kind, SyncSourceKind::Validator);
        assert_eq!(sources.first().unwrap().addr, validator_addr);
        assert_eq!(sources.len(), 3);
    }

    #[test]
    fn build_sync_sources_falls_back_to_seeders_when_validator_missing() {
        let map = common::ClusterMap {
            miners: vec![test_miner(
                1,
                "peer-pub-1",
                "372af6558dd5d388d739c9b2f3e34cd1c78fa10c23ceb77221d5eb3869eadb88",
                "141.94.253.155:11220",
                true,
            )],
            epoch: 1,
            previous_hash: None,
            signature: None,
            pg_count: 16384,
            ec_k: 10,
            ec_m: 20,
            pg_upmap: std::collections::HashMap::new(),
        };
        let sources = build_sync_sources(&map, "", None);

        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].kind, SyncSourceKind::HistoricalSeeder);
        assert_eq!(sources[0].addr, "141.94.253.155:11220".parse().unwrap());
    }
}
