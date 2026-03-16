//! Iroh-docs replica for manifest gossip.
//!
//! The miner can join the validator's iroh-doc to receive manifest and
//! cluster-map updates via gossip, enabling self-healing without direct
//! validator communication.

use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use futures::StreamExt as _;
use iroh_docs::{
    DocTicket,
    api::DocsApi,
    engine::{DefaultAuthorStorage, Engine},
};
use iroh_gossip::net::Gossip;
use tracing::{debug, info, warn};

use crate::state;

/// Join the iroh-doc specified by `ticket_str`.
///
/// Spawns an iroh-docs engine with persistent storage under `data_dir/docs_v2/`,
/// imports the doc namespace from the ticket, and starts sync.
/// Stores the doc handle in global state and sets DOC_JOINED = true.
pub async fn join_doc(endpoint: iroh::Endpoint, data_dir: &Path, ticket_str: &str) -> Result<()> {
    let docs_dir = data_dir.join("docs_v2");
    tokio::fs::create_dir_all(&docs_dir).await?;

    // Blob store for doc replication
    let blobs_dir = docs_dir.join("blobs");
    tokio::fs::create_dir_all(&blobs_dir).await?;
    let blobs_store = iroh_blobs::store::fs::FsStore::load(&blobs_dir).await?;

    // Replica store
    let docs_path = docs_dir.join("docs.db");
    let docs_store = iroh_docs::store::fs::Store::persistent(&docs_path)?;

    // Gossip + downloader
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let downloader = iroh_blobs::api::downloader::Downloader::new(&blobs_store, &endpoint);
    let author_storage = DefaultAuthorStorage::Persistent(docs_dir.join("default_author"));

    // Engine
    let engine = Engine::spawn(
        endpoint.clone(),
        gossip,
        docs_store,
        blobs_store.deref().clone(),
        downloader,
        author_storage,
        None,
    )
    .await
    .context("Failed to spawn iroh-docs engine for miner")?;
    let engine_arc = Arc::new(engine);
    let docs_api = DocsApi::spawn(engine_arc.clone());

    // Parse ticket and join
    let ticket = DocTicket::from_str(ticket_str).context("Failed to parse doc ticket")?;
    let doc = docs_api
        .import_namespace(ticket.capability.clone())
        .await
        .context("Failed to import doc namespace")?;

    info!(doc_id = %doc.id(), "[GOSSIP] Joined manifest gossip network");

    engine_arc
        .start_sync(doc.id(), ticket.nodes.clone())
        .await
        .context("Failed to start doc sync")?;

    // Subscribe to doc events and log incoming manifest/cluster-map updates.
    let mut event_sub = doc
        .subscribe()
        .await
        .context("Failed to subscribe to doc events")?;
    let doc_id_str = doc.id().to_string();
    tokio::spawn(async move {
        let mut manifest_count = 0u64;
        let mut map_count = 0u64;
        loop {
            match event_sub.next().await {
                Some(Ok(event)) => {
                    use iroh_docs::engine::LiveEvent;
                    if let LiveEvent::InsertRemote { entry, .. } = event {
                        let key = entry.key();
                        if key.starts_with(b"map:") {
                            map_count += 1;
                            let epoch_str = std::str::from_utf8(&key[4..]).unwrap_or("?");
                            debug!(doc_id = %doc_id_str, epoch = %epoch_str, total_maps = map_count, "[DOC] Received cluster map update via gossip");
                        } else {
                            manifest_count += 1;
                            let hash_str = std::str::from_utf8(key).unwrap_or("?");
                            debug!(doc_id = %doc_id_str, file_hash = %hash_str, total_manifests = manifest_count, "[DOC] Received manifest update via gossip");
                            // Log periodically so we don't flood but confirm sync is working
                            if manifest_count == 1 || manifest_count % 100 == 0 {
                                info!(doc_id = %doc_id_str, total_manifests = manifest_count, total_maps = map_count, "[DOC] Gossip sync active — manifests received");
                            }
                        }
                    }
                }
                Some(Err(e)) => {
                    warn!(error = %e, "[DOC] Doc event stream error");
                }
                None => {
                    info!("[DOC] Doc event stream closed");
                    break;
                }
            }
        }
    });

    // Store in global state
    {
        let mut guard = state::get_doc_replica().write().await;
        *guard = Some(doc);
    }
    {
        let mut guard = state::get_doc_replica_blobs().write().await;
        *guard = Some(blobs_store);
    }
    state::get_doc_joined().store(true, std::sync::atomic::Ordering::Release);

    Ok(())
}
