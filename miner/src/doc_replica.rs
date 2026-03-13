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
use iroh_docs::{
    DocTicket,
    api::DocsApi,
    engine::{DefaultAuthorStorage, Engine},
};
use iroh_gossip::net::Gossip;
use tracing::info;

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
