//! HTTP API for the Warden service.
//!
//! Endpoints:
//! - POST /shards - Validator pushes new shard commitment
//! - DELETE /shards/{shard_hash} - Validator notifies shard deletion
//! - GET /health - Health check
//! - GET /metrics - Prometheus metrics (TODO)

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info};

use crate::state::{ShardInfo, WardenState};

/// Shared application state for handlers.
pub struct AppState {
    pub warden: Arc<WardenState>,
}

/// Request body for POST /shards.
#[derive(Debug, Deserialize)]
pub struct PushShardRequest {
    /// BLAKE3 hash of the shard
    pub shard_hash: String,
    /// Poseidon2 Merkle root commitment
    pub merkle_root: [u32; 8],
    /// Number of chunks in this shard
    pub chunk_count: u32,
    /// Miner UID holding this shard
    pub miner_uid: u32,
    /// Miner's Iroh node ID (hex) - deprecated, use miner_endpoint
    #[serde(default)]
    pub miner_node_id: String,
    /// Miner's full EndpointAddr (JSON serialized) for P2P connections
    #[serde(default)]
    pub miner_endpoint: Option<String>,
}

/// Response body for POST /shards.
#[derive(Debug, Serialize)]
pub struct PushShardResponse {
    pub status: String,
    pub shard_hash: String,
}

/// Response body for GET /health.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: &'static str,
    pub shards_tracked: usize,
    pub pending_challenges: usize,
}

/// POST /shards - Validator pushes new shard commitment.
pub async fn push_shard(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PushShardRequest>,
) -> impl IntoResponse {
    debug!(
        shard_hash = %req.shard_hash,
        miner_uid = req.miner_uid,
        chunk_count = req.chunk_count,
        "Received shard push"
    );

    // Parse the miner endpoint if provided
    let miner_endpoint = req.miner_endpoint.as_ref().and_then(|s| {
        serde_json::from_str::<iroh::EndpointAddr>(s)
            .map_err(|e| {
                tracing::warn!(error = %e, "Failed to parse miner_endpoint");
                e
            })
            .ok()
    });

    let info = ShardInfo {
        shard_hash: req.shard_hash.clone(),
        merkle_root: req.merkle_root,
        chunk_count: req.chunk_count,
        miner_uid: req.miner_uid,
        miner_endpoint,
        last_audited: None,
    };

    state.warden.upsert_shard(info);

    info!(
        shard_hash = %req.shard_hash,
        total_shards = state.warden.shard_count(),
        "Shard registered"
    );

    (
        StatusCode::OK,
        Json(PushShardResponse {
            status: "ok".to_string(),
            shard_hash: req.shard_hash,
        }),
    )
}

/// DELETE /shards/{shard_hash} - Validator notifies shard deletion.
pub async fn delete_shard(
    State(state): State<Arc<AppState>>,
    Path(shard_hash): Path<String>,
) -> impl IntoResponse {
    debug!(shard_hash = %shard_hash, "Received shard delete");

    state.warden.remove_shard(&shard_hash);

    info!(
        shard_hash = %shard_hash,
        total_shards = state.warden.shard_count(),
        "Shard removed"
    );

    StatusCode::OK
}

/// GET /health - Health check endpoint.
pub async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION"),
        shards_tracked: state.warden.shard_count(),
        pending_challenges: state.warden.pending_count(),
    })
}

/// Build the Axum router (used by tests).
#[cfg(test)]
fn build_router(state: Arc<AppState>) -> axum::Router {
    use axum::routing::{delete, get, post};
    axum::Router::new()
        .route("/shards", post(push_shard))
        .route("/shards/{shard_hash}", delete(delete_shard))
        .route("/health", get(health))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tempfile::tempdir;
    use tower::ServiceExt;

    fn app_state() -> (Arc<AppState>, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let warden = WardenState::open(&db_path, 100_000, 10_000).unwrap();
        warden.load_and_recover().unwrap();
        (
            Arc::new(AppState {
                warden: Arc::new(warden),
            }),
            dir,
        )
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let (state, _dir) = app_state();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_push_shard() {
        let (state, _dir) = app_state();
        let app = build_router(state.clone());

        let body = serde_json::json!({
            "shard_hash": "abc123",
            "merkle_root": [1, 2, 3, 4, 5, 6, 7, 8],
            "chunk_count": 100,
            "miner_uid": 42,
            "miner_node_id": "node123"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/shards")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.warden.shard_count(), 1);
    }

    #[tokio::test]
    async fn test_delete_shard() {
        let (state, _dir) = app_state();

        // Add a shard first
        state.warden.upsert_shard(ShardInfo {
            shard_hash: "abc123".to_string(),
            merkle_root: [0; 8],
            chunk_count: 100,
            miner_uid: 1,
            miner_endpoint: None,
            last_audited: None,
        });
        assert_eq!(state.warden.shard_count(), 1);

        let app = build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/shards/abc123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.warden.shard_count(), 0);
    }
}
