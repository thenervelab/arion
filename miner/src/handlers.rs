//! HTTP request handlers for the miner.

use crate::helpers::{bad_request_error, internal_error, not_found_error};
use crate::state::AppState;
use axum::Json;
use axum::extract::{Multipart, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use tracing::debug;

/// Request logging middleware
pub async fn log_request(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> impl IntoResponse {
    debug!(method = %req.method(), uri = %req.uri(), "Received request");
    next.run(req).await
}

/// Fallback handler for unknown routes
pub async fn fallback_handler(uri: axum::http::Uri) -> impl IntoResponse {
    debug!(uri = %uri, "404 - No route found");
    (StatusCode::NOT_FOUND, format!("No route for {}", uri))
}

/// Get blob by hash
pub async fn get_blob(
    State(state): State<AppState>,
    Path(hash_str): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let hash = match hash_str.parse::<iroh_blobs::Hash>() {
        Ok(h) => h,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "Invalid hash").into_response();
        }
    };

    // Use get_bytes (better for MemStore)
    match state.store.get_bytes(hash).await {
        Ok(bytes) => {
            // Empty bytes from FsStore means blob not found
            if bytes.is_empty() {
                return (StatusCode::NOT_FOUND, "Blob not found (empty)").into_response();
            }

            // Handle Range Header using and_then chains
            // Supports: "bytes=0-499", "bytes=500-", "bytes=-500"
            if let Some(slice) = headers
                .get("range")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("bytes="))
                .and_then(|range_val| {
                    let (start_str, end_str) = range_val.split_once('-')?;

                    let (start, end) = if start_str.is_empty() {
                        // "bytes=-500" means last 500 bytes
                        let suffix_len: usize = end_str.parse().ok()?;
                        let start = bytes.len().saturating_sub(suffix_len);
                        (start, bytes.len() - 1)
                    } else {
                        let start: usize = start_str.parse().ok()?;
                        let end = if end_str.is_empty() {
                            // "bytes=500-" means from 500 to end
                            bytes.len() - 1
                        } else {
                            end_str.parse::<usize>().ok()?.min(bytes.len() - 1)
                        };
                        (start, end)
                    };

                    (start <= end && start < bytes.len()).then(|| bytes[start..=end].to_vec())
                })
            {
                return (StatusCode::PARTIAL_CONTENT, slice).into_response();
            }
            (StatusCode::OK, bytes).into_response()
        }
        Err(e) => not_found_error("get_blob", e).into_response(),
    }
}

/// Add blob via multipart upload
pub async fn add_blob(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    // Process one file field from multipart request
    let field = match multipart.next_field().await {
        Ok(Some(field)) => field,
        Ok(None) => return (StatusCode::BAD_REQUEST, "No file provided").into_response(),
        Err(e) => {
            return bad_request_error("add_blob multipart", e).into_response();
        }
    };

    let data = match field.bytes().await {
        Ok(d) => d,
        Err(e) => {
            return bad_request_error("add_blob read bytes", e).into_response();
        }
    };

    // Use add_bytes (high-level API)
    let outcome = match state.store.add_bytes(data).await {
        Ok(o) => o,
        Err(e) => {
            return internal_error("add_blob store", e).into_response();
        }
    };

    let hash = outcome.hash;
    debug!(hash = %hash, "Stored blob");
    let node_addr = iroh::EndpointAddr::from(state.endpoint.secret_key().public());
    let ticket = iroh_blobs::ticket::BlobTicket::new(node_addr, hash, iroh_blobs::BlobFormat::Raw);
    let ticket_str = ticket.to_string().replace("blob", "hip");
    debug!(ticket = %ticket_str, "Generated ticket");
    Json(ticket_str).into_response()
}

/// Health check endpoint
pub async fn status() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}
