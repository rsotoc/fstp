//! Platform admin routes for Blocklace inspection and local append (Ágora bridge).

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fstp_core::blocklace::{AggregateAttrs, BlocklaceStore, BlockPayload};
use fstp_core::message::EventClass;
use fstp_core::types::{Ed25519Sig, Sha256Hash};
use serde::Deserialize;

use crate::server::SharedState;

#[derive(Debug, Deserialize)]
pub struct BlocklaceAppendRequest {
    pub event_hash_hex: String,
    pub event_class: String,
    pub participant_count: Option<u32>,
    pub quorum_reached: Option<bool>,
    pub rounds_completed: Option<u32>,
}

pub async fn blocklace_status_handler(State(state): State<SharedState>) -> Response {
    let state_read = state.read().await;
    let report = state_read.blocklace.verify_chain();
    let frontier = state_read.blocklace.frontier();
    let export = state_read.blocklace.export_frontier();
    drop(state_read);

    Json(serde_json::json!({
        "valid": report.valid,
        "total_blocks": report.total_blocks,
        "frontier_size": report.frontier_size,
        "dangling_pointers": report.dangling_pointers,
        "corrupted_blocks": report.corrupted_blocks.iter().map(|h| h.to_hex()).collect::<Vec<_>>(),
        "frontier_hashes": frontier.iter().map(|h| h.to_hex()).collect::<Vec<_>>(),
        "exported_at": export.exported_at,
    }))
    .into_response()
}

pub async fn blocklace_append_handler(
    State(state): State<SharedState>,
    Json(req): Json<BlocklaceAppendRequest>,
) -> Response {
    let event_class = match parse_event_class(&req.event_class) {
        Ok(c) => c,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": msg})),
            )
                .into_response();
        }
    };

    let hash_bytes = match hex::decode(req.event_hash_hex.trim()) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "event_hash_hex must be 32 bytes"})),
            )
                .into_response();
        }
    };
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash_bytes);
    let event_hash = Sha256Hash::from_bytes(arr);

    let payload = BlockPayload {
        event_hash,
        event_class,
        aggregate_attrs: AggregateAttrs {
            participant_count: req.participant_count,
            quorum_reached: req.quorum_reached,
            rounds_completed: req.rounds_completed,
        },
    };

    let mut state_write = state.write().await;
    let signature = state_write.signer.sign_bytes(&payload.canonical_bytes());
    match state_write.blocklace.append(payload, signature) {
        Ok(block) => Json(serde_json::json!({
            "block_hash": block.block_hash.to_hex(),
            "event_hash": block.payload.event_hash.to_hex(),
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

fn parse_event_class(s: &str) -> Result<EventClass, String> {
    match s.trim().to_lowercase().as_str() {
        "decision" => Ok(EventClass::Decision),
        "membership_change" => Ok(EventClass::MembershipChange),
        "credential_lifecycle" => Ok(EventClass::CredentialLifecycle),
        "federation_lifecycle" => Ok(EventClass::FederationLifecycle),
        other => Err(format!("unknown event_class: {other}")),
    }
}
