//! Admin HTTP routes for institutional quorum (AGR-106).

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use fstp_core::quorum::{QuorumConfig, QuorumShareSubmission, SuccessionReason};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::quorum_gate::DEFAULT_APPROVAL_TTL_SECS;
use crate::quorum_service::{self, AdminSignatureInput, RecoverRequest};
use crate::quorum_store;
use crate::server::SharedState;

pub const QUORUM_TOKEN_HEADER: &str = "x-fstp-quorum-token";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumStatusResponse {
    pub initialized: bool,
    pub threshold: Option<u8>,
    pub total_shares: Option<u8>,
    pub admin_count: usize,
    pub approval_active: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumSetupRequest {
    pub threshold: u8,
    pub total_shares: u8,
    pub admins: Vec<fstp_core::quorum::QuorumAdmin>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumRecoverRequest {
    pub shares: Vec<QuorumShareSubmission>,
    pub new_did: String,
    pub reason: SuccessionReason,
    pub admin_signatures: Vec<AdminSignatureInput>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumUnlockRequest {
    pub shares: Vec<QuorumShareSubmission>,
}

/// **GET /fstp/admin/quorum/status**
pub async fn quorum_status_handler(State(state): State<SharedState>) -> Response {
    let state_read = state.read().await;
    let cfg = &state_read.quorum_gate.config;
    Json(QuorumStatusResponse {
        initialized: state_read.quorum_gate.is_initialized(),
        threshold: cfg.as_ref().map(|c| c.threshold),
        total_shares: cfg.as_ref().map(|c| c.total_shares),
        admin_count: cfg.as_ref().map(|c| c.admins.len()).unwrap_or(0),
        approval_active: state_read.quorum_gate.approval_active(),
    })
    .into_response()
}

/// **POST /fstp/admin/quorum/setup** — split node seed into M-of-N shares (once).
pub async fn quorum_setup_handler(
    State(state): State<SharedState>,
    Json(req): Json<QuorumSetupRequest>,
) -> Response {
    let mut state_write = state.write().await;
    if state_write.quorum_gate.is_initialized() {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "quorum already initialized"})),
        )
            .into_response();
    }
    let config = QuorumConfig {
        threshold: req.threshold,
        total_shares: req.total_shares,
        admins: req.admins,
        initialized: false,
    };
    match quorum_service::setup_quorum(&state_write.pod, config) {
        Ok((saved, shares)) => {
            state_write.quorum_gate.config = Some(saved);
            Json(serde_json::json!({
                "initialized": true,
                "threshold": state_write.quorum_gate.config.as_ref().unwrap().threshold,
                "shareCount": shares.len(),
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// **POST /fstp/admin/quorum/recover** — M shares + admin signatures → succession act.
pub async fn quorum_recover_handler(
    State(state): State<SharedState>,
    Json(req): Json<QuorumRecoverRequest>,
) -> Response {
    let mut state_write = state.write().await;
    let Some(config) = state_write.quorum_gate.config.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "quorum not configured"})),
        )
            .into_response();
    };
    let old_did = state_write.node_did.clone();
    let recover_req = RecoverRequest {
        shares: req.shares,
        new_did: req.new_did,
        reason: req.reason,
        admin_signatures: req.admin_signatures,
    };
    match quorum_service::recover_quorum(&state_write.pod, &config, &old_did, recover_req) {
        Ok(mut outcome) => {
            let token = state_write
                .quorum_gate
                .grant_approval(Duration::from_secs(DEFAULT_APPROVAL_TTL_SECS));
            outcome.approval_token = token.clone();
            Json(serde_json::json!({
                "succession": outcome.succession,
                "approvalToken": token,
                "approvalTtlSecs": outcome.approval_ttl_secs,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// **POST /fstp/admin/quorum/unlock** — M shares → short-lived approval token (maintenance).
pub async fn quorum_unlock_handler(
    State(state): State<SharedState>,
    Json(req): Json<QuorumUnlockRequest>,
) -> Response {
    let mut state_write = state.write().await;
    let Some(config) = state_write.quorum_gate.config.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "quorum not configured"})),
        )
            .into_response();
    };
    match quorum_service::unlock_with_shares(&config, req.shares) {
        Ok(_seed) => {
            let token = state_write
                .quorum_gate
                .grant_approval(Duration::from_secs(DEFAULT_APPROVAL_TTL_SECS));
            Json(serde_json::json!({
                "approvalToken": token,
                "approvalTtlSecs": DEFAULT_APPROVAL_TTL_SECS,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// **GET /fstp/admin/quorum/share/{index}** — export one Shamir share (platform admin).
pub async fn quorum_export_share_handler(
    State(state): State<SharedState>,
    Path(index): Path<u8>,
) -> Response {
    let state_read = state.read().await;
    if !state_read.quorum_gate.is_initialized() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "quorum not initialized"})),
        )
            .into_response();
    }
    match quorum_store::load_share(&state_read.pod, index) {
        Ok(Some(share)) => Json(share).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "share not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// Returns 403 response if protected op lacks valid quorum token.
pub fn require_quorum_token(state: &crate::server::ServerState, headers: &HeaderMap) -> Option<Response> {
    if !state.quorum_gate.is_initialized() {
        return None;
    }
    let token = headers
        .get(QUORUM_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok());
    if state.quorum_gate.verify_token(token) {
        return None;
    }
    Some(
        (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "QUORUM_REQUIRED",
                "hint": "Submit M shares via POST /fstp/admin/quorum/unlock and pass X-Fstp-Quorum-Token"
            })),
        )
            .into_response(),
    )
}
