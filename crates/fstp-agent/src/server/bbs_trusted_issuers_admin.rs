//! Admin routes for BBS+ issuer public keys (verify-only registry, ADR-AGR-278 P5).

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::server::SharedState;

#[derive(Debug, Deserialize)]
pub struct RegisterBbsIssuerRequest {
    pub did: String,
    #[serde(alias = "bbsPublicKeyHex", alias = "bbs_public_key_hex")]
    pub bbs_public_key_hex: String,
}

#[derive(Debug, Serialize)]
pub struct BbsIssuersStatusResponse {
    pub count: usize,
}

/// **POST /fstp/admin/bbs-trusted-issuers/register**
pub async fn register_bbs_issuer_handler(
    State(state): State<SharedState>,
    Json(req): Json<RegisterBbsIssuerRequest>,
) -> Response {
    let did = req.did.trim();
    let pk = req.bbs_public_key_hex.trim();
    if did.is_empty() || pk.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "did and bbs_public_key_hex required"})),
        )
            .into_response();
    }
    let mut state_write = state.write().await;
    state_write
        .bbs_issuer_registry
        .insert(did.to_string(), pk.to_string());
    let count = state_write.bbs_issuer_registry.len();
    Json(serde_json::json!({
        "registered": true,
        "did": did,
        "count": count,
    }))
    .into_response()
}

/// **GET /fstp/admin/bbs-trusted-issuers/status**
pub async fn bbs_issuers_status_handler(State(state): State<SharedState>) -> Response {
    let state_read = state.read().await;
    Json(BbsIssuersStatusResponse {
        count: state_read.bbs_issuer_registry.len(),
    })
    .into_response()
}
