//! Admin routes for trusted issuer registry (production bootstrap).

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::server::SharedState;
use crate::trusted_issuers;

#[derive(Debug, Deserialize)]
pub struct RegisterTrustedIssuerRequest {
    pub did: String,
    pub pubkey_hex: String,
}

#[derive(Debug, Serialize)]
pub struct TrustedIssuersStatusResponse {
    pub count: usize,
    pub governance_issuer_configured: bool,
}

/// **POST /fstp/admin/trusted-issuers/register** — add issuer (platform key).
pub async fn register_trusted_issuer_handler(
    State(state): State<SharedState>,
    Json(req): Json<RegisterTrustedIssuerRequest>,
) -> Response {
    let mut state_write = state.write().await;
    match trusted_issuers::register_one(
        &mut state_write.issuer_registry,
        &req.did,
        &req.pubkey_hex,
    ) {
        Ok(true) => {
            if let Err(e) =
                trusted_issuers::persist_registry_to_pod(&state_write.pod, &state_write.issuer_registry)
            {
                tracing::warn!(error = %e, "Failed to persist trusted_issuers.json to pod");
            }
            Json(serde_json::json!({
                "registered": true,
                "did": req.did,
                "count": state_write.issuer_registry.len(),
            }))
            .into_response()
        }
        Ok(false) => (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid issuer entry"})),
        )
            .into_response(),
        Err(e) => (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// **GET /fstp/admin/trusted-issuers/status**
pub async fn trusted_issuers_status_handler(State(state): State<SharedState>) -> Response {
    let state_read = state.read().await;
    let governance = std::env::var("FSTP_GOVERNANCE_ISSUER_DID")
        .or_else(|_| std::env::var("VELYZOR_COMMON_ISSUER_DID"))
        .or_else(|_| std::env::var("AGORA_COMMON_ISSUER_DID"))
        .ok()
        .filter(|s| !s.trim().is_empty());
    Json(TrustedIssuersStatusResponse {
        count: state_read.issuer_registry.len(),
        governance_issuer_configured: governance.is_some(),
    })
    .into_response()
}

