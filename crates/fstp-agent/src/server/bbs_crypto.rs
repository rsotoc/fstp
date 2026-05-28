//! BBS+ crypto HTTP API (AGR-DT-274) — delegates to fstp-core.

use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use fstp_core::bbs_plus::{
    derive_proof, generate_key_pair, sign_messages, verify_proof, BbsDeriveProofRequest,
    BbsSignRequest, BbsVerifyProofRequest,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateKeyPairQuery {
    pub message_count: Option<usize>,
}

/// **POST /fstp/crypto/bbs/keypair** — issuer key generation for N messages.
pub async fn bbs_keypair_handler(Json(query): Json<GenerateKeyPairQuery>) -> Response {
    let count = query.message_count.unwrap_or(8).clamp(1, 64);
    match generate_key_pair(count) {
        Ok(keys) => (StatusCode::OK, Json(keys)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// **POST /fstp/crypto/bbs/sign**
pub async fn bbs_sign_handler(Json(req): Json<BbsSignRequest>) -> Response {
    match sign_messages(&req) {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(e) => error_response(e.to_string()),
    }
}

/// **POST /fstp/crypto/bbs/derive-proof**
pub async fn bbs_derive_proof_handler(Json(req): Json<BbsDeriveProofRequest>) -> Response {
    match derive_proof(&req) {
        Ok(bundle) => (StatusCode::OK, Json(bundle)).into_response(),
        Err(e) => error_response(e.to_string()),
    }
}

/// **POST /fstp/crypto/bbs/verify-proof**
pub async fn bbs_verify_proof_handler(Json(req): Json<BbsVerifyProofRequest>) -> Response {
    match verify_proof(&req) {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(e) => error_response(e.to_string()),
    }
}

fn error_response(message: String) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": message })),
    )
        .into_response()
}
