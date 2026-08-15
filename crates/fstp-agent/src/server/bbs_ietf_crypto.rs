//! IETF CFRG BBS HTTP API — dual-profile with [`super::bbs_crypto`] (Ursa).

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fstp_core::bbs_ietf::{
    capability_metadata, derive_proof, generate_key_pair, sign_messages, verify_proof,
    BbsIetfDeriveProofRequest, BbsIetfSignRequest, BbsIetfVerifyProofRequest,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateKeyPairQuery {
    pub message_count: Option<usize>,
}

/// **GET /fstp/crypto/bbs/ietf/status** — capability metadata (draft, ciphersuite, dual-profile).
pub async fn bbs_ietf_status_handler() -> Response {
    (StatusCode::OK, Json(capability_metadata())).into_response()
}

/// **POST /fstp/crypto/bbs/ietf/keypair**
pub async fn bbs_ietf_keypair_handler(Json(query): Json<GenerateKeyPairQuery>) -> Response {
    let count = query.message_count.unwrap_or(8).clamp(1, 64);
    match generate_key_pair(count) {
        Ok(keys) => (StatusCode::OK, Json(keys)).into_response(),
        Err(e) => error_response(e.to_string()),
    }
}

/// **POST /fstp/crypto/bbs/ietf/sign**
pub async fn bbs_ietf_sign_handler(Json(req): Json<BbsIetfSignRequest>) -> Response {
    match sign_messages(&req) {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(e) => error_response(e.to_string()),
    }
}

/// **POST /fstp/crypto/bbs/ietf/derive-proof**
pub async fn bbs_ietf_derive_proof_handler(Json(req): Json<BbsIetfDeriveProofRequest>) -> Response {
    match derive_proof(&req) {
        Ok(bundle) => (StatusCode::OK, Json(bundle)).into_response(),
        Err(e) => error_response(e.to_string()),
    }
}

/// **POST /fstp/crypto/bbs/ietf/verify-proof**
pub async fn bbs_ietf_verify_proof_handler(Json(req): Json<BbsIetfVerifyProofRequest>) -> Response {
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
