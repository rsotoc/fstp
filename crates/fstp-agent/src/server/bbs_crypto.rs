//! Legacy Ursa BBS+ HTTP API — **disabled** (410 Gone). Use `/fstp/crypto/bbs/ietf/*`.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateKeyPairQuery {
    pub message_count: Option<usize>,
}

fn ursa_gone() -> Response {
    (
        StatusCode::GONE,
        Json(json!({
            "success": false,
            "error": "BBS_URSA_GONE",
            "message": "Ursa BBS path disabled; use IETF CFRG routes under /fstp/crypto/bbs/ietf/",
            "ietfStatusPath": "/fstp/crypto/bbs/ietf/status",
            "ietfKeypairPath": "/fstp/crypto/bbs/ietf/keypair",
            "ietfSignPath": "/fstp/crypto/bbs/ietf/sign",
            "ietfDeriveProofPath": "/fstp/crypto/bbs/ietf/derive-proof",
            "ietfVerifyProofPath": "/fstp/crypto/bbs/ietf/verify-proof"
        })),
    )
        .into_response()
}

/// **POST /fstp/crypto/bbs/keypair** — Gone (Ursa retired).
pub async fn bbs_keypair_handler(Json(_query): Json<GenerateKeyPairQuery>) -> Response {
    ursa_gone()
}

/// **POST /fstp/crypto/bbs/sign** — Gone (Ursa retired).
pub async fn bbs_sign_handler(Json(_req): Json<serde_json::Value>) -> Response {
    ursa_gone()
}

/// **POST /fstp/crypto/bbs/derive-proof** — Gone (Ursa retired).
pub async fn bbs_derive_proof_handler(Json(_req): Json<serde_json::Value>) -> Response {
    ursa_gone()
}

/// **POST /fstp/crypto/bbs/verify-proof** — Gone (Ursa retired).
pub async fn bbs_verify_proof_handler(Json(_req): Json<serde_json::Value>) -> Response {
    ursa_gone()
}
