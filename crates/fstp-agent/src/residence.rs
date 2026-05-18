//! Pod residence platform routes (whitepaper §3.2 contextual identity, §4 scenarios).
//! HKDF-derived subject CII + Blocklace `MembershipChange` (HU-04).

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fstp_core::blocklace::{AggregateAttrs, BlocklaceStore, BlockPayload};
use fstp_core::identity::FederationContext;
use fstp_core::message::EventClass;
use fstp_core::types::{Ed25519Sig, FederationEndpoint, Sha256Hash};
use serde::{Deserialize, Serialize};

use crate::platform_util::link_id_from_pair;
use crate::server::SharedState;

const CONTRACT_VERSION: &str = "1.0.0";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantResidenceRequest {
    pub citizen_id: i64,
    pub pod_key: String,
    pub credential_json: Option<String>,
    pub signature_hex: Option<String>,
    pub source_community_id: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantResidenceResponse {
    pub granted: bool,
    pub subject_cii: Option<String>,
    pub error_message: Option<String>,
    pub stub_response: bool,
    pub contract_version: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeResidenceRequest {
    pub citizen_id: i64,
    pub pod_key: String,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeResidenceResponse {
    pub revoked: bool,
    pub contract_version: &'static str,
}

/// **POST /pod-agent/v1/residences/grant**
pub async fn grant_residence_handler(
    State(state): State<SharedState>,
    Json(req): Json<GrantResidenceRequest>,
) -> Response {
    if req.pod_key.trim().is_empty() || req.citizen_id <= 0 {
        return grant_json(GrantResidenceResponse {
            granted: false,
            subject_cii: None,
            error_message: Some("INVALID_REQUEST".into()),
            stub_response: false,
            contract_version: CONTRACT_VERSION,
        });
    }

    let (subject_cii, block_hash) = {
        let mut state_write = state.write().await;
        let link_scope = format!(
            "residence:{}:{}",
            req.pod_key.trim(),
            req.source_community_id.unwrap_or(0)
        );
        let link_id = link_id_from_pair(&state_write.node_did.0, &link_scope);
        let ctx = FederationContext::new(
            link_id,
            FederationEndpoint::new(&state_write.own_endpoint_url, "pod-residence"),
        );
        let subject_id = format!("citizen:{}", req.citizen_id);
        let subject_cii = state_write.gii.derive_subject_cii(&ctx, &subject_id);

        let signable = serde_json::json!({
            "action": "grant_residence",
            "citizenId": req.citizen_id,
            "podKey": req.pod_key,
            "sourceCommunityId": req.source_community_id,
            "hasCredential": req.credential_json.is_some(),
        });
        let event_hash = Sha256Hash::digest(signable.to_string().as_bytes());
        let sig = state_write.signer.sign_bytes(signable.to_string().as_bytes());
        let payload = BlockPayload {
            event_hash: event_hash.clone(),
            event_class: EventClass::MembershipChange,
            aggregate_attrs: AggregateAttrs {
                participant_count: Some(1),
                quorum_reached: Some(true),
                rounds_completed: Some(1),
            },
        };
        let block_hash = match state_write.blocklace.append(payload, sig) {
            Ok(b) => Some(format!("{}", b.block_hash)),
            Err(e) => {
                tracing::error!(error = %e, "grant residence blocklace append failed");
                None
            }
        };

        tracing::info!(
            citizen_id = req.citizen_id,
            pod_key = %req.pod_key,
            subject_cii = %subject_cii,
            ?block_hash,
            "Pod residence granted"
        );
        (subject_cii, block_hash)
    };

    let _ = block_hash;
    grant_json(GrantResidenceResponse {
        granted: true,
        subject_cii: Some(subject_cii.0),
        error_message: None,
        stub_response: false,
        contract_version: CONTRACT_VERSION,
    })
}

/// **POST /pod-agent/v1/residences/revoke**
pub async fn revoke_residence_handler(
    State(state): State<SharedState>,
    Json(req): Json<RevokeResidenceRequest>,
) -> Response {
    let signable = serde_json::json!({
        "action": "revoke_residence",
        "citizenId": req.citizen_id,
        "podKey": req.pod_key,
        "reason": req.reason,
    });
    let event_hash = Sha256Hash::digest(signable.to_string().as_bytes());
    let mut state_write = state.write().await;
    let sig: Ed25519Sig = state_write.signer.sign_bytes(signable.to_string().as_bytes());
    let payload = BlockPayload {
        event_hash: event_hash.clone(),
        event_class: EventClass::MembershipChange,
        aggregate_attrs: AggregateAttrs {
            participant_count: Some(1),
            quorum_reached: Some(true),
            rounds_completed: None,
        },
    };
    if let Err(e) = state_write.blocklace.append(payload, sig) {
        tracing::warn!(error = %e, "revoke residence blocklace append failed");
    }

    tracing::info!(
        citizen_id = req.citizen_id,
        pod_key = %req.pod_key,
        "Pod residence revoked"
    );

    (
        StatusCode::OK,
        Json(RevokeResidenceResponse {
            revoked: true,
            contract_version: CONTRACT_VERSION,
        }),
    )
        .into_response()
}

fn grant_json(body: GrantResidenceResponse) -> Response {
    (StatusCode::OK, Json(body)).into_response()
}
