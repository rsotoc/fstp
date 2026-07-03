//! Velyzor ↔ SA platform routes (whitepaper §4 coordination, §5 deployment).
//! `present-passport`, admin sync — mirrors `docs/contracts/agora-pod-agent-v1.md`.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fstp_core::identity::FederationContext;
use fstp_core::types::{FederationEndpoint, FstpError, LinkId};
use serde::{Deserialize, Serialize};

use crate::outbound::{build_http_client, present_credential_to_peer};
use crate::platform_util::link_id_from_pair;
use crate::server::SharedState;

const CONTRACT_VERSION: &str = "1.0.0";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentPassportPlatformRequest {
    pub citizen_id: i64,
    pub source_pod_key: String,
    pub source_subject_cii: String,
    pub target_external_did: String,
    pub target_agent_url: Option<String>,
    pub credential_external_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentPassportPlatformResponse {
    pub accepted: bool,
    pub target_subject_cii: Option<String>,
    pub error_message: Option<String>,
    pub stub_response: bool,
    pub contract_version: &'static str,
}

/// **POST /pod-agent/v1/federation/present-passport**
///
/// Called by Velyzor (source Pod). Forwards a signed `PresentCredential` to the target peer.
pub async fn present_passport_handler(
    State(state): State<SharedState>,
    Json(req): Json<PresentPassportPlatformRequest>,
) -> Response {
    if req.target_external_did.trim().is_empty() {
        return platform_json(PresentPassportPlatformResponse {
            accepted: false,
            target_subject_cii: None,
            error_message: Some("TARGET_DID_REQUIRED".into()),
            stub_response: false,
            contract_version: CONTRACT_VERSION,
        });
    }

    let (node_did, own_url, signer, link_id, target_endpoint) = {
        let state_read = state.read().await;
        let target_did = req.target_external_did.trim().to_lowercase();

        let (link_id, endpoint) = if let Some(peer) = state_read.peer_by_did(&target_did) {
            (peer.link_id, peer.endpoint.clone())
        } else if let Some(url) = req.target_agent_url.as_ref().filter(|u| !u.is_empty()) {
            let dev = std::env::var("FSTP_DEV_INSECURE_OUTBOUND")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false);
            if !dev {
                return platform_json(PresentPassportPlatformResponse {
                    accepted: false,
                    target_subject_cii: None,
                    error_message: Some(
                        "PEER_NOT_REGISTERED: register peer via POST /fstp/admin/peers \
                         or set FSTP_DEV_INSECURE_OUTBOUND=true with targetAgentUrl"
                            .into(),
                    ),
                    stub_response: false,
                    contract_version: CONTRACT_VERSION,
                });
            }
            let link_id = link_id_from_pair(&state_read.node_did.0, &target_did);
            (link_id, FederationEndpoint::new(url.trim(), "dev-insecure"))
        } else {
            return platform_json(PresentPassportPlatformResponse {
                accepted: false,
                target_subject_cii: None,
                error_message: Some("TARGET_AGENT_URL_OR_PEER_REGISTRY_REQUIRED".into()),
                stub_response: false,
                contract_version: CONTRACT_VERSION,
            });
        };

        (
            state_read.node_did.clone(),
            state_read.own_endpoint_url.clone(),
            state_read.signer.clone(),
            link_id,
            endpoint,
        )
    };

    let subject_id = format!("{}:{}", req.source_subject_cii, req.citizen_id);

    if dev_loopback_present_enabled() && same_sa_endpoint(&own_url, &target_endpoint.url) {
        match loopback_present_subject_cii(
            &state,
            link_id,
            &own_url,
            &target_endpoint.cert_fingerprint,
            &subject_id,
        )
        .await
        {
            Ok(subject_cii) => {
                tracing::info!(
                    citizen_id = req.citizen_id,
                    target_did = %req.target_external_did,
                    subject_cii = %subject_cii,
                    "Present-passport accepted via dev loopback (same SA)"
                );
                return platform_json(PresentPassportPlatformResponse {
                    accepted: true,
                    target_subject_cii: Some(subject_cii),
                    error_message: None,
                    stub_response: false,
                    contract_version: CONTRACT_VERSION,
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "Present-passport loopback failed");
                return platform_json(PresentPassportPlatformResponse {
                    accepted: false,
                    target_subject_cii: None,
                    error_message: Some(e.to_string()),
                    stub_response: false,
                    contract_version: CONTRACT_VERSION,
                });
            }
        }
    }

    let http = match build_http_client() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to build outbound HTTP client");
            return platform_json(PresentPassportPlatformResponse {
                accepted: false,
                target_subject_cii: None,
                error_message: Some("OUTBOUND_CLIENT_ERROR".into()),
                stub_response: false,
                contract_version: CONTRACT_VERSION,
            });
        }
    };

    match present_credential_to_peer(
        &http,
        &signer,
        &node_did,
        &own_url,
        &target_endpoint,
        link_id,
        &subject_id,
        req.credential_external_id.as_deref(),
        &req.source_pod_key,
        req.citizen_id,
    )
    .await
    {
        Ok(outcome) => {
            tracing::info!(
                citizen_id = req.citizen_id,
                target_did = %req.target_external_did,
                subject_cii = %outcome.subject_cii,
                "Present-passport accepted by target peer"
            );
            platform_json(PresentPassportPlatformResponse {
                accepted: true,
                target_subject_cii: Some(outcome.subject_cii),
                error_message: None,
                stub_response: false,
                contract_version: CONTRACT_VERSION,
            })
        }
        Err(e) => {
            tracing::warn!(
                citizen_id = req.citizen_id,
                error = %e,
                "Present-passport failed"
            );
            let msg = match &e {
                FstpError::HttpError { status, body } => {
                    format!("HTTP_{status}: {body}")
                }
                other => other.to_string(),
            };
            platform_json(PresentPassportPlatformResponse {
                accepted: false,
                target_subject_cii: None,
                error_message: Some(msg),
                stub_response: false,
                contract_version: CONTRACT_VERSION,
            })
        }
    }
}

/// **POST /fstp/admin/sync**
///
/// Triggers an active frontier sync with a registered peer (`link_id` query param).
pub async fn admin_sync_handler(
    State(state): State<SharedState>,
    axum::extract::Query(params): axum::extract::Query<AdminSyncQuery>,
) -> Response {
    let link_id = match params.link_id {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "link_id query parameter required"})),
            )
                .into_response();
        }
    };

    let peer_endpoint = {
        let state_read = state.read().await;
        let entry = state_read
            .federation
            .values()
            .find(|e| e.link_id == link_id)
            .cloned();
        match entry {
            Some(e) => e.endpoint,
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "unknown link_id"})),
                )
                    .into_response();
            }
        }
    };

    let client = crate::client::FstpClient::new();
    match client
        .synchronize_with_peer(state.clone(), &peer_endpoint, link_id)
        .await
    {
        Ok(result) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ok",
                "link_id": result.link_id.to_string(),
                "blocks_sent": result.blocks_sent,
                "blocks_received": result.blocks_received,
                "outcome": format!("{:?}", result.outcome),
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct AdminSyncQuery {
    pub link_id: Option<LinkId>,
}

fn platform_json(body: PresentPassportPlatformResponse) -> Response {
    (StatusCode::OK, Json(body)).into_response()
}

/// Dev: skip outbound HTTPS to self (same bind URL) — avoids mTLS loopback TLS failures.
fn dev_loopback_present_enabled() -> bool {
    if std::env::var("FSTP_DEV_LOOPBACK_PRESENT")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
    {
        return true;
    }
    std::env::var("FSTP_DEV_INSECURE_OUTBOUND")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

fn normalize_sa_url(url: &str) -> String {
    url.trim()
        .trim_end_matches('/')
        .to_lowercase()
        .replace("localhost", "127.0.0.1")
}

fn same_sa_endpoint(own_url: &str, peer_url: &str) -> bool {
    normalize_sa_url(own_url) == normalize_sa_url(peer_url)
}

/// Mirrors inbound `present_credential_handler` HKDF for P3 same-SA demos.
async fn loopback_present_subject_cii(
    state: &SharedState,
    link_id: LinkId,
    counterpart_url: &str,
    peer_cert_fingerprint: &str,
    subject_id: &str,
) -> Result<String, FstpError> {
    let state_read = state.read().await;
    let ctx = FederationContext::new(
        link_id,
        FederationEndpoint::new(counterpart_url, peer_cert_fingerprint),
    );
    let subject_cii = state_read.gii.derive_subject_cii(&ctx, subject_id);
    Ok(subject_cii.0)
}
