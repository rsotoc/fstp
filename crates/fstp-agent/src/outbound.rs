//! Outbound federation HTTP client (whitepaper §3.1 SA, §5 mTLS).
//! Signs and POSTs `present-credential` to a registered peer endpoint.

use chrono::{Duration, Utc};
use fstp_core::crypto::NodeSigner;
use fstp_core::message::{CredentialType, CredentialValidity};
use fstp_core::types::{Did, FederationEndpoint, FstpError, LinkId, Result};
use serde::{Deserialize, Serialize};

/// Payload mirrored from `handlers::PresentCredentialRequest` (inbound peer API).
#[derive(Debug, Serialize)]
pub struct OutboundPresentCredentialRequest {
    pub link_id: LinkId,
    pub counterpart_url: String,
    pub subject_id: String,
    pub credential_type: CredentialType,
    pub claims: serde_json::Value,
    pub issuer_did: String,
    pub validity: CredentialValidity,
    pub signature_hex: String,
}

#[derive(Debug, Deserialize)]
struct PresentCredentialResponse {
    subject_cii: String,
}

#[derive(Debug, Clone)]
pub struct PresentCredentialOutcome {
    pub subject_cii: String,
    pub block_hash: Option<String>,
}

/// Build signable bytes (must match `handlers::PresentCredentialSignable`).
fn present_signable_bytes(req: &OutboundPresentCredentialRequest) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Signable<'a> {
        link_id: LinkId,
        counterpart_url: &'a str,
        subject_id: &'a str,
        credential_type: &'a CredentialType,
        claims: &'a serde_json::Value,
        issuer_did: &'a str,
        validity: &'a CredentialValidity,
    }
    let inner = Signable {
        link_id: req.link_id,
        counterpart_url: &req.counterpart_url,
        subject_id: &req.subject_id,
        credential_type: &req.credential_type,
        claims: &req.claims,
        issuer_did: &req.issuer_did,
        validity: &req.validity,
    };
    serde_json::to_vec(&inner).map_err(FstpError::SerializationError)
}

/// Signs and POSTs `PresentCredential` to the target agent's federation endpoint.
pub async fn present_credential_to_peer(
    http: &reqwest::Client,
    signer: &NodeSigner,
    issuer_did: &Did,
    own_endpoint_url: &str,
    target: &FederationEndpoint,
    link_id: LinkId,
    subject_id: &str,
    credential_external_id: Option<&str>,
    source_pod_key: &str,
    citizen_id: i64,
) -> Result<PresentCredentialOutcome> {
    let now = Utc::now();
    let claims = serde_json::json!({
        "citizenId": citizen_id,
        "sourcePodKey": source_pod_key,
        "credentialExternalId": credential_external_id,
        "purpose": "pod_federation_passport",
    });

    let mut req = OutboundPresentCredentialRequest {
        link_id,
        counterpart_url: own_endpoint_url.to_string(),
        subject_id: subject_id.to_string(),
        credential_type: CredentialType::InstitutionalMembership,
        claims,
        issuer_did: issuer_did.0.clone(),
        validity: CredentialValidity {
            issued_at: now,
            valid_until: now + Duration::days(365),
        },
        signature_hex: String::new(),
    };

    let signable = present_signable_bytes(&req)?;
    let sig = signer.sign_bytes(&signable);
    req.signature_hex = hex::encode(sig.0.to_bytes());

    let url = target.present_credential_url();
    tracing::info!(%url, %link_id, "Outbound: POST present-credential to peer");

    let mut request = http.post(&url).json(&req);
    if dev_trust_present_credential() {
        let key = std::env::var("FSTP_POD_AGENT_KEY")
            .or_else(|_| std::env::var("FSTP_AGORA_POD_AGENT_KEY"))
            .unwrap_or_else(|_| "dev-pod-agent-key".to_string());
        request = request.header("X-Pod-Agent-Key", key);
    }

    let http_res = request.send().await.map_err(|e| FstpError::SyncFailed {
        link_id,
        reason: format!("present-credential HTTP: {e}"),
    })?;

    let status = http_res.status();
    let body = http_res.text().await.map_err(|e| FstpError::SyncFailed {
        link_id,
        reason: e.to_string(),
    })?;

    if !status.is_success() {
        return Err(FstpError::HttpError {
            status: status.as_u16(),
            body,
        });
    }

    let parsed: PresentCredentialResponse =
        serde_json::from_str(&body).map_err(FstpError::SerializationError)?;

    let block_hash = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| {
            v.get("block_hash")
                .and_then(|b| b.as_str().map(String::from))
        });

    Ok(PresentCredentialOutcome {
        subject_cii: parsed.subject_cii,
        block_hash,
    })
}

fn dev_trust_present_credential() -> bool {
    std::env::var("FSTP_DEV_TRUST_PRESENT_CREDENTIAL")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

pub fn build_http_client() -> Result<reqwest::Client> {
    let insecure = std::env::var("FSTP_DEV_INSECURE_OUTBOUND")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let mut builder = reqwest::Client::builder();
    if insecure {
        tracing::warn!(
            "FSTP_DEV_INSECURE_OUTBOUND enabled — TLS certificate verification disabled"
        );
        builder = builder.danger_accept_invalid_certs(true);
    }

    if let (Ok(cert_path), Ok(key_path)) = (
        std::env::var("FSTP_CERT_PATH"),
        std::env::var("FSTP_KEY_PATH"),
    ) {
        if let (Ok(cert_pem), Ok(key_pem)) = (std::fs::read(&cert_path), std::fs::read(&key_path)) {
            if let Ok(identity) = reqwest::Identity::from_pkcs8_pem(&cert_pem, &key_pem) {
                builder = builder.identity(identity);
            } else {
                tracing::warn!(
                    cert = %cert_path,
                    key = %key_path,
                    "Could not load mTLS client identity for outbound HTTP"
                );
            }
        }
    }

    builder
        .build()
        .map_err(|e| FstpError::TlsError(format!("reqwest client: {e}")))
}
