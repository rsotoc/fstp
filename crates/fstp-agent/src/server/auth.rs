//! Federation authentication (whitepaper §3.1, §2.2 threat model, §5 deployment).
//! Peer routes: mTLS client certificate fingerprint; platform routes: `X-Pod-Agent-Key`.

use super::{FederationEntry, SharedState};
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use fstp_core::types::RejectionReason;
use fstp_core::utils::{cert_fingerprint, verify_cert_fingerprint};
use fstp_core::ContextualId;
use serde_json::json;

/// Type inserted into request extensions to pass the client certificate.
/// This decouples the auth middleware from third-party server primitives.
#[derive(Debug, Clone)]
pub struct TlsClientCert(pub Vec<u8>);

#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub entry: FederationEntry,
    pub cert_fingerprint: String,
    /// CII of the authenticated peer, mirrored from entry for convenience.
    pub cii: Option<ContextualId>,
}

/// axum middleware that authenticates the client certificate and resolves
/// the peer's `FederationEntry`.
pub async fn auth_middleware(
    State(state): State<SharedState>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();

    // Platform integration (Velyzor → agent); not a federated peer mTLS session.
    if path == "/rpc/verify-credential" {
        return next.run(request).await;
    }

    if is_platform_route(path) {
        return platform_key_auth(request, next).await;
    }

    // Dev: inbound present-credential without mTLS when platform key matches.
    if path == "/fstp/present-credential" && dev_trust_present_credential() {
        if platform_key_valid(&request) {
            return next.run(request).await;
        }
    }

    // Step 1: Extract client cert from extensions (Accepts MockClientCert or production TlsClientCert)
    let cert_der: Option<Vec<u8>> = request
        .extensions()
        .get::<MockClientCert>()
        .map(|m| m.0.clone())
        .or_else(|| {
            request
                .extensions()
                .get::<TlsClientCert>()
                .map(|t| t.0.clone())
        });

    let cert_der = match cert_der {
        Some(c) => c,
        None => {
            return auth_error(
                StatusCode::UNAUTHORIZED,
                RejectionReason::CertFingerprintMismatch,
                "no client certificate presented",
            );
        }
    };

    // Step 2: Compute fingerprint and constant-time evaluation
    let fingerprint = cert_fingerprint(&cert_der);
    let state_read = state.read().await;
    let mut authenticated_peer: Option<FederationEntry> = None;

    for entry in state_read.federation.values() {
        if verify_cert_fingerprint(&cert_der, &entry.cert_fingerprint) {
            authenticated_peer = Some(entry.clone());
            break;
        }
    }

    let entry = match authenticated_peer {
        Some(e) => e,
        None => {
            tracing::warn!(fingerprint = %fingerprint, "rejected connection: unknown certificate fingerprint");
            return auth_error(
                StatusCode::FORBIDDEN,
                RejectionReason::UnknownCii,
                "certificate fingerprint not in federation list",
            );
        }
    };

    drop(state_read);

    request.extensions_mut().insert(PeerIdentity {
        cii: Some(entry.peer_cii.clone()),
        entry,
        cert_fingerprint: fingerprint,
    });

    next.run(request).await
}

pub fn verify_sender_cii(peer: &PeerIdentity, sender_cii: &ContextualId) -> Result<(), Response> {
    if &peer.entry.peer_cii != sender_cii {
        return Err(auth_error(
            StatusCode::FORBIDDEN,
            RejectionReason::InvalidSignature,
            "sender_cii does not match authenticated peer",
        ));
    }
    Ok(())
}

fn is_platform_route(path: &str) -> bool {
    path.starts_with("/pod-agent/v1/")
        || path.starts_with("/fstp/admin/")
        || path.starts_with("/fstp/crypto/bbs/")
}

fn expected_platform_key() -> String {
    std::env::var("FSTP_POD_AGENT_KEY")
        .or_else(|_| std::env::var("FSTP_VELYZOR_POD_AGENT_KEY"))
        .unwrap_or_else(|_| "dev-pod-agent-key".to_string())
}

fn platform_key_valid(request: &Request) -> bool {
    request
        .headers()
        .get("x-pod-agent-key")
        .and_then(|v| v.to_str().ok())
        .map(|k| k == expected_platform_key())
        .unwrap_or(false)
}

pub(crate) fn dev_trust_present_credential() -> bool {
    std::env::var("FSTP_DEV_TRUST_PRESENT_CREDENTIAL")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

async fn platform_key_auth(request: Request, next: Next) -> Response {
    if platform_key_valid(&request) {
        return next.run(request).await;
    }
    auth_error(
        StatusCode::UNAUTHORIZED,
        RejectionReason::CertFingerprintMismatch,
        "invalid or missing X-Pod-Agent-Key for platform route",
    )
}

fn auth_error(status: StatusCode, reason: RejectionReason, detail: &str) -> Response {
    (
        status,
        Json(json!({
            "error": format!("{:?}", reason),
            "detail": detail,
        })),
    )
        .into_response()
}

#[derive(Debug, Clone)]
pub struct MockClientCert(pub Vec<u8>);

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{FederationEntry, ServerState};
    use fstp_core::crypto::NodeSigner;
    use fstp_core::types::{ContextualId, FederationEndpoint, PublicKey};
    use fstp_core::utils::cert_fingerprint;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use uuid::Uuid;

    fn fake_cert_der() -> Vec<u8> {
        b"fake-der-cert-bytes-for-testing".to_vec()
    }

    fn make_state_with_peer(fingerprint: &str) -> SharedState {
        let signer = NodeSigner::generate();
        let peer_signer = NodeSigner::generate();
        use fstp_core::identity::GlobalInstanceId;
        use fstp_core::pod_store::EncryptedPodStore;
        use fstp_core::types::Did;
        let gii = GlobalInstanceId::new(
            Did::new("did:key:server"),
            b"test-server-ikm-32-bytes!!!!!!!!".to_vec(),
        );
        let pod_root = std::env::temp_dir().join(format!("fstp-auth-test-{}", Uuid::new_v4()));
        let pod = Arc::new(
            EncryptedPodStore::initialize(&pod_root, "test-passphrase")
                .expect("test pod init"),
        );
        let sync_crdt = fstp_core::sync_crdt::SyncCrdtEngine::new();
        let transparent_log = Arc::new(
            fstp_core::transparent_log::TransparentLog::open(pod_root.join("logs")).unwrap(),
        );
        let mut state = ServerState::new(
            ContextualId::new("cii:server"),
            gii,
            signer,
            pod,
            sync_crdt,
            transparent_log,
            Did::new("did:key:server"),
            "https://example.com".to_string(),
            fstp_core::sync_policy::SyncPolicy::default(),
        );
        state.register_peer(FederationEntry {
            peer_cii: ContextualId::new("cii:peer-a"),
            link_id: Uuid::new_v4(),
            cert_fingerprint: fingerprint.to_string(),
            endpoint: FederationEndpoint::new("https://example.com", fingerprint),
            peer_did: Some("did:key:peer-a".to_string()),
            peer_pubkey: peer_signer.public_key(),
        });
        Arc::new(RwLock::new(state))
    }

    #[tokio::test]
    async fn fingerprint_of_known_cert_resolves_peer() {
        let der = fake_cert_der();
        let fp = cert_fingerprint(&der);
        let state = make_state_with_peer(&fp);
        let state_read = state.read().await;

        let mut matched = false;
        for entry in state_read.federation.values() {
            if verify_cert_fingerprint(&der, &entry.cert_fingerprint) {
                assert_eq!(entry.peer_cii.to_string(), "cii:peer-a");
                matched = true;
                break;
            }
        }
        assert!(matched);
    }
}
