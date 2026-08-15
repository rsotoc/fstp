//! Federation HTTP server and `ServerState` (whitepaper §3.1 synchronization agent).
//! Hosts Blocklace, peer registry, and Axum router for `/fstp/*` and platform routes.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls_pemfile::Item;
use tokio::sync::RwLock;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

// ─────────────────────────────────────────────────────────────
// FSTP Core imports
// ─────────────────────────────────────────────────────────────

use fstp_core::audit::AuditLog;
use fstp_core::blocklace::InMemoryBlocklace;
use fstp_core::crypto::NodeSigner;
use fstp_core::identity::GlobalInstanceId;
use fstp_core::pod_store::EncryptedPodStore;
use fstp_core::inbound::InboundValidator;
use fstp_core::offline_queue::OfflineOutboundQueue;
use fstp_core::sync_crdt::SyncCrdtEngine;
use fstp_core::sync_policy::SyncPolicy;
use fstp_core::transparent_log::TransparentLog;
use fstp_core::types::{ContextualId, FederationEndpoint, FstpError, LinkId, PublicKey, Result};
use fstp_core::IssuerRegistry;

use super::handlers;
use super::mtls_accept::ClientCertInjectAcceptor;
use super::integration;

#[derive(Debug, Clone)]
pub struct FederationEntry {
    pub peer_cii: ContextualId,
    pub link_id: LinkId,
    pub cert_fingerprint: String,
    pub endpoint: FederationEndpoint,

    /// Optional institutional DID for HU-06 peer resolution (Phase 3).
    pub peer_did: Option<String>,

    /// Responder public key received during federation establishment.
    /// Used to verify signed synchronization responses.
    pub peer_pubkey: PublicKey,
}

#[derive(Debug)]
pub struct ServerState {
    pub own_cii: ContextualId,

    /// Local GII — used to derive subject-scoped CIIs (Phase 2).
    pub gii: GlobalInstanceId,

    /// Federated peers indexed by certificate fingerprint.
    pub federation: HashMap<String, FederationEntry>,

    /// Local Blocklace DAG.
    pub blocklace: InMemoryBlocklace,

    /// Encrypted institutional pod (AGR-101).
    pub pod: Arc<EncryptedPodStore>,

    /// Automerge CRDT sync engine (AGR-103).
    pub sync_crdt: SyncCrdtEngine,

    /// Hash-linked federation traffic log (AGR-104).
    pub transparent_log: Arc<TransparentLog>,

    /// Structured audit log (§4.2).
    pub audit: AuditLog,

    /// Node signing key used for signed protocol responses.
    pub signer: NodeSigner,

    /// Trusted issuer DIDs for gRPC credential verification.
    pub issuer_registry: IssuerRegistry,

    /// BBS+ public keys by issuer DID (verify-only, ADR-AGR-278 P5).
    pub bbs_issuer_registry: HashMap<String, String>,

    /// Local node DID (issuer for outbound present-credential).
    pub node_did: fstp_core::types::Did,

    /// Public base URL of this agent (`FSTP_OWN_URL`).
    pub own_endpoint_url: String,

    /// Secondary index: peer DID (lowercase) → cert fingerprint.
    peer_did_index: HashMap<String, String>,

    /// In-memory offline outbound queue (AGR-102).
    pub offline_queue: Arc<OfflineOutboundQueue>,

    /// Heartbeat / timeout policy from `config/sync_policy.json`.
    pub sync_policy: SyncPolicy,

    /// Centralized inbound validation (AGR-102).
    pub inbound_validator: InboundValidator,

    /// Shamir M-of-N governance (AGR-106).
    pub quorum_gate: crate::quorum_gate::QuorumGate,
}

impl ServerState {
    pub fn new(
        own_cii: ContextualId,
        gii: GlobalInstanceId,
        signer: NodeSigner,
        pod: Arc<EncryptedPodStore>,
        sync_crdt: SyncCrdtEngine,
        transparent_log: Arc<TransparentLog>,
        node_did: fstp_core::types::Did,
        own_endpoint_url: String,
        sync_policy: SyncPolicy,
    ) -> Self {
        Self::new_with_blocklace(
            own_cii,
            gii,
            signer,
            InMemoryBlocklace::new(),
            pod,
            sync_crdt,
            transparent_log,
            node_did,
            own_endpoint_url,
            sync_policy,
        )
    }

    pub fn new_with_blocklace(
        own_cii: ContextualId,
        gii: GlobalInstanceId,
        signer: NodeSigner,
        blocklace: InMemoryBlocklace,
        pod: Arc<EncryptedPodStore>,
        sync_crdt: SyncCrdtEngine,
        transparent_log: Arc<TransparentLog>,
        node_did: fstp_core::types::Did,
        own_endpoint_url: String,
        sync_policy: SyncPolicy,
    ) -> Self {
        let offline_queue =
            Arc::new(OfflineOutboundQueue::new(sync_policy.offline_queue_capacity));
        Self {
            own_cii,
            gii,
            federation: HashMap::new(),
            blocklace,
            pod,
            sync_crdt,
            transparent_log: transparent_log.clone(),
            audit: AuditLog::with_transparent(transparent_log),
            signer,
            issuer_registry: IssuerRegistry::default(),
            bbs_issuer_registry: HashMap::new(),
            node_did,
            own_endpoint_url,
            peer_did_index: HashMap::new(),
            offline_queue,
            sync_policy,
            inbound_validator: InboundValidator::default(),
            quorum_gate: crate::quorum_gate::QuorumGate::default(),
        }
    }

    /// Persist Blocklace snapshot + frontier into the encrypted pod.
    pub fn flush_pod_blocklace(&self) -> Result<()> {
        crate::pod_runtime::flush_blocklace(&self.pod, &self.blocklace)
    }

    /// Persist Automerge CRDT state into `pod/sync_state.json`.
    pub fn flush_pod_sync_crdt(&self) -> Result<()> {
        crate::pod_runtime::flush_sync_crdt(&self.pod, &self.sync_crdt)
    }

    pub fn register_peer(&mut self, entry: FederationEntry) {
        if let Some(did) = entry.peer_did.as_ref() {
            self.peer_did_index
                .insert(did.trim().to_lowercase(), entry.cert_fingerprint.clone());
        }
        self.federation
            .insert(entry.cert_fingerprint.clone(), entry);
    }

    /// Updates an existing peer (same TLS fingerprint) when pod_directory DID rotates (dev bootstrap).
    pub fn upsert_peer_metadata(
        &mut self,
        cert_fingerprint: &str,
        endpoint_url: &str,
        peer_did: Option<String>,
        peer_pubkey: fstp_core::types::PublicKey,
    ) -> bool {
        let Some(entry) = self.federation.get_mut(cert_fingerprint) else {
            return false;
        };
        if let Some(ref old_did) = entry.peer_did {
            self.peer_did_index.remove(&old_did.trim().to_lowercase());
        }
        if let Some(ref did) = peer_did {
            entry.peer_did = Some(did.trim().to_string());
            self.peer_did_index.insert(
                did.trim().to_lowercase(),
                cert_fingerprint.to_string(),
            );
        } else {
            entry.peer_did = None;
        }
        entry.endpoint = FederationEndpoint::new(endpoint_url, cert_fingerprint);
        entry.peer_pubkey = peer_pubkey;
        true
    }

    pub fn peer_by_did(&self, did: &str) -> Option<&FederationEntry> {
        let fp = self.peer_did_index.get(&did.trim().to_lowercase())?;
        self.federation.get(fp)
    }

    pub fn peer_by_fingerprint(&self, fingerprint: &str) -> Option<&FederationEntry> {
        self.federation.get(fingerprint)
    }
}

pub type SharedState = Arc<RwLock<ServerState>>;

/// Builds the Axum router with all federation endpoints and middleware.
pub fn build_router(state: SharedState) -> Router {
    Router::new()
        .route("/fstp/sync/frontier", post(handlers::frontier_handler))
        .route("/fstp/sync/blocks", post(handlers::blocks_handler))
        .route("/fstp/health", get(handlers::health_handler))
        .route(
            "/fstp/present-credential",
            post(handlers::present_credential_handler),
        )
        .route(
            "/fstp/federation/control",
            post(handlers::federation_control_handler),
        )
        .route(
            "/fstp/federation/identity",
            post(handlers::identity_event_handler),
        )
        .route("/fstp/admin/peers", post(handlers::register_peer_handler))
        .route(
            "/rpc/verify-credential",
            post(handlers::verify_credential_http_handler),
        )
        .route(
            "/pod-agent/v1/federation/present-passport",
            post(integration::present_passport_handler),
        )
        .route(
            "/pod-agent/v1/residences/grant",
            post(crate::residence::grant_residence_handler),
        )
        .route(
            "/pod-agent/v1/residences/revoke",
            post(crate::residence::revoke_residence_handler),
        )
        .route("/fstp/admin/sync", post(integration::admin_sync_handler))
        .route(
            "/fstp/admin/blocklace/status",
            get(super::blocklace_admin::blocklace_status_handler),
        )
        .route(
            "/fstp/admin/blocklace/append",
            post(super::blocklace_admin::blocklace_append_handler),
        )
        .route(
            "/fstp/admin/sync-status",
            get(super::sync_admin::sync_status_handler),
        )
        .route(
            "/fstp/admin/outbound-queue/status",
            get(super::outbound_admin::outbound_queue_status_handler),
        )
        .route(
            "/fstp/admin/trusted-issuers/register",
            post(super::trusted_issuers_admin::register_trusted_issuer_handler),
        )
        .route(
            "/fstp/admin/trusted-issuers/status",
            get(super::trusted_issuers_admin::trusted_issuers_status_handler),
        )
        .route(
            "/fstp/admin/bbs-trusted-issuers/register",
            post(super::bbs_trusted_issuers_admin::register_bbs_issuer_handler),
        )
        .route(
            "/fstp/admin/bbs-trusted-issuers/status",
            get(super::bbs_trusted_issuers_admin::bbs_issuers_status_handler),
        )
        .route(
            "/fstp/admin/transparent-log/status",
            get(super::transparent_admin::transparent_log_status_handler),
        )
        .route(
            "/fstp/admin/transparent-log/query",
            get(super::transparent_admin::transparent_log_query_handler),
        )
        .route(
            "/fstp/admin/quorum/status",
            get(super::quorum_admin::quorum_status_handler),
        )
        .route(
            "/fstp/admin/quorum/setup",
            post(super::quorum_admin::quorum_setup_handler),
        )
        .route(
            "/fstp/admin/quorum/recover",
            post(super::quorum_admin::quorum_recover_handler),
        )
        .route(
            "/fstp/admin/quorum/unlock",
            post(super::quorum_admin::quorum_unlock_handler),
        )
        .route(
            "/fstp/admin/quorum/share/:index",
            get(super::quorum_admin::quorum_export_share_handler),
        )
        .route(
            "/fstp/crypto/bbs/keypair",
            post(super::bbs_crypto::bbs_keypair_handler),
        )
        .route(
            "/fstp/crypto/bbs/sign",
            post(super::bbs_crypto::bbs_sign_handler),
        )
        .route(
            "/fstp/crypto/bbs/derive-proof",
            post(super::bbs_crypto::bbs_derive_proof_handler),
        )
        .route(
            "/fstp/crypto/bbs/verify-proof",
            post(super::bbs_crypto::bbs_verify_proof_handler),
        )
        .route(
            "/fstp/crypto/bbs/ietf/status",
            get(super::bbs_ietf_crypto::bbs_ietf_status_handler),
        )
        .route(
            "/fstp/crypto/bbs/ietf/keypair",
            post(super::bbs_ietf_crypto::bbs_ietf_keypair_handler),
        )
        .route(
            "/fstp/crypto/bbs/ietf/sign",
            post(super::bbs_ietf_crypto::bbs_ietf_sign_handler),
        )
        .route(
            "/fstp/crypto/bbs/ietf/derive-proof",
            post(super::bbs_ietf_crypto::bbs_ietf_derive_proof_handler),
        )
        .route(
            "/fstp/crypto/bbs/ietf/verify-proof",
            post(super::bbs_ietf_crypto::bbs_ietf_verify_proof_handler),
        )
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .with_state(state)
}

/// TLS configuration parameters for the federation server.
pub struct TlsParams {
    pub cert_pem_path: PathBuf,
    pub key_pem_path: PathBuf,
    /// When set, require client certs signed by this CA (P5 mTLS).
    pub client_ca_pem_path: Option<PathBuf>,
}

pub async fn load_tls_config(params: &TlsParams) -> Result<RustlsConfig> {
    let cert_pem = tokio::fs::read(&params.cert_pem_path)
        .await
        .map_err(|e| FstpError::TlsError(format!("read cert: {e}")))?;
    let key_pem = tokio::fs::read(&params.key_pem_path)
        .await
        .map_err(|e| FstpError::TlsError(format!("read key: {e}")))?;

    let server_config = build_server_config(&cert_pem, &key_pem, params.client_ca_pem_path.as_deref())?;
    Ok(RustlsConfig::from_config(Arc::new(server_config)))
}

fn build_server_config(
    cert_pem: &[u8],
    key_pem: &[u8],
    client_ca_path: Option<&std::path::Path>,
) -> Result<rustls::ServerConfig> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &*cert_pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| FstpError::TlsError(format!("parse server cert: {e}")))?
        .into_iter()
        .map(|c| c.into_owned())
        .collect();

    let key = read_private_key(key_pem)?;

    let mut config = if let Some(ca_path) = client_ca_path {
        let ca_pem = std::fs::read(ca_path)
            .map_err(|e| FstpError::TlsError(format!("read client CA {}: {e}", ca_path.display())))?;
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
            let cert = cert.map_err(|e| FstpError::TlsError(format!("parse client CA: {e}")))?;
            roots
                .add(cert.into_owned())
                .map_err(|e| FstpError::TlsError(format!("add client CA: {e}")))?;
        }
        let verifier_builder = WebPkiClientVerifier::builder(roots.into());
        let verifier = if crate::production::client_cert_required() {
            verifier_builder
                .build()
                .map_err(|e| FstpError::TlsError(format!("client verifier: {e}")))?
        } else {
            verifier_builder
                .allow_unauthenticated()
                .build()
                .map_err(|e| FstpError::TlsError(format!("client verifier: {e}")))?
        };
        if crate::production::client_cert_required() {
            tracing::info!(
                ca = %ca_path.display(),
                "mTLS: client certificate required at TLS handshake"
            );
        } else {
            tracing::info!(
                ca = %ca_path.display(),
                "mTLS: optional client certificate (peer routes enforce fingerprint in middleware)"
            );
        };
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| FstpError::TlsError(format!("server config: {e}")))?
    } else {
        tracing::warn!(
            "FSTP_CLIENT_CA_PATH unset — TLS accepts connections without client certificate"
        );
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| FstpError::TlsError(format!("server config: {e}")))?
    };

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

fn read_private_key(key_pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut keys: Vec<PrivateKeyDer<'static>> = rustls_pemfile::read_all(&mut &*key_pem)
        .filter_map(|item| match item.ok()? {
            Item::Sec1Key(k) => Some(
                PrivateKeyDer::try_from(k.secret_sec1_der().to_vec())
                    .map_err(|e| FstpError::TlsError(e.to_string()))
                    .ok()?,
            ),
            Item::Pkcs1Key(k) => Some(
                PrivateKeyDer::try_from(k.secret_pkcs1_der().to_vec())
                    .map_err(|e| FstpError::TlsError(e.to_string()))
                    .ok()?,
            ),
            Item::Pkcs8Key(k) => Some(
                PrivateKeyDer::try_from(k.secret_pkcs8_der().to_vec())
                    .map_err(|e| FstpError::TlsError(e.to_string()))
                    .ok()?,
            ),
            _ => None,
        })
        .collect();
    keys.pop()
        .ok_or_else(|| FstpError::TlsError("no private key in PEM".into()))
}

/// Launches the HTTPS federation server.
pub async fn serve(addr: &str, state: SharedState, tls: TlsParams) -> Result<()> {
    let tls_config = load_tls_config(&tls).await?;

    let router = build_router(state.clone()).layer(axum::middleware::from_fn_with_state(
        state,
        crate::server::auth::auth_middleware,
    ));

    let addr: SocketAddr = addr
        .parse()
        .map_err(|e| FstpError::TlsError(format!("invalid bind address: {e}")))?;

    let acceptor = ClientCertInjectAcceptor::new(tls_config);

    tracing::info!("FSTP federation server listening on {addr}");

    axum_server::bind(addr)
        .acceptor(acceptor)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|e| FstpError::TlsError(e.to_string()))
}
