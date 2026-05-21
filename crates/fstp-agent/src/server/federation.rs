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
use fstp_core::types::{ContextualId, FederationEndpoint, FstpError, LinkId, PublicKey, Result};
use fstp_core::IssuerRegistry;

use super::handlers;
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

    /// Structured audit log (§4.2).
    pub audit: AuditLog,

    /// Node signing key used for signed protocol responses.
    pub signer: NodeSigner,

    /// Trusted issuer DIDs for gRPC credential verification.
    pub issuer_registry: IssuerRegistry,

    /// Local node DID (issuer for outbound present-credential).
    pub node_did: fstp_core::types::Did,

    /// Public base URL of this agent (`FSTP_OWN_URL`).
    pub own_endpoint_url: String,

    /// Secondary index: peer DID (lowercase) → cert fingerprint.
    peer_did_index: HashMap<String, String>,
}

impl ServerState {
    pub fn new(
        own_cii: ContextualId,
        gii: GlobalInstanceId,
        signer: NodeSigner,
        node_did: fstp_core::types::Did,
        own_endpoint_url: String,
    ) -> Self {
        Self {
            own_cii,
            gii,
            federation: HashMap::new(),
            blocklace: InMemoryBlocklace::new(),
            audit: AuditLog::new(),
            signer,
            issuer_registry: IssuerRegistry::default(),
            node_did,
            own_endpoint_url,
            peer_did_index: HashMap::new(),
        }
    }

    pub fn new_with_blocklace(
        own_cii: ContextualId,
        gii: GlobalInstanceId,
        signer: NodeSigner,
        blocklace: InMemoryBlocklace,
        node_did: fstp_core::types::Did,
        own_endpoint_url: String,
    ) -> Self {
        Self {
            own_cii,
            gii,
            federation: HashMap::new(),
            blocklace,
            audit: AuditLog::new(),
            signer,
            issuer_registry: IssuerRegistry::default(),
            node_did,
            own_endpoint_url,
            peer_did_index: HashMap::new(),
        }
    }

    pub fn register_peer(&mut self, entry: FederationEntry) {
        if let Some(did) = entry.peer_did.as_ref() {
            self.peer_did_index
                .insert(did.trim().to_lowercase(), entry.cert_fingerprint.clone());
        }
        self.federation
            .insert(entry.cert_fingerprint.clone(), entry);
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
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .with_state(state)
}

/// TLS configuration parameters for the federation server.
pub struct TlsParams {
    pub cert_pem_path: PathBuf,
    pub key_pem_path: PathBuf,
}

pub async fn load_tls_config(params: &TlsParams) -> Result<RustlsConfig> {
    RustlsConfig::from_pem_file(&params.cert_pem_path, &params.key_pem_path)
        .await
        .map_err(|e| FstpError::TlsError(e.to_string()))
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

    tracing::info!("FSTP federation server listening on {addr}");

    axum_server::bind_rustls(addr, tls_config)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|e| FstpError::TlsError(e.to_string()))
}
