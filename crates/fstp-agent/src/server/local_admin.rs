//! Loopback-only operator API for pod-local tasks (desktop Tauri "Pod local" profile).
//! Binds to 127.0.0.1 — never exposed on the public mTLS federation listener.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use tokio::sync::RwLock;

use fstp_core::blocklace::BlocklaceStore;
use crate::server::SharedState;

pub const LOCAL_ADMIN_TOKEN_HEADER: &str = "X-Local-Operator-Token";

#[derive(Clone)]
pub struct LocalAdminState {
    pub shared: SharedState,
    pub expected_token: Arc<String>,
}

#[derive(Serialize)]
pub struct LocalAdminStatus {
    pub own_cii: String,
    pub peer_count: usize,
    pub blocklace_frontier_size: u32,
    pub own_endpoint_url: String,
    pub node_did: String,
}

#[derive(Serialize)]
pub struct LocalAdminPeerView {
    pub cert_fingerprint: String,
    pub peer_cii: String,
    pub link_id: String,
    pub endpoint: String,
    pub peer_did: Option<String>,
}

#[derive(Serialize)]
pub struct LocalAdminPeersResponse {
    pub peers: Vec<LocalAdminPeerView>,
}

#[derive(Serialize)]
pub struct LocalAdminProbeResponse {
    pub fingerprint: String,
    pub reachable: bool,
}

pub fn resolve_pod_root() -> PathBuf {
    std::env::var("VELYZOR_POD_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./pod-data"))
}

pub fn token_file_path() -> PathBuf {
    resolve_pod_root().join("local-admin.token")
}

/// Load or create a random operator token persisted under the pod root.
pub fn load_or_create_operator_token() -> Result<String, String> {
    let path = token_file_path();
    if path.exists() {
        return std::fs::read_to_string(&path)
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("read local admin token: {e}"));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create pod root: {e}"))?;
    }
    let token = uuid::Uuid::new_v4().to_string();
    std::fs::write(&path, &token).map_err(|e| format!("write local admin token: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(&path, perms);
        }
    }
    tracing::info!(path = %path.display(), "Created local operator token file");
    Ok(token)
}

pub fn build_router(state: LocalAdminState) -> Router {
    Router::new()
        .route("/agent-admin/v1/status", get(status_handler))
        .route("/agent-admin/v1/peers", get(peers_handler))
        .route("/agent-admin/v1/peers/:fingerprint/probe", post(probe_handler))
        .route(
            "/agent-admin/v1/blocklace/snapshot",
            get(blocklace_snapshot_handler),
        )
        .route("/agent-admin/v1/residences", get(residences_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state)
}

async fn auth_middleware(
    State(state): State<LocalAdminState>,
    request: Request,
    next: Next,
) -> Response {
    let provided = request
        .headers()
        .get(LOCAL_ADMIN_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided != state.expected_token.as_str() {
        return (StatusCode::UNAUTHORIZED, "Invalid local operator token").into_response();
    }
    next.run(request).await
}

pub async fn status_handler(State(state): State<LocalAdminState>) -> Json<LocalAdminStatus> {
    let read = state.shared.read().await;
    let frontier_size = read.blocklace.verify_chain().frontier_size as u32;
    Json(LocalAdminStatus {
        own_cii: read.own_cii.to_string(),
        peer_count: read.federation.len(),
        blocklace_frontier_size: frontier_size,
        own_endpoint_url: read.own_endpoint_url.clone(),
        node_did: read.node_did.to_string(),
    })
}

pub async fn peers_handler(State(state): State<LocalAdminState>) -> Json<LocalAdminPeersResponse> {
    let read = state.shared.read().await;
    let peers = read
        .federation
        .iter()
        .map(|(fp, entry)| LocalAdminPeerView {
            cert_fingerprint: fp.clone(),
            peer_cii: entry.peer_cii.to_string(),
            link_id: entry.link_id.to_string(),
            endpoint: entry.endpoint.to_string(),
            peer_did: entry.peer_did.clone(),
        })
        .collect();
    Json(LocalAdminPeersResponse { peers })
}

pub async fn probe_handler(
    State(state): State<LocalAdminState>,
    axum::extract::Path(fingerprint): axum::extract::Path<String>,
) -> Json<LocalAdminProbeResponse> {
    let read = state.shared.read().await;
    let reachable = read.federation.contains_key(&fingerprint);
    Json(LocalAdminProbeResponse {
        fingerprint,
        reachable,
    })
}

pub async fn blocklace_snapshot_handler(
    State(state): State<LocalAdminState>,
) -> Json<serde_json::Value> {
    let read = state.shared.read().await;
    let chain = read.blocklace.verify_chain();
    Json(serde_json::json!({
        "frontierSize": chain.frontier_size,
        "valid": chain.valid,
    }))
}

pub async fn residences_handler(State(_state): State<LocalAdminState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "residences": [],
        "message": "Residence listing is pod-local; full detail via Velyzor backend /pod-agent integration."
    }))
}

/// Spawn loopback HTTP server (plain HTTP, localhost only).
pub async fn serve_loopback(
    bind: &str,
    shared: SharedState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let enabled = std::env::var("FSTP_LOCAL_ADMIN_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    if !enabled {
        tracing::info!("Local admin API disabled (FSTP_LOCAL_ADMIN_ENABLED=false)");
        return Ok(());
    }

    let token = load_or_create_operator_token()?;
    let addr: SocketAddr = bind
        .parse()
        .map_err(|e| format!("invalid FSTP_LOCAL_ADMIN_BIND '{bind}': {e}"))?;

    if !addr.ip().is_loopback() {
        return Err(format!("FSTP_LOCAL_ADMIN_BIND must be loopback, got {addr}").into());
    }

    let state = LocalAdminState {
        shared,
        expected_token: Arc::new(token),
    };
    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "Local operator API listening (agent-admin v1)");
    axum::serve(listener, router).await?;
    Ok(())
}
