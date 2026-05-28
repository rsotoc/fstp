//! FSTP Sync Agent binary entry point (whitepaper §3.1 SA, §5 deployment).
//! Launches concurrent mTLS Axum federation server and local gRPC gateway.

mod agora_notify;
mod agora_socket;
mod client;
mod governance_notify;
mod heartbeat_scheduler;
mod outbound;
mod node_identity;
mod outbound_worker;
mod persistence;
mod pod_runtime;
mod platform_util;
mod production;
mod quorum_gate;
mod quorum_service;
mod quorum_store;
mod residence;
mod server;
mod sync_scheduler;
mod trusted_issuers;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::server::{ServerState, TlsParams};
use fstp_core::crypto::NodeSigner;
use fstp_core::identity::{FederationContext, GlobalInstanceId};
use fstp_core::types::{Did, FederationEndpoint};

/// Fails fast when another process (often a stale fstp-agent) already owns the port.
async fn preflight_listen_addr(addr: &str, env_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let socket: SocketAddr = addr
        .parse()
        .map_err(|e| format!("invalid {env_name} '{addr}': {e}"))?;
    tokio::net::TcpListener::bind(socket)
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                format!(
                    "{env_name} {addr} already in use — stop the other fstp-agent (lsof -i :{}) or change the port",
                    socket.port()
                )
            } else {
                format!("{env_name} {addr} bind failed: {e}")
            }
        })?;
    Ok(())
}

/// Loads optional `.env` from cwd or monorepo `fstp/.env` (skipped when FSTP_SKIP_DOTENV=1).
fn load_dotenv_files() -> Option<&'static str> {
    if std::env::var("FSTP_SKIP_DOTENV").is_ok() {
        return None;
    }
    for path in [".env", "fstp/.env"] {
        if !std::path::Path::new(path).exists() {
            continue;
        }
        match dotenvy::from_filename(path) {
            Ok(_) => {
                tracing::info!(path, "Loaded environment from .env file");
                return Some(path);
            }
            Err(e) => tracing::warn!(path, error = %e, "Failed to parse .env file"),
        }
    }
    None
}

fn warn_if_trusted_issuers_commented_in_dotenv(env_path: &str) {
    let Ok(content) = std::fs::read_to_string(env_path) else {
        return;
    };
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#')
            && trimmed.contains("FSTP_TRUSTED_ISSUERS_JSON")
            && trimmed.contains("did:key:")
        {
            tracing::warn!(
                path = env_path,
                "FSTP_TRUSTED_ISSUERS_JSON is commented out in .env — remove the leading # and use single quotes around the JSON"
            );
            return;
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Inicializar el sistema de logs (tracing)
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    tracing::info!("Initializing FSTP Federated Sync Agent...");

    let _ = rustls::crypto::ring::default_provider().install_default();

    let loaded_dotenv = load_dotenv_files();

    production::enforce_production_profile();

    // 2. Derivar la identidad contextual del nodo mediante HKDF-SHA256 (Property 3.1).
    //
    // IKM: en producción debe leerse de la clave privada DID del nodo (p.ej. desde
    // un archivo PEM o un HSM). Aquí se lee de la variable de entorno FSTP_NODE_IKM
    // o se genera aleatoriamente para desarrollo local.
    //
    let ikm = node_identity::resolve_node_ikm().map_err(|e| format!("{e}"))?;

    let node_did_str = if production::is_production_profile() {
        std::env::var("FSTP_NODE_DID").map_err(|_| {
            "FSTP_NODE_DID required in production (see docs/MTLS-PRODUCTION.md)".to_string()
        })?
    } else {
        std::env::var("FSTP_NODE_DID").unwrap_or_else(|_| "did:key:local-dev-node".to_string())
    };

    let signer_seed = node_identity::signer_seed_from_ikm(&ikm);

    let gii = GlobalInstanceId::new(Did::new(&node_did_str), ikm);

    // El CII base del nodo se deriva usando un link_id fijo (identidad raíz del nodo)
    // y la URL de su propio endpoint como contexto.
    let own_endpoint_url =
        std::env::var("FSTP_OWN_URL").unwrap_or_else(|_| "https://localhost:8080".to_string());

    let root_link_id = Uuid::parse_str(
        &std::env::var("FSTP_ROOT_LINK_ID")
            .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000000".to_string()),
    )?;

    let root_context = FederationContext::new(
        root_link_id,
        FederationEndpoint::new(&own_endpoint_url, "self"),
    );

    let own_cii = gii.derive_cii(&root_context);
    tracing::info!(cii = %own_cii, did = %node_did_str, "Node identity established via HKDF derivation");

    // 3. Construir el NodeSigner desde los primeros 32 bytes del IKM.
    let signer = NodeSigner::from_seed(&signer_seed);
    tracing::info!(pubkey = %hex::encode(signer.public_key().0.as_bytes()), "Node signing key ready");

    // 4. Encrypted pod (AGR-101) + Blocklace snapshot inside pod/blocklace/
    let pod = pod_runtime::open_pod()?;
    let blocklace = pod_runtime::load_blocklace(&pod)?;
    let sync_crdt = pod_runtime::load_sync_crdt(&pod)?;
    let transparent_log = pod_runtime::open_transparent_log()?;
    let sync_policy = pod_runtime::load_sync_policy(&pod)?;

    let node_did = Did::new(&node_did_str);
    let identity = pod_runtime::NodeIdentity {
        did: node_did_str.clone(),
        own_url: own_endpoint_url.clone(),
        root_link_id: root_link_id.to_string(),
        own_cii: own_cii.0.clone(),
    };
    pod_runtime::persist_node_identity(&pod, &identity)?;

    let mut server_state = ServerState::new_with_blocklace(
        own_cii.clone(),
        gii.clone(),
        signer,
        blocklace,
        pod.clone(),
        sync_crdt,
        transparent_log,
        node_did.clone(),
        own_endpoint_url.clone(),
        sync_policy,
    );
    server_state
        .issuer_registry
        .register(node_did.clone(), server_state.signer.public_key());

    match trusted_issuers::bootstrap_trusted_issuers(&pod, &mut server_state.issuer_registry) {
        Ok(n) if n > 0 => tracing::info!(count = n, "Trusted issuers bootstrapped"),
        Ok(_) => {
            if let Some(path) = loaded_dotenv {
                warn_if_trusted_issuers_commented_in_dotenv(path);
            } else {
                for path in [".env", "fstp/.env"] {
                    if std::path::Path::new(path).exists() {
                        warn_if_trusted_issuers_commented_in_dotenv(path);
                        break;
                    }
                }
            }
            if !production::is_production_profile() {
                tracing::warn!(
                    "No trusted issuers in pod/env — external verify-credential will fail until FSTP_TRUSTED_ISSUERS_JSON is set"
                );
            }
        }
        Err(e) => return Err(format!("trusted issuers bootstrap: {e}").into()),
    }

    production::validate_production_issuers(&server_state.issuer_registry, &node_did)
        .map_err(|e| format!("{e}"))?;

    if let Ok(Some(cfg)) = quorum_store::load_config(&pod) {
        server_state.quorum_gate.config = Some(cfg);
    }
    production::validate_production_quorum(&server_state.quorum_gate)
        .map_err(|e| format!("{e}"))?;

    let shared_state = Arc::new(RwLock::new(server_state));

    agora_socket::spawn(shared_state.clone());
    heartbeat_scheduler::spawn(shared_state.clone());
    outbound_worker::spawn(shared_state.clone());

    if let Ok(secs) = std::env::var("FSTP_SYNC_INTERVAL_SECS") {
        if let Ok(interval) = secs.parse::<u64>() {
            sync_scheduler::spawn(shared_state.clone(), interval);
        }
    }

    // 4. Configurar TLS
    let tls_params = TlsParams {
        cert_pem_path: std::env::var("FSTP_CERT_PATH")
            .unwrap_or_else(|_| "certs/server.crt".into())
            .into(),
        key_pem_path: std::env::var("FSTP_KEY_PATH")
            .unwrap_or_else(|_| "certs/server.key".into())
            .into(),
        client_ca_pem_path: std::env::var("FSTP_CLIENT_CA_PATH")
            .ok()
            .map(PathBuf::from),
    };

    let http_addr = std::env::var("FSTP_HTTP_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let grpc_addr =
        std::env::var("FSTP_GRPC_ADDR").unwrap_or_else(|_| "127.0.0.1:50051".to_string());

    let http_state = shared_state.clone();
    let grpc_state = shared_state.clone();
    let local_admin_state = shared_state.clone();
    let local_admin_bind = std::env::var("FSTP_LOCAL_ADMIN_BIND")
        .unwrap_or_else(|_| "127.0.0.1:9091".to_string());

    tracing::info!(http = %http_addr, grpc = %grpc_addr, "Launching SA network layers...");

    if let Err(e) = preflight_listen_addr(&http_addr, "FSTP_HTTP_ADDR").await {
        tracing::error!(error = %e, "Cannot start federation HTTP server");
        return Err(e);
    }
    if let Err(e) = preflight_listen_addr(&grpc_addr, "FSTP_GRPC_ADDR").await {
        tracing::error!(error = %e, "Cannot start local gRPC gateway");
        return Err(e);
    }

    // 5. Ejecución concurrente; abortar si cualquier servidor falla
    tokio::select! {
        res = server::local_admin::serve_loopback(&local_admin_bind, local_admin_state) => {
            if let Err(e) = res {
                tracing::error!(error = %e, "Local operator API stopped");
            }
        }
        res = server::serve(&http_addr, http_state, tls_params) => {
            if let Err(e) = res {
                tracing::error!(error = %e, "Catastrophic failure in mTLS Federation HTTP Server");
            }
        }
        res = server::serve_grpc(&grpc_addr, grpc_state) => {
            if let Err(e) = res {
                tracing::error!(error = %e, "Catastrophic failure in Local gRPC Gateway");
            }
        }
    }

    // Flush Blocklace into encrypted pod before exit
    {
        let state_read = shared_state.read().await;
        if let Err(e) = state_read.flush_pod_blocklace() {
            tracing::error!(error = %e, "Failed to flush Blocklace to encrypted pod on shutdown");
        }
        if let Err(e) = state_read.flush_pod_sync_crdt() {
            tracing::error!(error = %e, "Failed to flush CRDT sync state to encrypted pod on shutdown");
        }
    }

    tracing::info!("FSTP Federated Sync Agent shutting down.");
    Ok(())
}
