//! FSTP Sync Agent binary entry point (whitepaper §3.1 SA, §5 deployment).
//! Launches concurrent mTLS Axum federation server and local gRPC gateway.

mod production;
mod persistence;
mod client;
mod outbound;
mod platform_util;
mod agora_notify;
mod residence;
mod sync_scheduler;
mod server;

use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use fstp_core::identity::{FederationContext, GlobalInstanceId};
use fstp_core::types::{Did, FederationEndpoint};
use fstp_core::crypto::NodeSigner;
use crate::server::{ServerState, TlsParams};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Inicializar el sistema de logs (tracing)
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    tracing::info!("Initializing FSTP Federated Sync Agent...");

    production::enforce_production_profile();

    // 2. Derivar la identidad contextual del nodo mediante HKDF-SHA256 (Property 3.1).
    //
    // IKM: en producción debe leerse de la clave privada DID del nodo (p.ej. desde
    // un archivo PEM o un HSM). Aquí se lee de la variable de entorno FSTP_NODE_IKM
    // o se genera aleatoriamente para desarrollo local.
    //
    // TODO(production): load IKM from the node's DID private key bytes, not from
    // an environment variable. The env var approach is acceptable for local dev
    // but must not be used in a deployed federation node.
    let ikm: Vec<u8> = std::env::var("FSTP_NODE_IKM")
        .map(|s| s.into_bytes())
        .unwrap_or_else(|_| {
            tracing::warn!("FSTP_NODE_IKM not set — using ephemeral random IKM. \
                CIIs will change on restart. Set FSTP_NODE_IKM for stable identities.");
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            std::time::SystemTime::now().hash(&mut h);
            h.finish().to_le_bytes().repeat(4) // 32 bytes
        });

    let node_did_str = std::env::var("FSTP_NODE_DID")
        .unwrap_or_else(|_| "did:key:local-dev-node".to_string());

    // Extraer el seed del signer ANTES de mover ikm a GlobalInstanceId.
    let signer_seed: [u8; 32] = {
        let mut seed = [0u8; 32];
        let src = if ikm.len() >= 32 { &ikm[..32] } else { &ikm };
        seed[..src.len()].copy_from_slice(src);
        seed
    };

    let gii = GlobalInstanceId::new(Did::new(&node_did_str), ikm);

    // El CII base del nodo se deriva usando un link_id fijo (identidad raíz del nodo)
    // y la URL de su propio endpoint como contexto.
    let own_endpoint_url = std::env::var("FSTP_OWN_URL")
        .unwrap_or_else(|_| "https://localhost:8080".to_string());

    let root_link_id = Uuid::parse_str(
        &std::env::var("FSTP_ROOT_LINK_ID")
            .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000000".to_string())
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

    // 4. Crear el estado compartido, cargando el Blocklace desde disco si existe
    let blocklace_path = persistence::default_path();
    if let Some(parent) = blocklace_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let blocklace = persistence::load_or_new(&blocklace_path)?;

    let node_did = Did::new(&node_did_str);
    let mut server_state = ServerState::new_with_blocklace(
        own_cii.clone(),
        gii.clone(),
        signer,
        blocklace,
        node_did.clone(),
        own_endpoint_url.clone(),
    );
    server_state
        .issuer_registry
        .register(node_did.clone(), server_state.signer.public_key());

    // Optional: FSTP_TRUSTED_ISSUERS_JSON=[{"did":"did:key:…","pubkeyHex":"…64 hex…"}]
    if let Ok(json) = std::env::var("FSTP_TRUSTED_ISSUERS_JSON") {
        #[derive(serde::Deserialize)]
        struct TrustedIssuer {
            did: String,
            pubkey_hex: String,
        }
        if let Ok(list) = serde_json::from_str::<Vec<TrustedIssuer>>(&json) {
            for entry in list {
                if let Ok(bytes) = hex::decode(entry.pubkey_hex.trim()) {
                    if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                        if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&arr) {
                            server_state.issuer_registry.register(
                                Did::new(&entry.did),
                                fstp_core::types::PublicKey(vk),
                            );
                        }
                    }
                }
            }
        }
    }

    let shared_state = Arc::new(RwLock::new(server_state));

    if let Ok(secs) = std::env::var("FSTP_SYNC_INTERVAL_SECS") {
        if let Ok(interval) = secs.parse::<u64>() {
            sync_scheduler::spawn(shared_state.clone(), interval);
        }
    }

    // 4. Configurar TLS
    let tls_params = TlsParams {
        cert_pem_path: std::env::var("FSTP_CERT_PATH")
            .unwrap_or_else(|_| "certs/server.crt".into()).into(),
        key_pem_path: std::env::var("FSTP_KEY_PATH")
            .unwrap_or_else(|_| "certs/server.key".into()).into(),
    };

    let http_addr = std::env::var("FSTP_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let grpc_addr = std::env::var("FSTP_GRPC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50051".to_string());

    let http_state = shared_state.clone();
    let grpc_state = shared_state.clone();

    tracing::info!(http = %http_addr, grpc = %grpc_addr, "Launching SA network layers...");

    // 5. Ejecución concurrente; abortar si cualquier servidor falla
    tokio::select! {
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

    // Flush Blocklace to disk before exit
    {
        let state_read = shared_state.read().await;
        if let Err(e) = persistence::flush(&state_read.blocklace, &blocklace_path) {
            tracing::error!(error = %e, "Failed to flush Blocklace on shutdown");
        }
    }

    tracing::info!("FSTP Federated Sync Agent shutting down.");
    Ok(())
}