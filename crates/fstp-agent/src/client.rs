//! Federation Sync Client.
//! Initiates the active Frontier Exchange and Block Push protocols (Definition 3.1).

use crate::server::SharedState;
use chrono::Utc;
use fstp_core::blocklace::{Block, BlocklaceStore};
use fstp_core::crypto::verify_response_signature;
use fstp_core::types::{
    ContextualId, FederationEndpoint, FrontierRequest, FrontierResponse, FstpError, LinkId, Result,
    SyncOutcome, SyncResult,
};

pub struct FstpClient {
    /// Cliente HTTP asíncrono reutilizable para el ciclo de vida de la red
    http_client: reqwest::Client,
}

impl FstpClient {
    /// Inicializa una nueva instancia del cliente de sincronización.
    /// En producción, este cliente se configurará para cargar las llaves x509 locales
    /// y ejecutar la autenticación mutua TLS (mTLS).
    pub fn new() -> Self {
        Self {
            http_client: reqwest::Client::new(),
        }
    }

    /// **Protocolo de Sincronización Activa (Trace de Ejecución Sección 5.1)**
    ///
    /// Realiza el ciclo completo en doble vía con una isla remota:
    /// 1. Envía la frontera local al par (`FrontierRequest`).
    /// 2. Procesa la respuesta para inyectar los bloques que nos hacían falta.
    /// 3. Calcula y empuja el delta que le hacía falta al par.
    pub async fn synchronize_with_peer(
        &self,
        state: SharedState,
        peer_endpoint: &FederationEndpoint,
        link_id: LinkId,
    ) -> Result<SyncResult> {
        let _start_time = Utc::now();

        // ── PASO 1: Preparar la Petición de Frontera ──
        let (own_cii, local_frontier) = {
            let state_read = state.read().await;
            let cii = state_guard_cii(&state_read);
            let frontier = state_read.blocklace.frontier();
            (cii, frontier)
        };

        let timestamp = Utc::now();
        let signature = {
            let state_read = state.read().await;
            state_read
                .signer
                .sign_request(&own_cii, &link_id, &local_frontier, &timestamp)
        };

        let request_payload = FrontierRequest {
            sender_cii: own_cii,
            link_id,
            frontier: local_frontier,
            timestamp,
            signature,
        };

        // ── PASO 2: Disparar el Intercambio de Fronteras (HTTP POST) ──
        tracing::info!(peer_url = %peer_endpoint.frontier_url(), "SA Client: Iniciando intercambio de fronteras");

        let http_response = self
            .http_client
            .post(peer_endpoint.frontier_url())
            .json(&request_payload)
            .send()
            .await
            .map_err(|e| FstpError::SyncFailed {
                link_id,
                reason: e.to_string(),
            })?;

        if !http_response.status().is_success() {
            return Err(FstpError::HttpError {
                status: http_response.status().as_u16(),
                body: http_response.text().await.unwrap_or_default(),
            });
        }

        let response_text = http_response
            .text()
            .await
            .map_err(|e| FstpError::SyncFailed {
                link_id,
                reason: e.to_string(),
            })?;

        let response_payload: FrontierResponse =
            serde_json::from_str(&response_text).map_err(FstpError::SerializationError)?;

        let blocks_received_count = response_payload.missing_blocks.len();

        // ── PASO 3: Verificar la firma de la respuesta antes de procesar su contenido ──
        // The response signature binds responder_cii + link_id + frontier + timestamp.
        // We look up the peer's public key from the federation registry (not from the
        // response itself — that would be trivially forgeable).
        {
            let state_read = state.read().await;
            let peer_entry = state_read
                .federation
                .values()
                .find(|e| e.link_id == link_id)
                .ok_or_else(|| FstpError::SyncFailed {
                    link_id,
                    reason: "peer not found in federation registry".into(),
                })?;

            verify_response_signature(
                &response_payload.responder_cii,
                &response_payload.link_id,
                &response_payload.responder_frontier,
                &response_payload.timestamp,
                &response_payload.signature,
                &peer_entry.peer_pubkey,
            )
            .map_err(|e| FstpError::SyncFailed {
                link_id,
                reason: format!("FrontierResponse signature invalid: {e}"),
            })?;
        }

        tracing::info!(link_id = %link_id, "SA Client: FrontierResponse signature verified");

        // ── PASO 4: Fusionar los bloques recibidos en nuestro Grafo local ──
        if !response_payload.missing_blocks.is_empty() {
            let mut state_write = state.write().await;
            state_write
                .blocklace
                .merge_blocks(response_payload.missing_blocks)?;
            tracing::info!(
                count = blocks_received_count,
                "SA Client: Bloques remotos integrados con éxito"
            );
        }

        // ── PASO 5: Calcular y Empujar nuestro Delta hacia el par (Block Push) ──
        // sync_delta is called with the peer's actual frontier so that the DFS
        // stops exactly at blocks the peer already holds — no redundant transmission.
        // This requires a fresh read lock acquired after the merge above.
        let blocks_to_push: Vec<Block> = {
            let state_read = state.read().await;
            state_read
                .blocklace
                .sync_delta(&response_payload.responder_frontier)
        };

        let blocks_sent_count = blocks_to_push.len();

        if !blocks_to_push.is_empty() {
            tracing::info!(peer_url = %peer_endpoint.blocks_url(), count = blocks_sent_count, "SA Client: Empujando delta de bloques");

            let push_response = self
                .http_client
                .post(peer_endpoint.blocks_url())
                .json(&blocks_to_push)
                .send()
                .await
                .map_err(|e| FstpError::SyncFailed {
                    link_id,
                    reason: e.to_string(),
                })?;

            if !push_response.status().is_success() {
                return Err(FstpError::HttpError {
                    status: push_response.status().as_u16(),
                    body: push_response.text().await.unwrap_or_default(),
                });
            }
        }

        // ── PASO 5: Consolidar el Reporte de Auditoría de la Sincronización ──
        Ok(SyncResult {
            link_id,
            peer_cii: response_payload.responder_cii,
            blocks_sent: blocks_sent_count,
            blocks_received: blocks_received_count,
            completed_at: Utc::now(),
            outcome: SyncOutcome::Success,
        })
    }
}

/// Helper para extraer el CII de forma segura respetando las capas asíncronas
fn state_guard_cii(state: &crate::server::ServerState) -> ContextualId {
    state.own_cii.clone()
}
