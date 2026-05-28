//! Admin routes for CRDT sync status (AGR-103 / F01-2).

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use fstp_core::blocklace::BlocklaceStore;
use fstp_core::sync_crdt::InstanceStatus;

use crate::server::SharedState;

/// **GET /fstp/admin/sync-status** — institutional sync snapshot for desktop shell.
pub async fn sync_status_handler(State(state): State<SharedState>) -> Response {
    let state_read = state.read().await;
    let frontier_size = state_read.blocklace.verify_chain().frontier_size as u32;
    let mut status = state_read.sync_crdt.sync_status(frontier_size);
    status.federated_instances = state_read
        .federation
        .values()
        .map(|peer| InstanceStatus {
            link_id: peer.link_id,
            last_seen: None,
            healthy: true,
        })
        .collect();
    Json(status).into_response()
}
