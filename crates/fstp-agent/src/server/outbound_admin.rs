//! Admin routes for offline outbound queue (AGR-102 / F01-4).

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::server::SharedState;

#[derive(Debug, Serialize)]
pub struct OutboundQueueStatusResponse {
    pub queued: usize,
    pub dropped_total: u64,
    pub drained_total: u64,
    pub heartbeat_interval_secs: u64,
    pub max_send_retries: u32,
}

/// **GET /fstp/admin/outbound-queue/status** — offline queue metrics for desktop shell.
pub async fn outbound_queue_status_handler(State(state): State<SharedState>) -> Response {
    let state_read = state.read().await;
    let stats = state_read.offline_queue.stats();
    Json(OutboundQueueStatusResponse {
        queued: stats.queued,
        dropped_total: stats.dropped_total,
        drained_total: stats.drained_total,
        heartbeat_interval_secs: state_read.sync_policy.heartbeat_interval_secs(),
        max_send_retries: state_read.sync_policy.max_send_retries,
    })
    .into_response()
}
