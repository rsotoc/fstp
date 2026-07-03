//! Admin routes for Velyzor Transparent Log (AGR-104 / F01-3).

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use fstp_core::transparent_log::{LogFilter, LogDirection};
use serde::Deserialize;

use crate::server::SharedState;

#[derive(Debug, Deserialize)]
pub struct TransparentQueryParams {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub direction: Option<String>,
    pub message_type: Option<String>,
    pub peer_cii: Option<String>,
    #[serde(default)]
    pub include_rejected: bool,
}

/// **GET /fstp/admin/transparent-log/status** — integrity + 24h stats.
pub async fn transparent_log_status_handler(State(state): State<SharedState>) -> Response {
    let state_read = state.read().await;
    let integrity = state_read
        .transparent_log
        .verify_integrity()
        .unwrap_or_else(|e| fstp_core::transparent_log::TransparentIntegrityReport {
            valid: false,
            entries_checked: 0,
            first_broken_index: None,
            expected_prev_hash: None,
            actual_prev_hash: None,
            detail: Some(e.to_string()),
        });
    let stats = state_read
        .transparent_log
        .stats(std::time::Duration::from_secs(86_400))
        .unwrap_or_default();
    Json(serde_json::json!({
        "integrity": integrity,
        "stats_24h": stats,
        "log_dir": state_read.transparent_log.log_dir().display().to_string(),
    }))
    .into_response()
}

/// **GET /fstp/admin/transparent-log/query** — filtered entries for desktop shell.
pub async fn transparent_log_query_handler(
    State(state): State<SharedState>,
    Query(params): Query<TransparentQueryParams>,
) -> Response {
    let from = params
        .from
        .unwrap_or_else(|| Utc::now() - chrono::Duration::hours(24));
    let to = params.to.unwrap_or_else(Utc::now);
    let direction = params.direction.as_deref().and_then(parse_direction);
    let filter = LogFilter {
        direction,
        message_type: params.message_type,
        peer_cii: params
            .peer_cii
            .map(fstp_core::types::ContextualId::new),
        include_rejected: params.include_rejected,
    };
    let state_read = state.read().await;
    match state_read.transparent_log.query(from, to, Some(&filter)) {
        Ok(entries) => Json(serde_json::json!({ "entries": entries })).into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

fn parse_direction(raw: &str) -> Option<LogDirection> {
    match raw.trim().to_uppercase().as_str() {
        "SENT" => Some(LogDirection::Sent),
        "RECV" => Some(LogDirection::Recv),
        "RECV_REJECTED" => Some(LogDirection::RecvRejected),
        _ => None,
    }
}
