//! Unix domain socket listener for Ágora → SA governance notifications (AGR-113).

use std::path::PathBuf;
use std::time::Duration;

use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};

use fstp_core::governance_notification::{
    GovernanceEventNotification, GovernanceNotifyError, CONTENT_HASH_LEN, ED25519_SIG_LEN,
};

use crate::governance_notify::process_governance_notification;
use crate::server::SharedState;

pub mod notification_proto {
    include!(concat!(env!("OUT_DIR"), "/agora.notification.rs"));
}

use notification_proto::{GovernanceEventAck, GovernanceEventNotification as WireNotification};

const MAX_FRAME_BYTES: usize = 1_048_576;
const CONNECT_TIMEOUT_SECS: u64 = 5;
const WRITE_TIMEOUT_SECS: u64 = 2;

/// Resolve socket path: `FSTP_AGORA_SOCKET_PATH` or `{AGORA_POD_ROOT}/agent.sock`.
pub fn resolve_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("FSTP_AGORA_SOCKET_PATH") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(root) = std::env::var("AGORA_POD_ROOT") {
        return PathBuf::from(root).join("agent.sock");
    }
    PathBuf::from("/tmp/agora-sync/agent.sock")
}

/// Spawn the background Unix socket accept loop.
pub fn spawn(state: SharedState) {
    if !crate::production::governance_socket_enabled() {
        tracing::info!("Governance notification socket disabled (FSTP_GOVERNANCE_SOCKET_ENABLED)");
        return;
    }
    tokio::spawn(async move {
        let path = resolve_socket_path();
        if let Err(e) = run_listener(state, path.clone()).await {
            tracing::error!(path = %path.display(), error = %e, "Ágora notification socket stopped");
        }
    });
}

async fn run_listener(
    state: SharedState,
    path: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }

    let listener = UnixListener::bind(&path)?;
    info!(path = %path.display(), "Ágora governance notification socket listening (AGR-113)");

    loop {
        let (stream, _) = listener.accept().await?;
        let state_clone = state.clone();
        let path_display = path.display().to_string();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(state_clone, stream).await {
                warn!(path = %path_display, error = %e, "Ágora socket connection error");
            }
        });
    }
}

async fn handle_connection(
    state: SharedState,
    mut stream: UnixStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let frame = tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        read_frame(&mut stream),
    )
    .await
    .map_err(|_| "read timeout")??;

    let wire = WireNotification::decode(frame.as_slice())
        .map_err(|e| format!("protobuf decode: {e}"))?;

    let dto = wire_to_dto(&wire).map_err(|e| format!("dto validation: {e:?}"))?;
    let outcome = process_governance_notification(&state, dto).await;

    let ack = GovernanceEventAck {
        accepted: outcome.accepted,
        block_hash_hex: outcome.block_hash_hex.unwrap_or_default(),
        error_code: outcome.error_code.unwrap_or_default(),
    };
    let ack_bytes = ack.encode_to_vec();

    tokio::time::timeout(
        Duration::from_secs(WRITE_TIMEOUT_SECS),
        write_frame(&mut stream, &ack_bytes),
    )
    .await
    .map_err(|_| "write timeout")??;

    Ok(())
}

async fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(format!("frame length {len} exceeds max {MAX_FRAME_BYTES}").into());
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).await?;
    }
    Ok(payload)
}

async fn write_frame(
    stream: &mut UnixStream,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

fn wire_to_dto(
    wire: &WireNotification,
) -> Result<GovernanceEventNotification, GovernanceNotifyError> {
    if wire.content_hash.len() != CONTENT_HASH_LEN {
        return Err(GovernanceNotifyError::InvalidContentHash);
    }
    if wire.instance_signature.len() != ED25519_SIG_LEN {
        return Err(GovernanceNotifyError::InvalidSignature);
    }
    let mut content_hash = [0u8; CONTENT_HASH_LEN];
    content_hash.copy_from_slice(&wire.content_hash);
    let mut instance_signature = [0u8; ED25519_SIG_LEN];
    instance_signature.copy_from_slice(&wire.instance_signature);

    Ok(GovernanceEventNotification {
        event_class: wire.event_class.clone(),
        timestamp_utc_ms: wire.timestamp_utc_ms,
        process_id: wire.process_id.clone(),
        quorum_met: wire.quorum_met,
        participant_count: wire.participant_count,
        content_hash,
        instance_signature,
    })
}

/// Fuzz-safe decode: malformed frames must not panic the listener task.
pub fn try_decode_frame(bytes: &[u8]) -> Option<WireNotification> {
    if bytes.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if len > MAX_FRAME_BYTES || bytes.len() < 4 + len {
        return None;
    }
    WireNotification::decode(&bytes[4..4 + len]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn fuzz_frame_decode_never_panics(blob in prop::collection::vec(any::<u8>(), 0..4096)) {
            let _ = try_decode_frame(&blob);
        }
    }
}
