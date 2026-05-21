//! Periodic O(Δ) Blocklace sync with registered peers (whitepaper §3.1, §6).
//! Driven by `FSTP_SYNC_INTERVAL_SECS`.

use std::time::Duration;

use tracing::info;

use crate::client::FstpClient;
use crate::server::SharedState;

/// Spawn a background task that syncs every `interval_secs` with each federation peer.
pub fn spawn(state: SharedState, interval_secs: u64) {
    tokio::spawn(async move {
        let client = FstpClient::new();
        let interval = Duration::from_secs(interval_secs.max(30));
        info!(secs = interval_secs, "FSTP periodic sync scheduler started");
        loop {
            tokio::time::sleep(interval).await;
            let peers: Vec<(uuid::Uuid, fstp_core::types::FederationEndpoint)> = {
                let read = state.read().await;
                read.federation
                    .values()
                    .map(|e| (e.link_id, e.endpoint.clone()))
                    .collect()
            };
            for (link_id, endpoint) in peers {
                match client
                    .synchronize_with_peer(state.clone(), &endpoint, link_id)
                    .await
                {
                    Ok(r) => info!(
                        link_id = %link_id,
                        sent = r.blocks_sent,
                        received = r.blocks_received,
                        "Periodic sync completed"
                    ),
                    Err(e) => tracing::warn!(
                        link_id = %link_id,
                        error = %e,
                        "Periodic sync failed"
                    ),
                }
            }
        }
    });
}
