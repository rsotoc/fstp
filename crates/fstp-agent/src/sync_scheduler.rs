//! Periodic O(Δ) Blocklace sync with registered peers (whitepaper §3.1, §6).
//! Driven by `FSTP_SYNC_INTERVAL_SECS`.

use std::time::Duration;

use fstp_core::offline_queue::OutboundTaskKind;
use tracing::info;

use crate::client::FstpClient;
use crate::server::SharedState;

/// Spawn a background task that syncs every `interval_secs` with each federation peer.
pub fn spawn(state: SharedState, interval_secs: u64) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(interval_secs.max(30));
        info!(secs = interval_secs, "FSTP periodic sync scheduler started");
        loop {
            tokio::time::sleep(interval).await;
            let (peers, client) = {
                let read = state.read().await;
                let peers = read
                    .federation
                    .values()
                    .map(|e| (e.link_id, e.endpoint.clone()))
                    .collect::<Vec<_>>();
                let client = FstpClient::new_with_policy(&read.sync_policy);
                (peers, client)
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
                    Err(e) => {
                        tracing::warn!(
                            link_id = %link_id,
                            error = %e,
                            "Periodic sync failed — enqueueing for offline retry"
                        );
                        let read = state.read().await;
                        if let Err(enq) = read.offline_queue.enqueue(
                            link_id,
                            endpoint,
                            OutboundTaskKind::SyncPeer,
                        ) {
                            tracing::error!(error = %enq, "Failed to enqueue sync task");
                        }
                    }
                }
            }
        }
    });
}
