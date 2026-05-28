//! Periodic `INSTANCE_ALIVE` identity heartbeats to federation peers (AGR-102).

use std::time::Duration;

use fstp_core::message::IdentityEventKind;
use fstp_core::offline_queue::OutboundTaskKind;
use fstp_core::types::FederationEndpoint;
use tracing::info;

use crate::outbound::send_identity_event;
use crate::server::SharedState;

/// Spawn background heartbeats at `sync_policy.heartbeat_interval_secs`.
pub fn spawn(state: SharedState) {
    tokio::spawn(async move {
        loop {
            let (interval_secs, own_cii, own_endpoint, peers, max_retries) = {
                let read = state.read().await;
                (
                    read.sync_policy.heartbeat_interval_secs(),
                    read.own_cii.clone(),
                    FederationEndpoint::new(
                        read.own_endpoint_url.clone(),
                        "self",
                    ),
                    read.federation
                        .values()
                        .map(|e| (e.link_id, e.endpoint.clone(), e.peer_cii.clone()))
                        .collect::<Vec<_>>(),
                    read.sync_policy.max_send_retries,
                )
            };

            tokio::time::sleep(Duration::from_secs(interval_secs)).await;

            if peers.is_empty() {
                continue;
            }

            let http = match crate::outbound::build_http_client() {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "Heartbeat: HTTP client build failed");
                    continue;
                }
            };

            let signer = {
                let read = state.read().await;
                read.signer.clone()
            };

            for (link_id, endpoint, _peer_cii) in peers {
                match send_identity_event(
                    &http,
                    &signer,
                    &own_cii,
                    &own_endpoint,
                    &endpoint,
                    IdentityEventKind::InstanceAlive,
                )
                .await
                {
                    Ok(()) => info!(%link_id, url = %endpoint.url, "Heartbeat INSTANCE_ALIVE sent"),
                    Err(e) => {
                        tracing::warn!(%link_id, error = %e, "Heartbeat failed — enqueueing for retry");
                        let read = state.read().await;
                        if let Err(enq) = read.offline_queue.enqueue(
                            link_id,
                            endpoint,
                            OutboundTaskKind::IdentityHeartbeat,
                        ) {
                            tracing::error!(error = %enq, "Failed to enqueue heartbeat");
                        }
                        drop(read);
                        let _ = max_retries;
                    }
                }
            }
        }
    });
}
