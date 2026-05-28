//! Drains the in-memory offline outbound queue with exponential backoff (AGR-102).

use std::time::Duration;

use fstp_core::message::IdentityEventKind;
use fstp_core::offline_queue::{backoff_delay, OutboundTaskKind};
use tracing::info;

use crate::client::FstpClient;
use crate::outbound::send_identity_event;
use crate::server::SharedState;

const DRAIN_TICK_SECS: u64 = 15;
const BATCH_SIZE: usize = 32;

/// Periodically retries queued sync rounds and heartbeats.
pub fn spawn(state: SharedState) {
    tokio::spawn(async move {
        let http = match crate::outbound::build_http_client() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "Outbound worker: cannot build HTTP client");
                return;
            }
        };
        let client = FstpClient::from_shared_http(http);

        loop {
            tokio::time::sleep(Duration::from_secs(DRAIN_TICK_SECS)).await;

            let batch = {
                let read = state.read().await;
                read.offline_queue.drain_batch(BATCH_SIZE)
            };

            if batch.is_empty() {
                continue;
            }

            info!(count = batch.len(), "Draining offline outbound queue");

            for task in batch {
                let delay = backoff_delay(task.attempts);
                tokio::time::sleep(delay).await;

                let max_retries = {
                    let read = state.read().await;
                    read.sync_policy.max_send_retries
                };

                if task.attempts >= max_retries {
                    tracing::warn!(
                        task_id = %task.id,
                        kind = ?task.kind,
                        attempts = task.attempts,
                        "Outbound task exceeded max retries — dropping"
                    );
                    continue;
                }

                let ok = match task.kind {
                    OutboundTaskKind::SyncPeer => client
                        .synchronize_with_peer(state.clone(), &task.endpoint, task.link_id)
                        .await
                        .is_ok(),
                    OutboundTaskKind::IdentityHeartbeat => {
                        let (signer, own_cii, own_endpoint) = {
                            let read = state.read().await;
                            (
                                read.signer.clone(),
                                read.own_cii.clone(),
                                fstp_core::types::FederationEndpoint::new(
                                    read.own_endpoint_url.clone(),
                                    "self",
                                ),
                            )
                        };
                        send_identity_event(
                            client.http_client(),
                            &signer,
                            &own_cii,
                            &own_endpoint,
                            &task.endpoint,
                            IdentityEventKind::InstanceAlive,
                        )
                        .await
                        .is_ok()
                    }
                };

                if !ok {
                    let read = state.read().await;
                    read.offline_queue.requeue_failed(task);
                }
            }
        }
    });
}
