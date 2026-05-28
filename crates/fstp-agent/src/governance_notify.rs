//! Process `GovernanceEventNotification` from Ágora (AGR-113).

use fstp_core::governance_notification::{GovernanceEventNotification, GovernanceNotifyError};
use fstp_core::types::{Did, PublicKey, RejectionReason};
use fstp_core::BlocklaceStore;

use crate::server::SharedState;

#[derive(Debug, Clone)]
pub struct GovernanceProcessOutcome {
    pub accepted: bool,
    pub block_hash_hex: Option<String>,
    pub error_code: Option<String>,
}

pub async fn process_governance_notification(
    state: &SharedState,
    notification: GovernanceEventNotification,
) -> GovernanceProcessOutcome {
    let message_type = "governance_event_notification";

    if let Err(err) = notification.validate_schema() {
        return reject(state, message_type, None, &err).await;
    }

    let verifying_key = resolve_verifying_pubkey(state).await;
    if let Err(err) = notification.verify_instance_signature(&verifying_key) {
        return reject(state, message_type, None, &err).await;
    }

    let payload = match notification.to_block_payload() {
        Ok(p) => p,
        Err(err) => return reject(state, message_type, None, &err).await,
    };

    let mut state_write = state.write().await;
    let signature = state_write.signer.sign_bytes(&payload.canonical_bytes());

    match state_write.blocklace.append(payload, signature) {
        Ok(block) => {
            state_write.audit.record_inbound(
                message_type,
                Some(state_write.own_cii.clone()),
                None,
                Some(block.block_hash.clone()),
                Some(1),
            );
            tracing::info!(
                block_hash = %block.block_hash,
                process_id = %notification.process_id,
                "Governance notification anchored as EventHash block"
            );
            GovernanceProcessOutcome {
                accepted: true,
                block_hash_hex: Some(block.block_hash.to_hex()),
                error_code: None,
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Governance notification blocklace append failed");
            GovernanceProcessOutcome {
                accepted: false,
                block_hash_hex: None,
                error_code: Some("BLOCKLACE_APPEND_FAILED".into()),
            }
        }
    }
}

async fn reject(
    state: &SharedState,
    message_type: &str,
    peer_cii: Option<fstp_core::types::ContextualId>,
    err: &GovernanceNotifyError,
) -> GovernanceProcessOutcome {
    let state_read = state.read().await;
    state_read.audit.record_inbound_rejected(
        message_type,
        peer_cii,
        format!("{err:?}"),
        err.rejection_reason(),
    );
    GovernanceProcessOutcome {
        accepted: false,
        block_hash_hex: None,
        error_code: Some(rejection_code(err.rejection_reason())),
    }
}

fn rejection_code(reason: RejectionReason) -> String {
    match reason {
        RejectionReason::InvalidSignature => "INVALID_SIGNATURE".into(),
        RejectionReason::SchemaViolation => "SCHEMA_VIOLATION".into(),
        RejectionReason::UnknownMessageType => "UNKNOWN_EVENT_CLASS".into(),
        RejectionReason::TimestampOutOfWindow => "TIMESTAMP_OUT_OF_WINDOW".into(),
        other => format!("{other:?}"),
    }
}

async fn resolve_verifying_pubkey(state: &SharedState) -> PublicKey {
    let state_read = state.read().await;
    if let Ok(did) = std::env::var("FSTP_GOVERNANCE_ISSUER_DID")
        .or_else(|_| std::env::var("AGORA_COMMON_ISSUER_DID"))
    {
        if !did.trim().is_empty() {
            if let Some(pk) = state_read.issuer_registry.lookup(&Did::new(did.trim())) {
                return pk.clone();
            }
        }
    }
    if let Some(pk) = state_read.issuer_registry.lookup(&state_read.node_did) {
        return pk.clone();
    }
    state_read.signer.public_key()
}
