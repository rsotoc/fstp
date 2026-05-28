//! Quorum setup, recovery, and succession (AGR-106).

use chrono::Utc;
use fstp_core::quorum::{
    shamir_combine, shamir_split, sign_with_seed, succession_admin_signable, validate_quorum_config,
    verify_admin_signature, QuorumConfig, QuorumShareSubmission, SuccessionReason, SuccessionRecord,
};
use fstp_core::types::{Did, FstpError, Result};
use uuid::Uuid;

use crate::node_identity;
use crate::quorum_gate::DEFAULT_APPROVAL_TTL_SECS;
use crate::quorum_store;

/// Initialize Shamir shares from the current node seed and persist to the pod.
pub fn setup_quorum(
    pod: &fstp_core::pod_store::EncryptedPodStore,
    mut config: QuorumConfig,
) -> Result<(QuorumConfig, Vec<fstp_core::quorum::StoredShare>)> {
    if config.initialized {
        return Err(FstpError::PersistenceError(
            "quorum already initialized".into(),
        ));
    }
    validate_quorum_config(&config)?;
    let seed = node_signer_seed()?;
    let split = shamir_split(&seed, config.threshold, config.total_shares)?;
    config.initialized = true;
    quorum_store::save_config(pod, &config)?;
    for share in &split.shares {
        quorum_store::save_share(pod, share)?;
    }
    tracing::info!(
        threshold = config.threshold,
        total = config.total_shares,
        "Quorum Shamir shares created and stored in pod"
    );
    Ok((config, split.shares))
}

pub struct RecoverRequest {
    pub shares: Vec<QuorumShareSubmission>,
    pub new_did: String,
    pub reason: SuccessionReason,
    pub admin_signatures: Vec<AdminSignatureInput>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminSignatureInput {
    pub share_index: u8,
    pub signature_hex: String,
}

pub struct RecoverOutcome {
    pub succession: SuccessionRecord,
    pub approval_token: String,
    pub approval_ttl_secs: u64,
}

/// Reconstruct seed, verify admin signatures, persist succession act, grant short-lived approval.
pub fn recover_quorum(
    pod: &fstp_core::pod_store::EncryptedPodStore,
    config: &QuorumConfig,
    old_did: &Did,
    req: RecoverRequest,
) -> Result<RecoverOutcome> {
    if !config.initialized {
        return Err(FstpError::PersistenceError("quorum not initialized".into()));
    }
    let seed = shamir_combine(&req.shares, config.threshold)?;
    let record_id = Uuid::new_v4().to_string();
    let new_did = Did::new(req.new_did.trim());
    let mut quorum_sigs = Vec::new();

    if req.admin_signatures.len() < config.threshold as usize {
        return Err(FstpError::PersistenceError(format!(
            "need at least {} admin signatures",
            config.threshold
        )));
    }
    for sig_input in &req.admin_signatures {
        let admin = config
            .admins
            .iter()
            .find(|a| a.share_index == sig_input.share_index)
            .ok_or_else(|| {
                FstpError::PersistenceError(format!(
                    "unknown share_index {} in admin_signatures",
                    sig_input.share_index
                ))
            })?;
        let msg = succession_admin_signable(&record_id, old_did, &new_did, admin.share_index);
        verify_admin_signature(&admin.public_key_hex, &msg, &sig_input.signature_hex)?;
        quorum_sigs.push(sig_input.signature_hex.clone());
    }

    let succession_msg = format!(
        "fstp-succession-v1|{record_id}|{}|{}",
        old_did.0, new_did.0
    );
    let old_did_signature_hex = sign_with_seed(&seed, succession_msg.as_bytes())?;

    let succession = SuccessionRecord {
        record_id: record_id.clone(),
        old_did: old_did.0.clone(),
        new_did: new_did.0.clone(),
        reason: req.reason,
        timestamp_utc: Utc::now(),
        quorum_signatures_hex: quorum_sigs,
        old_did_signature_hex,
    };
    quorum_store::persist_succession_record(pod, &record_id, &succession)?;

    Ok(RecoverOutcome {
        succession,
        approval_token: String::new(), // filled by caller after grant_approval
        approval_ttl_secs: DEFAULT_APPROVAL_TTL_SECS,
    })
}

/// Maintenance unlock: M shares → approval token without publishing succession.
pub fn unlock_with_shares(config: &QuorumConfig, shares: Vec<QuorumShareSubmission>) -> Result<[u8; 32]> {
    if !config.initialized {
        return Err(FstpError::PersistenceError("quorum not initialized".into()));
    }
    shamir_combine(&shares, config.threshold)
}

fn node_signer_seed() -> Result<[u8; 32]> {
    let ikm = node_identity::resolve_node_ikm()?;
    Ok(node_identity::signer_seed_from_ikm(&ikm))
}
