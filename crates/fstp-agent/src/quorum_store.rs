//! Encrypted pod persistence for `config/quorum.json` and Shamir shares (AGR-106).

use fstp_core::pod_store::{EncryptedPodStore, PodPath, PodStore};
use fstp_core::quorum::{QuorumConfig, StoredShare};
use fstp_core::types::{FstpError, Result};

pub fn load_config(pod: &EncryptedPodStore) -> Result<Option<QuorumConfig>> {
    let path = PodPath::quorum_config();
    if !pod.exists(&path) {
        return Ok(None);
    }
    let cfg: QuorumConfig = pod.read(&path)?;
    Ok(Some(cfg))
}

pub fn save_config(pod: &EncryptedPodStore, config: &QuorumConfig) -> Result<()> {
    pod.write(&PodPath::quorum_config(), config)
}

pub fn save_share(pod: &EncryptedPodStore, share: &StoredShare) -> Result<()> {
    pod.write(&PodPath::quorum_share(share.share_index), share)
}

pub fn load_share(pod: &EncryptedPodStore, share_index: u8) -> Result<Option<StoredShare>> {
    let path = PodPath::quorum_share(share_index);
    if !pod.exists(&path) {
        return Ok(None);
    }
    Ok(Some(pod.read(&path)?))
}

pub fn persist_succession_record(
    pod: &EncryptedPodStore,
    record_id: &str,
    record: &fstp_core::quorum::SuccessionRecord,
) -> Result<()> {
    pod.write(&PodPath::succession_record(record_id), record)
}

pub fn ensure_quorum_initialized(pod: &EncryptedPodStore) -> Result<()> {
    let cfg = load_config(pod)?.ok_or_else(|| {
        FstpError::PersistenceError(
            "config/quorum.json missing — run POST /fstp/admin/quorum/setup".into(),
        )
    })?;
    if !cfg.initialized {
        return Err(FstpError::PersistenceError(
            "quorum not initialized — complete POST /fstp/admin/quorum/setup".into(),
        ));
    }
    Ok(())
}
