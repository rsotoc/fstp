//! Encrypted institutional pod integration (AGR-101 / F01-1).
//!
//! Blocklace and node metadata persist under the pod via [`EncryptedPodStore`].
//! Legacy plaintext `FSTP_BLOCKLACE_PATH` is migrated once on first pod open.

use std::path::PathBuf;
use std::sync::Arc;

use fstp_core::blocklace::{BlocklaceStore, InMemoryBlocklace};
use fstp_core::pod_store::{EncryptedPodStore, PodPath, PodStore};
use fstp_core::sync_crdt::{SyncCrdtEngine, SyncStateFile};
use fstp_core::sync_policy::SyncPolicy;
use fstp_core::transparent_log::TransparentLog;
use fstp_core::types::{FstpError, Result};
use serde::{Deserialize, Serialize};

use crate::persistence::{self, BlocklaceSnapshot};

/// Node metadata stored in `pod/identity.json` (no private keys).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeIdentity {
    pub did: String,
    pub own_url: String,
    pub root_link_id: String,
    pub own_cii: String,
}

/// Open or create the encrypted pod and return a shared handle.
pub fn open_pod() -> Result<Arc<EncryptedPodStore>> {
    let root = EncryptedPodStore::resolve_root()?;
    let passphrase = resolve_passphrase()?;
    let production = is_production_profile();

    let store = if root.join("keys/salt.bin").exists() {
        EncryptedPodStore::unlock(&root, &passphrase)?
    } else if production && !env_flag("FSTP_POD_AUTO_INIT") {
        return Err(FstpError::PersistenceError(format!(
            "encrypted pod not initialized at {} — set FSTP_POD_AUTO_INIT=1 on first deploy",
            root.display()
        )));
    } else {
        tracing::info!(root = %root.display(), "Initializing encrypted institutional pod (AGR-101)");
        EncryptedPodStore::initialize(&root, &passphrase)?
    };

    migrate_legacy_blocklace_if_needed(&store)?;
    tracing::info!(root = %root.display(), "Encrypted pod ready");
    Ok(Arc::new(store))
}

pub fn load_blocklace(pod: &EncryptedPodStore) -> Result<InMemoryBlocklace> {
    let path = PodPath::blocklace_snapshot();
    if !pod.exists(&path) {
        return Ok(InMemoryBlocklace::new());
    }

    let snapshot: BlocklaceSnapshot = pod.read(&path)?;
    if snapshot.version != 1 {
        return Err(FstpError::PersistenceError(format!(
            "unsupported blocklace snapshot version {}",
            snapshot.version
        )));
    }

    let mut bl = InMemoryBlocklace::new();
    bl.merge_blocks(snapshot.blocks)
        .map_err(|e| FstpError::PersistenceError(format!("merge blocklace snapshot: {e}")))?;

    let report = bl.verify_chain();
    if !report.valid {
        return Err(FstpError::PersistenceError(format!(
            "blocklace snapshot failed integrity: {} corrupted block(s)",
            report.corrupted_blocks.len()
        )));
    }

    tracing::info!(
        blocks = report.total_blocks,
        frontier = report.frontier_size,
        "Blocklace loaded from encrypted pod"
    );
    Ok(bl)
}

pub fn flush_blocklace(pod: &EncryptedPodStore, bl: &InMemoryBlocklace) -> Result<()> {
    use fstp_core::blocklace::BlocklaceStore;

    let all_blocks = bl.sync_delta(&[]);
    let snapshot = BlocklaceSnapshot {
        version: 1,
        blocks: all_blocks,
    };
    pod.write(&PodPath::blocklace_snapshot(), &snapshot)?;

    let frontier = bl.export_frontier();
    pod.write(&PodPath::blocklace_frontier(), &frontier)?;

    tracing::info!(
        blocks = snapshot.blocks.len(),
        frontier = frontier.frontier_hashes.len(),
        "Blocklace flushed to encrypted pod"
    );
    Ok(())
}

pub fn persist_node_identity(pod: &EncryptedPodStore, identity: &NodeIdentity) -> Result<()> {
    pod.write(&PodPath::identity(), identity)
}

pub fn load_sync_crdt(pod: &EncryptedPodStore) -> Result<SyncCrdtEngine> {
    let path = PodPath::sync_state();
    if !pod.exists(&path) {
        tracing::info!("No sync_state.json in pod — starting empty CRDT engine (AGR-103)");
        return Ok(SyncCrdtEngine::new());
    }
    let file: SyncStateFile = pod.read(&path)?;
    let engine = SyncCrdtEngine::from_state_file(&file)?;
    tracing::info!(
        pending_local = file.pending_local_events,
        pending_remote = file.pending_remote_events,
        "CRDT sync state loaded from encrypted pod"
    );
    Ok(engine)
}

pub fn flush_sync_crdt(pod: &EncryptedPodStore, engine: &SyncCrdtEngine) -> Result<()> {
    let file = engine.to_state_file()?;
    pod.write(&PodPath::sync_state(), &file)?;
    tracing::info!(
        pending_local = file.pending_local_events,
        pending_remote = file.pending_remote_events,
        "CRDT sync state flushed to encrypted pod"
    );
    Ok(())
}

/// Load or initialize `config/sync_policy.json` inside the encrypted pod (AGR-102).
pub fn load_sync_policy(pod: &EncryptedPodStore) -> Result<SyncPolicy> {
    let path = PodPath::sync_policy();
    if !pod.exists(&path) {
        let policy = SyncPolicy::default();
        pod.write(&path, &policy)?;
        tracing::info!(
            heartbeat_mins = policy.heartbeat_interval_mins,
            "Created default sync_policy.json in pod"
        );
        return Ok(policy);
    }
    let policy: SyncPolicy = pod.read(&path)?;
    policy.validate()?;
    tracing::info!(
        heartbeat_mins = policy.heartbeat_interval_mins_clamped(),
        queue_capacity = policy.offline_queue_capacity,
        "Sync policy loaded from pod"
    );
    Ok(policy)
}

pub fn open_transparent_log() -> Result<Arc<TransparentLog>> {
    let root = EncryptedPodStore::resolve_root()?;
    let log_dir = root.join("logs");
    let log = TransparentLog::open(log_dir)?;
    let report = log.verify_integrity()?;
    if !report.valid {
        tracing::warn!(
            detail = ?report.detail,
            index = ?report.first_broken_index,
            "Transparent log integrity check failed on open"
        );
    } else {
        tracing::info!(
            entries = report.entries_checked,
            "Ágora Transparent Log ready"
        );
    }
    Ok(Arc::new(log))
}

pub fn read_node_identity(pod: &EncryptedPodStore) -> Result<Option<NodeIdentity>> {
    if pod.exists(&PodPath::identity()) {
        Ok(Some(pod.read(&PodPath::identity())?))
    } else {
        Ok(None)
    }
}

fn migrate_legacy_blocklace_if_needed(pod: &EncryptedPodStore) -> Result<()> {
    if pod.exists(&PodPath::blocklace_snapshot()) {
        return Ok(());
    }

    if let Some(legacy_path) = legacy_blocklace_path() {
        tracing::info!(
            from = %legacy_path.display(),
            "Migrating legacy plaintext Blocklace into encrypted pod"
        );
        let bl = persistence::load_plain_snapshot(&legacy_path)?;
        flush_blocklace(pod, &bl)?;
    }
    Ok(())
}

fn legacy_blocklace_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("FSTP_BLOCKLACE_PATH") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }
    let default = PathBuf::from("data/blocklace.json");
    if default.exists() {
        return Some(default);
    }
    None
}

fn resolve_passphrase() -> Result<String> {
    if let Ok(p) = std::env::var("FSTP_POD_PASSPHRASE") {
        if p.is_empty() {
            return Err(FstpError::PersistenceError(
                "FSTP_POD_PASSPHRASE must not be empty".into(),
            ));
        }
        return Ok(p);
    }
    if is_production_profile() {
        return Err(FstpError::PersistenceError(
            "FSTP_POD_PASSPHRASE is required when FSTP_PROFILE=production".into(),
        ));
    }
    tracing::warn!(
        "FSTP_POD_PASSPHRASE not set — using dev default (never use in production)"
    );
    Ok("dev-local-passphrase".to_string())
}

fn is_production_profile() -> bool {
    std::env::var("FSTP_PROFILE")
        .map(|p| p.trim().eq_ignore_ascii_case("production"))
        .unwrap_or(false)
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use uuid::Uuid;

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!("fstp-agent-pod-{}", Uuid::new_v4()))
    }

    #[test]
    fn pod_roundtrip_blocklace() {
        let root = temp_root();
        let _ = std::fs::remove_dir_all(&root);
        std::env::set_var("AGORA_POD_ROOT", root.to_string_lossy().as_ref());
        std::env::set_var("FSTP_POD_PASSPHRASE", "test-pass");

        let pod = open_pod().unwrap();
        let bl = InMemoryBlocklace::new();
        flush_blocklace(&pod, &bl).unwrap();
        let loaded = load_blocklace(&pod).unwrap();
        assert!(loaded.frontier().is_empty());

        std::env::remove_var("AGORA_POD_ROOT");
        std::env::remove_var("FSTP_POD_PASSPHRASE");
        let _ = std::fs::remove_dir_all(&root);
    }
}
