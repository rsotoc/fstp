//! Blocklace persistence (whitepaper §3.3, §5 deployment).
//! JSON serialize/deserialize of the in-memory DAG for restart durability.
//!
//! Uses JSON for portability and auditability. In production, replace with
//! a binary format (e.g. MessagePack or a SQLite-backed store) if file size
//! or load time becomes a concern.
//!
//! The persisted file contains only the Blocklace structure — no raw event
//! content, no private keys. Content remains D_raw and never leaves the node.
//!
//! ## Usage
//!
//! At startup:
//!   `let bl = load_or_new(path)?;`
//!
//! At shutdown (or periodically):
//!   `flush(&bl, path)?;`

use std::fs;
use std::path::{Path, PathBuf};

use fstp_core::blocklace::{Block, BlocklaceStore, InMemoryBlocklace};
use fstp_core::types::{FstpError, Result};

/// Persisted snapshot of an `InMemoryBlocklace`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct BlocklaceSnapshot {
    pub version: u32,
    pub blocks: Vec<Block>,
}

/// Load a Blocklace from a **legacy plaintext** path (migration only).
pub fn load_plain_snapshot(path: &Path) -> Result<InMemoryBlocklace> {
    load_or_new(path)
}

/// Load a Blocklace from `path`, or return a fresh empty one if the file
/// does not exist. Returns an error if the file exists but cannot be parsed.
///
/// Prefer [`crate::pod_runtime::load_blocklace`] with an encrypted pod (F01-1).
pub fn load_or_new(path: &Path) -> Result<InMemoryBlocklace> {
    if !path.exists() {
        tracing::info!(path = %path.display(), "No existing Blocklace snapshot — starting fresh");
        return Ok(InMemoryBlocklace::new());
    }

    let data = fs::read(path)
        .map_err(|e| FstpError::PersistenceError(format!("read {}: {e}", path.display())))?;

    let snapshot: BlocklaceSnapshot = serde_json::from_slice(&data)
        .map_err(|e| FstpError::PersistenceError(format!("parse {}: {e}", path.display())))?;

    if snapshot.version != 1 {
        return Err(FstpError::PersistenceError(format!(
            "unsupported snapshot version {} in {}",
            snapshot.version,
            path.display()
        )));
    }

    let mut bl = InMemoryBlocklace::new();
    let block_count = snapshot.blocks.len();
    bl.merge_blocks(snapshot.blocks)
        .map_err(|e| FstpError::PersistenceError(format!("merge snapshot: {e}")))?;

    let report = bl.verify_chain();
    if !report.valid {
        return Err(FstpError::PersistenceError(format!(
            "loaded Blocklace failed integrity check: {} corrupted block(s)",
            report.corrupted_blocks.len()
        )));
    }

    tracing::info!(
        path        = %path.display(),
        blocks      = block_count,
        frontier    = report.frontier_size,
        "Blocklace snapshot loaded and verified"
    );

    Ok(bl)
}

/// Serialize the Blocklace to `path` atomically (write to `.tmp`, then rename).
/// Atomic rename prevents a partial write from corrupting the stored snapshot.
pub fn flush(bl: &InMemoryBlocklace, path: &Path) -> Result<()> {
    use fstp_core::blocklace::BlocklaceStore;

    // Collect all blocks via the public API
    let _frontier = bl.frontier();
    // sync_delta(&[]) returns all blocks (nothing is "known")
    let all_blocks = bl.sync_delta(&[]);

    let snapshot = BlocklaceSnapshot {
        version: 1,
        blocks: all_blocks,
    };

    let json = serde_json::to_vec_pretty(&snapshot)
        .map_err(|e| FstpError::PersistenceError(format!("serialize: {e}")))?;

    // Write to a temp file, then atomically rename
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, &json).map_err(|e| {
        FstpError::PersistenceError(format!("write tmp {}: {e}", tmp_path.display()))
    })?;

    fs::rename(&tmp_path, path)
        .map_err(|e| FstpError::PersistenceError(format!("rename to {}: {e}", path.display())))?;

    tracing::info!(
        path   = %path.display(),
        blocks = snapshot.blocks.len(),
        "Blocklace snapshot flushed to disk"
    );

    Ok(())
}

/// Legacy plaintext path (`FSTP_BLOCKLACE_PATH`). New deployments use the encrypted pod.
pub fn default_path() -> PathBuf {
    std::env::var("FSTP_BLOCKLACE_PATH")
        .unwrap_or_else(|_| "data/blocklace.json".to_string())
        .into()
}
