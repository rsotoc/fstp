//! Blocklace DAG substrate (whitepaper §3.3, Property 3.3).
//! Tamper-evident partial order with O(Δ) sync and erasure-compatible integrity.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::message::EventClass;
use crate::types::{Ed25519Sig, FstpError, Result, Sha256Hash};
use crate::utils::now_utc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateAttrs {
    /// Number of participants - not their identities.
    pub participant_count: Option<u32>,
    /// Whether a quorum threshold was reached.
    pub quorum_reached: Option<bool>,
    /// Number of deliberation rounds completed.
    pub rounds_completed: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockPayload {
    /// SHA-256 of the event in the node's data store.
    /// This is a *pointer*, not the event content.
    pub event_hash: Sha256Hash,
    pub event_class: EventClass,
    pub aggregate_attrs: AggregateAttrs,
}

impl BlockPayload {
    /// Canonical JSON serialization for hashing.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("BlockPayload serialization is infallible")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Hash of this block - the node's identity in the DAG.
    pub block_hash: Sha256Hash,
    pub payload: BlockPayload,
    /// Hashes of parent blocks. Empty only for the genesis block.
    pub parents: Vec<Sha256Hash>,
    /// Ed25519 signature over `(payload_bytes || sorted_parent_hashes)`.
    pub signature: Ed25519Sig,
    pub timestamp: DateTime<Utc>,
}

impl Block {
    /// Canonical bytes that the signature covers.
    /// OPTIMIZACIÓN: parent hashes son ordenados rigurosamente por sus bytes crudos para garantizar determinismo cross-platform.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = self.payload.canonical_bytes();
        let mut sorted_parents = self.parents.clone();
        sorted_parents.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for parent in &sorted_parents {
            bytes.extend_from_slice(parent.as_bytes());
        }
        bytes
    }

    /// Computes what the block hash should be.
    pub fn compute_hash(&self) -> Sha256Hash {
        Sha256Hash::digest(&self.signable_bytes())
    }
}

/// Reason an event was erased from the data store.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErasureReason {
    /// Data subject exercised their right to erasure (GDPR Art. 17 / LFPDPPP).
    DataSubjectRequest,
    /// Retention period expired under applicable law.
    RetentionExpiry,
    /// Administrative erasure by institutional decision.
    AdministrativeDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DanglingPointer {
    /// The block - byte-for-byte identical to before erasure.
    pub block: Block,
    pub erasure_timestamp: DateTime<Utc>,
    pub erasure_reason: ErasureReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub total_blocks: usize,
    pub dangling_pointers: usize,
    pub frontier_size: usize,
    pub valid: bool,
    pub corrupted_blocks: Vec<Sha256Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontierExport {
    pub frontier_hashes: Vec<Sha256Hash>,
    pub exported_at: DateTime<Utc>,
    pub total_blocks: usize,
    pub dangling_count: usize,
}

pub trait BlocklaceStore {
    fn append(&mut self, payload: BlockPayload, signature: Ed25519Sig) -> Result<Block>;
    fn frontier(&self) -> Vec<Sha256Hash>;
    fn contains(&self, block_hash: &Sha256Hash) -> bool;
    fn get_block(&self, block_hash: &Sha256Hash) -> Option<&Block>;
    fn verify_chain(&self) -> IntegrityReport;
    fn sync_delta(&self, remote_frontier: &[Sha256Hash]) -> Vec<Block>;
    fn merge_blocks(&mut self, blocks: Vec<Block>) -> Result<()>;
    fn fulfill_erasure(&mut self, event_hash: Sha256Hash, reason: ErasureReason) -> Result<DanglingPointer>;
    fn dangling_pointers(&self) -> Vec<&DanglingPointer>;
    fn export_frontier(&self) -> FrontierExport;
}

// ─────────────────────────────────────────────────────────────────────────────
// In-memory implementation
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct InMemoryBlocklace {
    blocks: HashMap<Sha256Hash, Block>,
    dangling: HashMap<Sha256Hash, DanglingPointer>,
    frontier_cache: HashSet<Sha256Hash>,
}

impl InMemoryBlocklace {
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            dangling: HashMap::new(),
            frontier_cache: HashSet::new(),
        }
    }

    /// OPTIMIZACIÓN COMPLETA: Cálculo incremental en O(N) solo para inicialización reconstructiva o fallback
    pub fn rebuild_frontier_cache(&mut self) {
        let all_parents: HashSet<Sha256Hash> = self.blocks.values()
            .flat_map(|b| b.parents.iter().cloned())
            .collect();

        self.frontier_cache = self.blocks.keys()
            .filter(|h| !all_parents.contains(h))
            .cloned()
            .collect();
    }

    fn ancestors_not_in(&self, start: &Sha256Hash, known: &HashSet<Sha256Hash>) -> Vec<Block> {
        let mut result = Vec::new();
        let mut stack = vec![start.clone()];
        let mut visited = HashSet::new();

        while let Some(hash) = stack.pop() {
            if visited.contains(&hash) || known.contains(&hash) {
                continue;
            }
            visited.insert(hash.clone());
            if let Some(block) = self.blocks.get(&hash) {
                result.push(block.clone());
                for parent in &block.parents {
                    if !visited.contains(parent) && !known.contains(parent) {
                        stack.push(parent.clone());
                    }
                }
            }
        }
        result
    }
}

impl Default for InMemoryBlocklace {
    fn default() -> Self {
        Self::new()
    }
}

impl BlocklaceStore for InMemoryBlocklace {
    fn append(&mut self, payload: BlockPayload, signature: Ed25519Sig) -> Result<Block> {
        let mut parents: Vec<Sha256Hash> = self.frontier_cache.iter().cloned().collect();
        // Parents must be sorted before hashing — same order as signable_bytes() and
        // compute_hash() — so that verify_chain() is consistent for multi-parent blocks.
        parents.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let timestamp = now_utc();

        let mut signable = payload.canonical_bytes();
        for p in &parents {
            signable.extend_from_slice(p.as_bytes());
        }

        let block_hash = Sha256Hash::digest(&signable);

        let block = Block {
            block_hash: block_hash.clone(),
            payload,
            parents,
            signature,
            timestamp,
        };

        self.blocks.insert(block_hash.clone(), block.clone());

        for parent in &block.parents {
            self.frontier_cache.remove(parent);
        }
        self.frontier_cache.insert(block_hash);

        Ok(block)
    }

    fn frontier(&self) -> Vec<Sha256Hash> {
        self.frontier_cache.iter().cloned().collect()
    }

    fn contains(&self, block_hash: &Sha256Hash) -> bool {
        self.blocks.contains_key(block_hash)
    }

    fn get_block(&self, block_hash: &Sha256Hash) -> Option<&Block> {
        self.blocks.get(block_hash)
    }

    fn verify_chain(&self) -> IntegrityReport {
        let mut corrupted = Vec::new();
        for (stored_hash, block) in &self.blocks {
            if block.compute_hash() != *stored_hash {
                corrupted.push(stored_hash.clone());
            }
        }
        IntegrityReport {
            total_blocks: self.blocks.len(),
            dangling_pointers: self.dangling.len(),
            frontier_size: self.frontier_cache.len(),
            valid: corrupted.is_empty(),
            corrupted_blocks: corrupted,
        }
    }

    fn sync_delta(&self, remote_frontier: &[Sha256Hash]) -> Vec<Block> {
        let known: HashSet<Sha256Hash> = remote_frontier.iter().cloned().collect();
        let mut delta = Vec::new();
        let mut unique_blocks = HashSet::new();

        for h in &self.frontier_cache {
            for block in self.ancestors_not_in(h, &known) {
                if unique_blocks.insert(block.block_hash.clone()) {
                    delta.push(block);
                }
            }
        }
        delta
    }

    fn merge_blocks(&mut self, blocks: Vec<Block>) -> Result<()> {
        // Primero insertar todos los bloques
        for block in &blocks {
            let computed = block.compute_hash();
            if computed != block.block_hash {
                return Err(FstpError::CryptoError(format!(
                    "block hash mismatch: stored={}, computed={}",
                    block.block_hash, computed
                )));
            }
            self.blocks.entry(block.block_hash.clone()).or_insert(block.clone());
        }
        // Actualización incremental: solo tocar los bloques nuevos
        for block in &blocks {
            if self.blocks.contains_key(&block.block_hash) {
                for parent in &block.parents {
                    self.frontier_cache.remove(parent);
                }
                self.frontier_cache.insert(block.block_hash.clone());
            }
        }
        Ok(())
    }

    fn fulfill_erasure(&mut self, event_hash: Sha256Hash, reason: ErasureReason) -> Result<DanglingPointer> {
        let block_hash = self.blocks.values()
            .find(|b| b.payload.event_hash == event_hash)
            .map(|b| b.block_hash.clone())
            .ok_or_else(|| FstpError::BlockNotFound(event_hash.clone()))?;

        if self.dangling.contains_key(&block_hash) {
            return Err(FstpError::ErasureAlreadyFulfilled(block_hash));
        }

        let block = self.blocks[&block_hash].clone();
        let dp = DanglingPointer {
            block,
            erasure_timestamp: now_utc(),
            erasure_reason: reason,
        };
        self.dangling.insert(block_hash, dp.clone());
        Ok(dp)
    }

    fn dangling_pointers(&self) -> Vec<&DanglingPointer> {
        self.dangling.values().collect()
    }

    fn export_frontier(&self) -> FrontierExport {
        FrontierExport {
            frontier_hashes: self.frontier(),
            exported_at: now_utc(),
            total_blocks: self.blocks.len(),
            dangling_count: self.dangling.len(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::EventClass;
    use ed25519_dalek::Signature as DalekSig;

    fn dummy_sig() -> Ed25519Sig {
        Ed25519Sig(DalekSig::from_bytes(&[0u8; 64]))
    }

    fn dummy_payload(seed: u8) -> BlockPayload {
        BlockPayload {
            event_hash: Sha256Hash::digest(&[seed]),
            event_class: EventClass::Decision,
            aggregate_attrs: AggregateAttrs {
                participant_count: Some(5),
                quorum_reached: Some(true),
                rounds_completed: Some(1),
            },
        }
    }

    #[test]
    fn append_and_retrieve() {
        let mut bl = InMemoryBlocklace::new();
        let block = bl.append(dummy_payload(1), dummy_sig()).unwrap();
        assert!(bl.contains(&block.block_hash));
        assert_eq!(bl.frontier().len(), 1);
    }

    #[test]
    fn verify_chain_passes_with_multi_parent_blocks() {
        // Simulates two concurrent writers converging: bl_a and bl_b each append
        // one block from genesis, then bl_a merges bl_b's block so the next append
        // has two parents. verify_chain must pass — this was broken before the
        // parent-sorting fix in append().
        let mut bl_a = InMemoryBlocklace::new();
        let mut bl_b = InMemoryBlocklace::new();

        let genesis = bl_a.append(dummy_payload(0), dummy_sig()).unwrap();
        bl_b.merge_blocks(vec![genesis]).unwrap();

        let block_a = bl_a.append(dummy_payload(1), dummy_sig()).unwrap();
        let block_b = bl_b.append(dummy_payload(2), dummy_sig()).unwrap();

        // bl_a now has two frontier blocks → next append produces a multi-parent block
        bl_a.merge_blocks(vec![block_b]).unwrap();
        bl_a.append(dummy_payload(3), dummy_sig()).unwrap();

        let report = bl_a.verify_chain();
        assert!(report.valid, "verify_chain must pass on a multi-parent DAG: {:?}", report.corrupted_blocks);
        assert!(report.corrupted_blocks.is_empty());

        // bl_b receives block_a and also converges
        bl_b.merge_blocks(vec![block_a]).unwrap();
        bl_b.append(dummy_payload(4), dummy_sig()).unwrap();
        let report_b = bl_b.verify_chain();
        assert!(report_b.valid, "verify_chain must pass on bl_b multi-parent DAG");
    }

    #[test]
    fn verify_chain_passes_on_clean_blocklace() {
        let mut bl = InMemoryBlocklace::new();
        bl.append(dummy_payload(1), dummy_sig()).unwrap();
        bl.append(dummy_payload(2), dummy_sig()).unwrap();
        let report = bl.verify_chain();
        assert!(report.valid);
        assert!(report.corrupted_blocks.is_empty());
    }

    #[test]
    fn erasure_does_not_break_chain() {
        let mut bl = InMemoryBlocklace::new();
        let payload = dummy_payload(42);
        let event_hash = payload.event_hash.clone();
        bl.append(payload, dummy_sig()).unwrap();
        bl.append(dummy_payload(43), dummy_sig()).unwrap();

        bl.fulfill_erasure(event_hash, ErasureReason::DataSubjectRequest).unwrap();

        let report = bl.verify_chain();
        assert!(report.valid, "Chain must remain valid after erasure");
        assert_eq!(report.dangling_pointers, 1);
    }

    #[test]
    fn sync_delta_is_exact() {
        let mut bl_a = InMemoryBlocklace::new();
        let mut bl_b = InMemoryBlocklace::new();

        let shared = bl_a.append(dummy_payload(1), dummy_sig()).unwrap();
        bl_b.merge_blocks(vec![shared]).unwrap();

        bl_a.append(dummy_payload(2), dummy_sig()).unwrap();
        let delta = bl_a.sync_delta(&bl_b.frontier());
        assert_eq!(delta.len(), 1, "Delta must contain exactly the missing block");
    }

    #[test]
    fn merge_is_idempotent() {
        let mut bl = InMemoryBlocklace::new();
        let block = bl.append(dummy_payload(1), dummy_sig()).unwrap();
        let count_before = bl.blocks.len();
        bl.merge_blocks(vec![block]).unwrap();
        assert_eq!(bl.blocks.len(), count_before);
    }

    #[test]
    fn merge_rejects_tampered_block() {
        let mut bl_a = InMemoryBlocklace::new();
        let mut block = bl_a.append(dummy_payload(1), dummy_sig()).unwrap();

        block.block_hash = Sha256Hash::digest(b"tampered");

        let mut bl_b = InMemoryBlocklace::new();
        let result = bl_b.merge_blocks(vec![block]);
        assert!(matches!(result, Err(FstpError::CryptoError(_))), "Tampered block must be rejected");
    }

    #[test]
    fn duplicate_erasure_is_rejected() {
        let mut bl = InMemoryBlocklace::new();
        let payload = dummy_payload(7);
        let event_hash = payload.event_hash.clone();
        bl.append(payload, dummy_sig()).unwrap();
        bl.fulfill_erasure(event_hash.clone(), ErasureReason::RetentionExpiry).unwrap();
        let result = bl.fulfill_erasure(event_hash, ErasureReason::RetentionExpiry);
        assert!(matches!(result, Err(FstpError::ErasureAlreadyFulfilled(_))));
    }

    #[test]
    fn frontier_export_counts_are_correct() {
        let mut bl = InMemoryBlocklace::new();
        bl.append(dummy_payload(1), dummy_sig()).unwrap();
        let payload = dummy_payload(2);
        let eh = payload.event_hash.clone();
        bl.append(payload, dummy_sig()).unwrap();
        bl.fulfill_erasure(eh, ErasureReason::AdministrativeDecision).unwrap();

        let export = bl.export_frontier();
        assert_eq!(export.total_blocks, 2);
        assert_eq!(export.dangling_count, 1);
    }
}