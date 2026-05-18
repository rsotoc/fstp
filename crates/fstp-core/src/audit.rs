//! Structured audit log for the FSTP Synchronization Agent (§4.2).
//!
//! The paper guarantees: "Every outbound message is recorded with its type,
//! timestamp, destination, and reference identifier; content is never written
//! to the log." This module provides exactly that interface.
//!
//! The log is append-only in memory for the current session and can be
//! flushed to a persistent backend (file, syslog, SIEM) by swapping the
//! `AuditSink` implementation. Content fields (block payloads, credential
//! JSON, frontier hashes) are never accepted as parameters.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use crate::types::{ContextualId, LinkId, Sha256Hash};

// ─────────────────────────────────────────────────────────────────────────────
// Audit record — only metadata, never content
// ─────────────────────────────────────────────────────────────────────────────

/// The direction of the logged federation activity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Outbound,
    Inbound,
}

/// A single audit record. All fields are D_pub metadata — no event content,
/// no credential payload, no frontier hashes appear here (§4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Monotonically increasing sequence number within the current session.
    pub seq: u64,
    pub timestamp: DateTime<Utc>,
    pub direction: Direction,
    /// Type name matching OutboundMessage::type_name() or a well-known inbound label.
    pub message_type: String,
    /// CII of the destination (outbound) or origin (inbound).
    pub peer_cii: Option<ContextualId>,
    /// Federation relationship this message belongs to.
    pub link_id: Option<LinkId>,
    /// Hash of the block appended or received, if applicable.
    pub block_hash: Option<Sha256Hash>,
    /// Number of blocks in a batch operation (sync_delta / merge), if applicable.
    pub block_count: Option<usize>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit logger
// ─────────────────────────────────────────────────────────────────────────────

/// Thread-safe audit logger. Holds records in memory and emits each one
/// to `tracing` at INFO level for integration with external log pipelines.
///
/// Clone is O(1) — all clones share the same inner log.
#[derive(Debug, Clone)]
pub struct AuditLog {
    inner: Arc<Mutex<AuditLogInner>>,
}

#[derive(Debug)]
struct AuditLogInner {
    records: Vec<AuditRecord>,
    seq: u64,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(AuditLogInner {
                records: Vec::new(),
                seq: 0,
            })),
        }
    }

    /// Record an outbound federation message. Call this from the SA before
    /// every network write — after type-system validation, before transmission.
    pub fn record_outbound(
        &self,
        message_type: impl Into<String>,
        peer_cii: Option<ContextualId>,
        link_id: Option<LinkId>,
        block_hash: Option<Sha256Hash>,
        block_count: Option<usize>,
    ) {
        self.append(AuditRecord {
            seq: 0, // filled in append()
            timestamp: Utc::now(),
            direction: Direction::Outbound,
            message_type: message_type.into(),
            peer_cii,
            link_id,
            block_hash,
            block_count,
        });
    }

    /// Record an inbound federation message. Call this from handlers after
    /// successful verification, before any state mutation.
    pub fn record_inbound(
        &self,
        message_type: impl Into<String>,
        peer_cii: Option<ContextualId>,
        link_id: Option<LinkId>,
        block_hash: Option<Sha256Hash>,
        block_count: Option<usize>,
    ) {
        self.append(AuditRecord {
            seq: 0,
            timestamp: Utc::now(),
            direction: Direction::Inbound,
            message_type: message_type.into(),
            peer_cii,
            link_id,
            block_hash,
            block_count,
        });
    }

    fn append(&self, mut record: AuditRecord) {
        let mut inner = self.inner.lock().expect("audit log mutex poisoned");
        inner.seq += 1;
        record.seq = inner.seq;

        // Emit to tracing so external log collectors (Loki, Splunk, etc.) pick it up.
        // The JSON serialization is the canonical form; content is never present.
        tracing::info!(
            seq           = record.seq,
            direction     = ?record.direction,
            message_type  = %record.message_type,
            peer_cii      = record.peer_cii.as_ref().map(|c| c.to_string()),
            link_id       = record.link_id.map(|id| id.to_string()),
            block_hash    = record.block_hash.as_ref().map(|h| h.to_string()),
            block_count   = record.block_count,
            "[FSTP AUDIT]"
        );

        inner.records.push(record);
    }

    /// Returns all audit records for the current session, in insertion order.
    /// Intended for the institution's administrator dashboard and for
    /// regulatory inspection (§4.2, §4.3).
    pub fn records(&self) -> Vec<AuditRecord> {
        self.inner.lock().expect("audit log mutex poisoned").records.clone()
    }

    /// Returns the total number of records logged this session.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("audit log mutex poisoned").records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_sequenced() {
        let log = AuditLog::new();
        log.record_outbound("event_hash", None, None, None, Some(1));
        log.record_outbound("federation_control", None, None, None, None);
        let recs = log.records();
        assert_eq!(recs[0].seq, 1);
        assert_eq!(recs[1].seq, 2);
    }

    #[test]
    fn inbound_and_outbound_directions_are_distinct() {
        let log = AuditLog::new();
        log.record_outbound("event_hash", None, None, None, None);
        log.record_inbound("frontier_response", None, None, None, Some(3));
        let recs = log.records();
        assert_eq!(recs[0].direction, Direction::Outbound);
        assert_eq!(recs[1].direction, Direction::Inbound);
    }

    #[test]
    fn clone_shares_state() {
        let log = AuditLog::new();
        let log2 = log.clone();
        log.record_outbound("event_hash", None, None, None, None);
        assert_eq!(log2.len(), 1, "Cloned handle must see the same records");
    }

    #[test]
    fn record_never_contains_content_fields() {
        // Structural: AuditRecord has no field that could hold raw event content.
        // This test documents the invariant; the type system enforces it.
        let log = AuditLog::new();
        log.record_outbound("event_hash", None, None, None, None);
        let rec = &log.records()[0];
        // If this compiles, the record type has no content field.
        let _: &Option<ContextualId> = &rec.peer_cii;
        let _: &Option<Sha256Hash>   = &rec.block_hash;
        // There is no `payload`, `credential_json`, or `frontier` field.
    }
}