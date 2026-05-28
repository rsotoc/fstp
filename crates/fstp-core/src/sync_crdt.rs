//! CRDT sync engine with Automerge (AGR-103 / F01-2).
//!
//! Four convergent structures live in one Automerge document:
//! decision rooms (multi-value register), member roster (observed-remove),
//! fractal credit (grow-only counter + signed deductions), record log (append-only).

use std::fmt;
use std::sync::{Mutex, OnceLock};

use automerge::transaction::Transactable;
use automerge::{ActorId, AutoCommit, ObjId, ObjType, ReadDoc, ScalarValue, Value, ROOT};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{ContextualId, FstpError, Result, Sha256Hash};

const SYNC_STATE_VERSION: u32 = 1;
const KEY_DECISION_ROOMS: &str = "decision_rooms";
const KEY_MEMBERS: &str = "members";
const KEY_CREDITS: &str = "credits";
const KEY_RECORDS: &str = "records";

const MEMBER_ACTIVE: &str = "ACTIVE";
const MEMBER_REMOVED: &str = "REMOVED";

/// On-disk envelope stored at `pod/sync_state.json` (encrypted by [`crate::pod_store`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncStateFile {
    pub version: u32,
    pub automerge_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync: Option<DateTime<Utc>>,
    #[serde(default)]
    pub pending_local_events: u32,
    #[serde(default)]
    pub pending_remote_events: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConflictedValue {
    pub field: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConflictSummary {
    pub room_id: Uuid,
    pub fields: Vec<ConflictedValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstanceStatus {
    pub link_id: Uuid,
    pub last_seen: Option<DateTime<Utc>>,
    pub healthy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SyncStatus {
    pub last_sync: Option<DateTime<Utc>>,
    pub pending_local_events: u32,
    pub pending_remote_events: u32,
    pub active_conflicts: Vec<ConflictSummary>,
    pub federated_instances: Vec<InstanceStatus>,
    pub fractal_credit_total: u64,
    pub blocklace_frontier_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionRoomSnapshot {
    pub room_id: Uuid,
    pub status: Option<String>,
    pub current_round: Option<u32>,
    pub last_updated_by: Option<String>,
    pub conflicts: Vec<ConflictedValue>,
    pub blocked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberSnapshot {
    pub citizen_cii: ContextualId,
    pub active: bool,
    pub removed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordEntry {
    pub record_id: Uuid,
    pub record_hash: Sha256Hash,
    pub timestamp_closed: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedDeduction {
    pub amount: u64,
    pub signature_hex: String,
    pub deducted_at: DateTime<Utc>,
}

/// Automerge-backed sync state for institutional pod data (AGR-103).
pub struct SyncCrdtEngine {
    am_doc: Mutex<AutoCommit>,
    pending_local_events: u32,
    pending_remote_events: u32,
    last_sync: Option<DateTime<Utc>>,
}

impl SyncCrdtEngine {
    fn am(&self) -> std::sync::MutexGuard<'_, AutoCommit> {
        self.am_doc
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn am_mut(&self) -> std::sync::MutexGuard<'_, AutoCommit> {
        self.am()
    }

    pub fn new() -> Self {
        let mut doc = load_bootstrap_doc().expect("sync crdt bootstrap");
        doc.set_actor(ActorId::random());
        Self {
            am_doc: Mutex::new(doc),
            pending_local_events: 0,
            pending_remote_events: 0,
            last_sync: None,
        }
    }

    pub fn from_state_file(file: &SyncStateFile) -> Result<Self> {
        if file.version != SYNC_STATE_VERSION {
            return Err(FstpError::PersistenceError(format!(
                "unsupported sync_state version {}",
                file.version
            )));
        }
        let bytes = B64
            .decode(file.automerge_b64.as_bytes())
            .map_err(|e| FstpError::PersistenceError(format!("sync_state base64: {e}")))?;
        let doc = AutoCommit::load(&bytes)
            .map_err(|e| FstpError::PersistenceError(format!("automerge load: {e}")))?;
        Ok(Self {
            am_doc: Mutex::new(doc),
            pending_local_events: file.pending_local_events,
            pending_remote_events: file.pending_remote_events,
            last_sync: file.last_sync,
        })
    }

    pub fn to_state_file(&self) -> Result<SyncStateFile> {
        Ok(SyncStateFile {
            version: SYNC_STATE_VERSION,
            automerge_b64: B64.encode(self.save_bytes()),
            last_sync: self.last_sync,
            pending_local_events: self.pending_local_events,
            pending_remote_events: self.pending_remote_events,
        })
    }

    pub fn save_bytes(&self) -> Vec<u8> {
        self.am_mut().save()
    }

    pub fn merge(&mut self, other: &SyncCrdtEngine) -> Result<()> {
        let mut remote = AutoCommit::load(&other.save_bytes())
            .map_err(|e| FstpError::PersistenceError(format!("merge load remote: {e}")))?;
        self.am_mut()
            .merge(&mut remote)
            .map_err(|e| FstpError::PersistenceError(format!("automerge merge: {e}")))?;
        self.reconcile_observed_remove_members()?;
        self.pending_remote_events = self
            .pending_remote_events
            .saturating_add(other.pending_local_events);
        Ok(())
    }

    pub fn mark_synced(&mut self) {
        self.last_sync = Some(Utc::now());
        self.pending_local_events = 0;
        self.pending_remote_events = 0;
    }

    pub fn bump_local_pending(&mut self) {
        self.pending_local_events = self.pending_local_events.saturating_add(1);
    }

    // ── Decision rooms (multi-value register semantics via get_all) ───────────

    pub fn set_decision_room(
        &mut self,
        room_id: Uuid,
        status: &str,
        current_round: u32,
        last_updated_by: &str,
    ) -> Result<()> {
        let mut doc = self.am_mut();
        let rooms = ensure_root_map(&mut doc, KEY_DECISION_ROOMS)?;
        append_decision_mvr_str(&mut doc, &rooms, room_id, "status", status)?;
        append_decision_mvr_i64(&mut doc, &rooms, room_id, "current_round", current_round as i64)?;
        append_decision_mvr_str(&mut doc, &rooms, room_id, "last_updated_by", last_updated_by)?;
        drop(doc);
        self.bump_local_pending();
        Ok(())
    }

    pub fn decision_room_conflicts(&self, room_id: &Uuid) -> Vec<ConflictedValue> {
        let Some(rooms) = root_map(&self.am(), KEY_DECISION_ROOMS) else {
            return Vec::new();
        };
        if !decision_room_exists(&self.am(), &rooms, room_id) {
            return Vec::new();
        }
        collect_decision_conflicts(&self.am(), &rooms, room_id)
    }

    pub fn decision_room_snapshot(&self, room_id: &Uuid) -> Option<DecisionRoomSnapshot> {
        let rooms = root_map(&self.am(), KEY_DECISION_ROOMS)?;
        if !decision_room_exists(&self.am(), &rooms, room_id) {
            return None;
        }
        let conflicts = self.decision_room_conflicts(room_id);
        Some(DecisionRoomSnapshot {
            room_id: *room_id,
            status: latest_decision_mvr_str(&self.am(), &rooms, room_id, "status"),
            current_round: latest_decision_mvr_u32(&self.am(), &rooms, room_id, "current_round"),
            last_updated_by: latest_decision_mvr_str(&self.am(), &rooms, room_id, "last_updated_by"),
            blocked: !conflicts.is_empty(),
            conflicts,
        })
    }

    pub fn resolve_decision_room(
        &mut self,
        room_id: Uuid,
        status: &str,
        current_round: u32,
        last_updated_by: &str,
    ) -> Result<()> {
        let mut doc = self.am_mut();
        let rooms = ensure_root_map(&mut doc, KEY_DECISION_ROOMS)?;
        clear_decision_mvr(&mut doc, &rooms, room_id, "status")?;
        clear_decision_mvr(&mut doc, &rooms, room_id, "current_round")?;
        clear_decision_mvr(&mut doc, &rooms, room_id, "last_updated_by")?;
        append_decision_mvr_str(&mut doc, &rooms, room_id, "status", status)?;
        append_decision_mvr_i64(&mut doc, &rooms, room_id, "current_round", current_round as i64)?;
        append_decision_mvr_str(&mut doc, &rooms, room_id, "last_updated_by", last_updated_by)?;
        drop(doc);
        self.bump_local_pending();
        Ok(())
    }

    // ── Member roster (observed-remove tombstones) ────────────────────────────

    pub fn roster_upsert(&mut self, citizen_cii: &ContextualId) -> Result<()> {
        if self.member_is_removed(citizen_cii)? {
            return Err(FstpError::PersistenceError(format!(
                "cannot re-activate removed member {}",
                citizen_cii.0
            )));
        }
        let mut doc = self.am_mut();
        let members = ensure_root_map(&mut doc, KEY_MEMBERS)?;
        let entry = ensure_child_map(&mut doc, &members, &citizen_cii.0)?;
        doc.put(&entry, "status", MEMBER_ACTIVE).map_err(am_err)?;
        doc.delete(&entry, "removed_at").ok();
        drop(doc);
        self.bump_local_pending();
        Ok(())
    }

    pub fn roster_remove(&mut self, citizen_cii: &ContextualId) -> Result<()> {
        let mut doc = self.am_mut();
        let members = ensure_root_map(&mut doc, KEY_MEMBERS)?;
        let entry = ensure_child_map(&mut doc, &members, &citizen_cii.0)?;
        doc.put(&entry, "status", MEMBER_REMOVED).map_err(am_err)?;
        doc.put(
            &entry,
            "removed_at",
            Utc::now().timestamp_millis() as i64,
        )
        .map_err(am_err)?;
        drop(doc);
        self.bump_local_pending();
        Ok(())
    }

    pub fn member_is_removed(&self, citizen_cii: &ContextualId) -> Result<bool> {
        let Some(members) = root_map(&self.am(), KEY_MEMBERS) else {
            return Ok(false);
        };
        let Ok(Some((Value::Object(_), entry))) = self.am().get(&members, &citizen_cii.0) else {
            return Ok(false);
        };
        Ok(all_scalars_contain(
            &self.am(),
            &entry,
            "status",
            MEMBER_REMOVED,
        ))
    }

    pub fn member_is_active(&self, citizen_cii: &ContextualId) -> bool {
        let doc = self.am();
        let Some(members) = root_map(&doc, KEY_MEMBERS) else {
            return false;
        };
        member_is_active_in_doc(&doc, &members, citizen_cii)
    }

    pub fn roster_snapshot(&self) -> Vec<MemberSnapshot> {
        let doc = self.am();
        let Some(members) = root_map(&doc, KEY_MEMBERS) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for key in doc.keys(&members) {
            let key_str = key.to_string();
            let citizen = ContextualId::new(key_str);
            let active = member_is_active_in_doc(&doc, &members, &citizen);
            let Ok(Some((Value::Object(_), entry))) = doc.get(&members, &key) else {
                continue;
            };
            let removed_at = scalar_i64(&doc, &entry, "removed_at").and_then(ms_to_datetime);
            out.push(MemberSnapshot {
                citizen_cii: citizen,
                active,
                removed_at,
            });
        }
        out.sort_by(|a, b| a.citizen_cii.0.cmp(&b.citizen_cii.0));
        out
    }

    // ── Fractal credit (grow-only counter + signed deductions list) ───────────

    pub fn credit_increment(&mut self, citizen_cii: &ContextualId, amount: u64) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let mut doc = self.am_mut();
        let credits = ensure_root_map(&mut doc, KEY_CREDITS)?;
        let entry = ensure_child_map(&mut doc, &credits, &citizen_cii.0)?;
        ensure_credit_counter(&mut doc, &entry)?;
        doc.increment(&entry, "balance", amount as i64)
            .map_err(am_err)?;
        drop(doc);
        self.bump_local_pending();
        Ok(())
    }

    pub fn credit_apply_deduction(
        &mut self,
        citizen_cii: &ContextualId,
        deduction: &SignedDeduction,
    ) -> Result<()> {
        if deduction.signature_hex.trim().is_empty() {
            return Err(FstpError::CryptoError(
                "deduction requires non-empty signature".into(),
            ));
        }
        let balance = self.credit_balance(citizen_cii);
        if deduction.amount > balance {
            return Err(FstpError::PersistenceError(
                "deduction exceeds balance".into(),
            ));
        }
        let mut doc = self.am_mut();
        let credits = ensure_root_map(&mut doc, KEY_CREDITS)?;
        let entry = ensure_child_map(&mut doc, &credits, &citizen_cii.0)?;
        let list = ensure_child_list(&mut doc, &entry, "deductions")?;
        let idx = doc.length(&list);
        let item = doc.insert_object(&list, idx, ObjType::Map).map_err(am_err)?;
        doc.put(&item, "amount", deduction.amount as i64)
            .map_err(am_err)?;
        doc.put(&item, "signature_hex", deduction.signature_hex.as_str())
            .map_err(am_err)?;
        doc.put(
            &item,
            "deducted_at",
            deduction.deducted_at.timestamp_millis() as i64,
        )
        .map_err(am_err)?;
        ensure_credit_counter(&mut doc, &entry)?;
        doc.increment(&entry, "balance", -(deduction.amount as i64))
            .map_err(am_err)?;
        drop(doc);
        self.bump_local_pending();
        Ok(())
    }

    pub fn credit_balance(&self, citizen_cii: &ContextualId) -> u64 {
        let Some(credits) = root_map(&self.am(), KEY_CREDITS) else {
            return 0;
        };
        let Ok(Some((Value::Object(_), entry))) = self.am().get(&credits, &citizen_cii.0) else {
            return 0;
        };
        scalar_i64(&self.am(), &entry, "balance").unwrap_or(0).max(0) as u64
    }

    pub fn fractal_credit_total(&self) -> u64 {
        let doc = self.am();
        let Some(credits) = root_map(&doc, KEY_CREDITS) else {
            return 0;
        };
        doc.keys(&credits)
            .filter_map(|key| {
                let Ok(Some((Value::Object(_), entry))) = doc.get(&credits, &key) else {
                    return None;
                };
                scalar_i64(&doc, &entry, "balance").map(|b| b.max(0) as u64)
            })
            .sum()
    }

    // ── Record log (append-only list) ─────────────────────────────────────────

    pub fn record_append(&mut self, entry: &RecordEntry) -> Result<()> {
        let mut doc = self.am_mut();
        let records = ensure_root_map(&mut doc, KEY_RECORDS)?;
        let item = ensure_child_map(&mut doc, &records, &entry.record_id.to_string())?;
        doc.put(&item, "record_id", entry.record_id.to_string())
            .map_err(am_err)?;
        doc.put(&item, "record_hash", entry.record_hash.to_hex())
            .map_err(am_err)?;
        doc.put(
            &item,
            "timestamp_closed",
            entry.timestamp_closed.timestamp_millis() as i64,
        )
        .map_err(am_err)?;
        drop(doc);
        self.bump_local_pending();
        Ok(())
    }

    pub fn record_log(&self) -> Vec<RecordEntry> {
        let doc = self.am();
        let Some(records) = root_map(&doc, KEY_RECORDS) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for key in doc.keys(&records) {
            let Ok(Some((Value::Object(_), item))) = doc.get(&records, &key) else {
                continue;
            };
            let record_id = scalar_str(&doc, &item, "record_id")
                .and_then(|s| Uuid::parse_str(&s).ok())
                .or_else(|| Uuid::parse_str(&key.to_string()).ok());
            let record_hash = scalar_str(&doc, &item, "record_hash")
                .and_then(|s| hex_record_hash(&s));
            let timestamp_closed = scalar_i64(&doc, &item, "timestamp_closed")
                .and_then(ms_to_datetime);
            if let (Some(record_id), Some(record_hash), Some(timestamp_closed)) =
                (record_id, record_hash, timestamp_closed)
            {
                out.push(RecordEntry {
                    record_id,
                    record_hash,
                    timestamp_closed,
                });
            }
        }
        out.sort_by_key(|e| e.timestamp_closed);
        out
    }

    pub fn sync_status(&self, blocklace_frontier_size: u32) -> SyncStatus {
        let active_conflicts = self
            .decision_room_ids()
            .into_iter()
            .filter_map(|id| {
                let conflicts = self.decision_room_conflicts(&id);
                if conflicts.is_empty() {
                    None
                } else {
                    Some(ConflictSummary {
                        room_id: id,
                        fields: conflicts,
                    })
                }
            })
            .collect();

        SyncStatus {
            last_sync: self.last_sync,
            pending_local_events: self.pending_local_events,
            pending_remote_events: self.pending_remote_events,
            active_conflicts,
            federated_instances: Vec::new(),
            fractal_credit_total: self.fractal_credit_total(),
            blocklace_frontier_size,
        }
    }

    fn decision_room_ids(&self) -> Vec<Uuid> {
        let Some(rooms) = root_map(&self.am(), KEY_DECISION_ROOMS) else {
            return Vec::new();
        };
        let mut ids = std::collections::BTreeSet::new();
        for key in self.am().keys(&rooms) {
            if let Some(room_id) = decision_room_id_from_key(&key.to_string()) {
                ids.insert(room_id);
            }
        }
        ids.into_iter().collect()
    }

    /// After merge, tombstones win over concurrent re-additions (observed-remove).
    fn reconcile_observed_remove_members(&mut self) -> Result<()> {
        let mut doc = self.am_mut();
        let members = match root_map(&doc, KEY_MEMBERS) {
            Some(m) => m,
            None => return Ok(()),
        };
        let keys: Vec<_> = doc.keys(&members).collect();
        for key in keys {
            let Ok(Some((Value::Object(_), entry))) = doc.get(&members, &key) else {
                continue;
            };
            if all_scalars_contain(&doc, &entry, "status", MEMBER_REMOVED) {
                doc.put(&entry, "status", MEMBER_REMOVED).map_err(am_err)?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for SyncCrdtEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncCrdtEngine")
            .field("pending_local_events", &self.pending_local_events)
            .field("pending_remote_events", &self.pending_remote_events)
            .field("last_sync", &self.last_sync)
            .finish_non_exhaustive()
    }
}

impl Default for SyncCrdtEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SyncCrdtEngine {
    fn clone(&self) -> Self {
        let bytes = self.save_bytes();
        let doc = AutoCommit::load(&bytes).expect("clone sync crdt");
        Self {
            am_doc: Mutex::new(doc),
            pending_local_events: self.pending_local_events,
            pending_remote_events: self.pending_remote_events,
            last_sync: self.last_sync,
        }
    }
}

fn load_bootstrap_doc() -> Result<AutoCommit> {
    let bytes = bootstrap_doc_bytes();
    AutoCommit::load(bytes).map_err(|e| FstpError::PersistenceError(format!("bootstrap load: {e}")))
}

fn bootstrap_doc_bytes() -> &'static [u8] {
    static BOOTSTRAP: OnceLock<Vec<u8>> = OnceLock::new();
    BOOTSTRAP.get_or_init(|| {
        let mut doc = AutoCommit::new().with_actor(ActorId::random());
        init_root(&mut doc).expect("bootstrap init");
        doc.save()
    })
    .as_slice()
}
fn init_root(doc: &mut AutoCommit) -> Result<()> {
    let _ = ensure_root_map(doc, KEY_DECISION_ROOMS)?;
    let _ = ensure_root_map(doc, KEY_MEMBERS)?;
    let _ = ensure_root_map(doc, KEY_CREDITS)?;
    let _ = ensure_root_map(doc, KEY_RECORDS)?;
    Ok(())
}

fn ensure_root_map(doc: &mut AutoCommit, key: &str) -> Result<ObjId> {
    if let Some(map) = root_map(doc, key) {
        return Ok(map);
    }
    doc.put_object(ROOT, key, ObjType::Map).map_err(am_err)
}

fn ensure_root_list(doc: &mut AutoCommit, key: &str) -> Result<ObjId> {
    if let Some(list) = root_list(doc, key) {
        return Ok(list);
    }
    doc.put_object(ROOT, key, ObjType::List).map_err(am_err)
}

fn ensure_child_map(doc: &mut AutoCommit, parent: &ObjId, key: &str) -> Result<ObjId> {
    if let Ok(Some((Value::Object(_), child))) = doc.get(parent, key) {
        return Ok(child);
    }
    doc.put_object(parent, key, ObjType::Map).map_err(am_err)
}

fn ensure_child_list(doc: &mut AutoCommit, parent: &ObjId, key: &str) -> Result<ObjId> {
    if let Ok(Some((Value::Object(_), child))) = doc.get(parent, key) {
        return Ok(child);
    }
    doc.put_object(parent, key, ObjType::List).map_err(am_err)
}

fn root_map(doc: &AutoCommit, key: &str) -> Option<ObjId> {
    match doc.get(ROOT, key).ok()? {
        Some((Value::Object(ObjType::Map), id)) => Some(id),
        _ => None,
    }
}

fn root_list(doc: &AutoCommit, key: &str) -> Option<ObjId> {
    match doc.get(ROOT, key).ok()? {
        Some((Value::Object(ObjType::List), id)) => Some(id),
        _ => None,
    }
}

fn decision_mvr_key(room_id: Uuid, field: &str) -> String {
    format!("{room_id}::{field}::{}", Uuid::new_v4())
}

fn decision_mvr_prefix(room_id: &Uuid, field: &str) -> String {
    format!("{room_id}::{field}::")
}

fn decision_room_id_from_key(key: &str) -> Option<Uuid> {
    let room_part = key.split("::").next()?;
    Uuid::parse_str(room_part).ok()
}

fn decision_room_exists(doc: &AutoCommit, rooms: &ObjId, room_id: &Uuid) -> bool {
    let prefix = format!("{room_id}::");
    doc.keys(rooms).any(|key| key.to_string().starts_with(&prefix))
}

fn collect_decision_conflicts(
    doc: &AutoCommit,
    rooms: &ObjId,
    room_id: &Uuid,
) -> Vec<ConflictedValue> {
    ["status", "current_round", "last_updated_by"]
        .iter()
        .filter_map(|field| decision_field_conflicts(doc, rooms, room_id, field))
        .collect()
}

fn decision_field_conflicts(
    doc: &AutoCommit,
    rooms: &ObjId,
    room_id: &Uuid,
    field: &str,
) -> Option<ConflictedValue> {
    let prefix = decision_mvr_prefix(room_id, field);
    let mut values = Vec::new();
    for key in doc.keys(rooms) {
        let key_str = key.to_string();
        if !key_str.starts_with(&prefix) {
            continue;
        }
        let Ok(Some((value, _))) = doc.get(rooms, &key) else {
            continue;
        };
        if let Some(text) = scalar_to_string(&value) {
            if !values.contains(&text) {
                values.push(text);
            }
        }
    }
    if values.len() > 1 {
        Some(ConflictedValue {
            field: field.to_string(),
            values,
        })
    } else {
        None
    }
}

fn append_decision_mvr_str(
    doc: &mut AutoCommit,
    rooms: &ObjId,
    room_id: Uuid,
    field: &str,
    value: &str,
) -> Result<()> {
    doc.put(rooms, &decision_mvr_key(room_id, field), value)
        .map_err(am_err)
}

fn append_decision_mvr_i64(
    doc: &mut AutoCommit,
    rooms: &ObjId,
    room_id: Uuid,
    field: &str,
    value: i64,
) -> Result<()> {
    doc.put(rooms, &decision_mvr_key(room_id, field), value)
        .map_err(am_err)
}

fn clear_decision_mvr(
    doc: &mut AutoCommit,
    rooms: &ObjId,
    room_id: Uuid,
    field: &str,
) -> Result<()> {
    let prefix = decision_mvr_prefix(&room_id, field);
    for key in doc
        .keys(rooms)
        .map(|k| k.to_string())
        .collect::<Vec<_>>()
    {
        if key.starts_with(&prefix) {
            doc.delete(rooms, &key).map_err(am_err)?;
        }
    }
    Ok(())
}

fn latest_decision_mvr_str(
    doc: &AutoCommit,
    rooms: &ObjId,
    room_id: &Uuid,
    field: &str,
) -> Option<String> {
    let prefix = decision_mvr_prefix(room_id, field);
    let mut last = None;
    for key in doc.keys(rooms) {
        let key_str = key.to_string();
        if !key_str.starts_with(&prefix) {
            continue;
        }
        let Ok(Some((value, _))) = doc.get(rooms, &key) else {
            continue;
        };
        if let Some(text) = scalar_to_string(&value) {
            last = Some(text);
        }
    }
    last
}

fn latest_decision_mvr_u32(
    doc: &AutoCommit,
    rooms: &ObjId,
    room_id: &Uuid,
    field: &str,
) -> Option<u32> {
    latest_decision_mvr_str(doc, rooms, room_id, field)
        .and_then(|s| s.parse::<u32>().ok())
}

fn member_is_active_in_doc(
    doc: &AutoCommit,
    members: &ObjId,
    citizen_cii: &ContextualId,
) -> bool {
    let Ok(Some((Value::Object(_), entry))) = doc.get(members, &citizen_cii.0) else {
        return false;
    };
    !all_scalars_contain(doc, &entry, "status", MEMBER_REMOVED)
}

fn all_scalars_contain(doc: &AutoCommit, obj: &ObjId, field: &str, needle: &str) -> bool {
    doc.get_all(obj, field)
        .ok()
        .unwrap_or_default()
        .iter()
        .any(|(v, _)| scalar_to_string(v).as_deref() == Some(needle))
}

fn scalar_str(doc: &AutoCommit, obj: &ObjId, field: &str) -> Option<String> {
    doc.get(obj, field)
        .ok()
        .flatten()
        .and_then(|(v, _)| scalar_to_string(&v))
}

fn scalar_u32(doc: &AutoCommit, obj: &ObjId, field: &str) -> Option<u32> {
    scalar_i64(doc, obj, field).and_then(|v| u32::try_from(v).ok())
}

fn scalar_i64(doc: &AutoCommit, obj: &ObjId, field: &str) -> Option<i64> {
    match doc.get(obj, field).ok().flatten()?.0 {
        Value::Scalar(s) => match s.as_ref() {
            ScalarValue::Int(i) => Some(*i),
            ScalarValue::Uint(u) => i64::try_from(*u).ok(),
            ScalarValue::Counter(c) => Some(i64::from(c)),
            _ => None,
        },
        _ => None,
    }
}

fn ensure_credit_counter(doc: &mut AutoCommit, entry: &ObjId) -> Result<()> {
    if doc.get(entry, "balance").ok().flatten().is_some() {
        return Ok(());
    }
    doc.put(entry, "balance", ScalarValue::Counter(0i64.into()))
        .map_err(am_err)?;
    Ok(())
}

fn scalar_to_string(v: &Value) -> Option<String> {
    match v {
        Value::Scalar(s) => match s.as_ref() {
            ScalarValue::Str(st) => Some(st.to_string()),
            ScalarValue::Int(i) => Some(i.to_string()),
            ScalarValue::Uint(u) => Some(u.to_string()),
            ScalarValue::Boolean(b) => Some(b.to_string()),
            _ => None,
        },
        _ => None,
    }
}

fn ms_to_datetime(ms: i64) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp_millis(ms)
}

fn hex_record_hash(hex: &str) -> Option<Sha256Hash> {
    let bytes = hex::decode(hex).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(Sha256Hash::from_bytes(arr))
}

fn am_err(e: automerge::AutomergeError) -> FstpError {
    FstpError::PersistenceError(format!("automerge: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn cii(n: u8) -> ContextualId {
        ContextualId::new(format!("cii:test-{n}"))
    }

    #[test]
    fn decision_room_preserves_conflicts_until_resolved() {
        let mut local = SyncCrdtEngine::new();
        let mut remote = SyncCrdtEngine::new();
        let room = Uuid::new_v4();

        local
            .set_decision_room(room, "VOTING", 1, "local")
            .unwrap();
        remote
            .set_decision_room(room, "DRAFT", 2, "remote")
            .unwrap();

        local.merge(&remote).unwrap();
        let conflicts = local.decision_room_conflicts(&room);
        assert!(!conflicts.is_empty());

        local
            .resolve_decision_room(room, "VOTING", 3, "admin")
            .unwrap();
        assert!(local.decision_room_conflicts(&room).is_empty());
    }

    #[test]
    fn roster_remove_wins_over_concurrent_add() {
        let mut a = SyncCrdtEngine::new();
        let mut b = SyncCrdtEngine::new();
        let member = cii(1);

        a.roster_upsert(&member).unwrap();
        b.roster_upsert(&member).unwrap();
        a.merge(&b).unwrap();

        a.roster_remove(&member).unwrap();
        b.roster_upsert(&member).unwrap();
        a.merge(&b).unwrap();

        assert!(!a.member_is_active(&member));
        assert!(a.roster_upsert(&member).is_err());
    }

    #[test]
    fn credit_deduction_requires_signature() {
        let mut engine = SyncCrdtEngine::new();
        let citizen = cii(9);
        engine.credit_increment(&citizen, 10).unwrap();
        let err = engine
            .credit_apply_deduction(
                &citizen,
                &SignedDeduction {
                    amount: 1,
                    signature_hex: String::new(),
                    deducted_at: Utc::now(),
                },
            )
            .unwrap_err();
        assert!(matches!(err, FstpError::CryptoError(_)));
    }

    #[test]
    fn record_log_merge_is_order_independent() {
        let mut a = SyncCrdtEngine::new();
        let mut b = SyncCrdtEngine::new();
        let e1 = RecordEntry {
            record_id: Uuid::new_v4(),
            record_hash: Sha256Hash::digest(b"one"),
            timestamp_closed: Utc::now(),
        };
        let e2 = RecordEntry {
            record_id: Uuid::new_v4(),
            record_hash: Sha256Hash::digest(b"two"),
            timestamp_closed: Utc::now(),
        };
        a.record_append(&e1).unwrap();
        b.record_append(&e2).unwrap();

        let mut ab = a.clone();
        ab.merge(&b).unwrap();
        let mut ba = b.clone();
        ba.merge(&a).unwrap();

        assert_eq!(ab.record_log(), ba.record_log());
        assert_eq!(ab.record_log().len(), 2);
    }

    #[test]
    fn sync_state_file_roundtrip() {
        let mut engine = SyncCrdtEngine::new();
        engine
            .set_decision_room(Uuid::new_v4(), "OPEN", 1, "admin")
            .unwrap();
        let file = engine.to_state_file().unwrap();
        let loaded = SyncCrdtEngine::from_state_file(&file).unwrap();
        assert_eq!(
            loaded.decision_room_ids().len(),
            engine.decision_room_ids().len()
        );
    }

    proptest! {
        #[test]
        fn merge_commutative_roster(a_ops in 0u8..8, b_ops in 0u8..8) {
            let mut left = SyncCrdtEngine::new();
            let mut right = SyncCrdtEngine::new();
            for i in 0..a_ops {
                let m = cii(i);
                if i % 3 == 0 {
                    let _ = left.roster_remove(&m);
                } else {
                    let _ = left.roster_upsert(&m);
                }
            }
            for i in 0..b_ops {
                let m = cii(i + 100);
                if i % 2 == 0 {
                    let _ = right.roster_upsert(&m);
                } else {
                    let _ = right.roster_remove(&m);
                }
            }
            let mut ab = left.clone();
            ab.merge(&right).unwrap();
            let mut ba = right.clone();
            ba.merge(&left).unwrap();
            prop_assert_eq!(ab.roster_snapshot(), ba.roster_snapshot());
        }

        #[test]
        fn merge_associative_roster(extra in 0u8..5) {
            let mut a = SyncCrdtEngine::new();
            let mut b = SyncCrdtEngine::new();
            let mut c = SyncCrdtEngine::new();
            for i in 0..extra {
                let m = cii(i);
                let _ = a.roster_upsert(&m);
                let _ = b.roster_upsert(&m);
                let _ = c.roster_remove(&m);
            }
            let mut ab_then_c = {
                let mut ab = a.clone();
                ab.merge(&b).unwrap();
                ab.merge(&c).unwrap();
                ab
            };
            let mut a_then_bc = {
                let mut bc = b.clone();
                bc.merge(&c).unwrap();
                let mut merged = a.clone();
                merged.merge(&bc).unwrap();
                merged
            };
            prop_assert_eq!(ab_then_c.roster_snapshot(), a_then_bc.roster_snapshot());
        }

        #[test]
        fn merge_idempotent_roster(seed in 0u8..6) {
            let mut engine = SyncCrdtEngine::new();
            for i in 0..seed {
                let _ = engine.roster_upsert(&cii(i));
            }
            let snapshot = engine.roster_snapshot();
            let mut twice = engine.clone();
            twice.merge(&engine).unwrap();
            prop_assert_eq!(twice.roster_snapshot(), snapshot);
        }
    }
}
