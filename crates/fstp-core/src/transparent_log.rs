//! Ágora Transparent Log — hash-linked JSONL audit trail (AGR-104 / F01-3).
//!
//! Records federation traffic metadata only (no message content, GII, or PII).
//! Entries form a tamper-evident chain via `prev_hash` / `entry_hash`.

use std::fmt;

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};

use uuid::Uuid;

use crate::audit::{AuditRecord, Direction};
use crate::types::{ContextualId, FstpError, RejectionReason, Result, Sha256Hash};

pub const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
pub const ACTIVE_LOG_NAME: &str = "transparent_log.jsonl";
pub const CHAIN_ANCHOR_NAME: &str = "transparent_log.chain_anchor";
pub const DEFAULT_MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
pub const DEFAULT_MAX_ROTATED_FILES: usize = 30;

/// Traffic direction per AGR-104 (distinct from in-memory [`crate::audit::Direction`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LogDirection {
    Sent,
    Recv,
    RecvRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransparentRejectionReason {
    InvalidSignature,
    UnknownCii,
    UnknownType,
    TimestampSkew,
    SchemaViolation,
    CertFingerprintMismatch,
}

impl From<RejectionReason> for TransparentRejectionReason {
    fn from(reason: RejectionReason) -> Self {
        match reason {
            RejectionReason::InvalidSignature => Self::InvalidSignature,
            RejectionReason::UnknownCii => Self::UnknownCii,
            RejectionReason::UnknownMessageType => Self::UnknownType,
            RejectionReason::TimestampOutOfWindow => Self::TimestampSkew,
            RejectionReason::SchemaViolation => Self::SchemaViolation,
            RejectionReason::CertFingerprintMismatch => Self::CertFingerprintMismatch,
        }
    }
}

/// One line in `logs/transparent_log.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub direction: LogDirection,
    pub message_type: String,
    pub message_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_cii: Option<String>,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<TransparentRejectionReason>,
    pub prev_hash: String,
    pub entry_hash: String,
}

#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    pub direction: Option<LogDirection>,
    pub message_type: Option<String>,
    pub peer_cii: Option<ContextualId>,
    pub include_rejected: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogStats {
    pub total_entries: u64,
    pub sent: u64,
    pub recv: u64,
    pub recv_rejected: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransparentIntegrityReport {
    pub valid: bool,
    pub entries_checked: u64,
    pub first_broken_index: Option<u64>,
    pub expected_prev_hash: Option<String>,
    pub actual_prev_hash: Option<String>,
    pub detail: Option<String>,
}

/// Append-only hash-linked transparent log on disk.
pub struct TransparentLog {
    log_dir: PathBuf,
    active_path: PathBuf,
    chain_tip: Mutex<String>,
    max_file_bytes: u64,
    max_rotated_files: usize,
    rotation_seq: Mutex<u64>,
    write_lock: Mutex<()>,
}

impl fmt::Debug for TransparentLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransparentLog")
            .field("log_dir", &self.log_dir)
            .finish_non_exhaustive()
    }
}

impl TransparentLog {
    pub fn open(log_dir: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_limits(
            log_dir,
            DEFAULT_MAX_FILE_BYTES,
            DEFAULT_MAX_ROTATED_FILES,
        )
    }

    pub fn open_with_limits(
        log_dir: impl AsRef<Path>,
        max_file_bytes: u64,
        max_rotated_files: usize,
    ) -> Result<Self> {
        let log_dir = log_dir.as_ref().to_path_buf();
        fs::create_dir_all(&log_dir).map_err(|e| io_err("create logs dir", e))?;
        let active_path = log_dir.join(ACTIVE_LOG_NAME);
        let rotation_seq = detect_rotation_seq(&log_dir);
        let chain_tip = restore_chain_tip(&log_dir, &active_path)?;
        Ok(Self {
            log_dir,
            active_path,
            chain_tip: Mutex::new(chain_tip),
            max_file_bytes,
            max_rotated_files,
            rotation_seq: Mutex::new(rotation_seq),
            write_lock: Mutex::new(()),
        })
    }

    pub fn log_dir(&self) -> &Path {
        &self.log_dir
    }

    pub fn append_entry(&self, mut entry: LogEntry) -> Result<LogEntry> {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.maybe_rotate()?;

        let mut tip = self
            .chain_tip
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        entry.prev_hash = tip.clone();
        entry.entry_hash = compute_entry_hash(&entry)?;
        forbid_sensitive_fields(&entry)?;

        let line = serde_json::to_string(&entry)
            .map_err(|e| FstpError::PersistenceError(format!("log json: {e}")))?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.active_path)
            .map_err(|e| io_err("open log append", e))?;
        writeln!(file, "{line}").map_err(|e| io_err("append log line", e))?;
        file.sync_all().ok();

        *tip = entry.entry_hash.clone();
        Ok(entry)
    }

    pub fn append_sent(
        &self,
        message_type: impl Into<String>,
        message_id: impl Into<String>,
        peer_cii: Option<ContextualId>,
        summary: impl Into<String>,
    ) -> Result<LogEntry> {
        self.append_entry(LogEntry {
            timestamp: Utc::now(),
            direction: LogDirection::Sent,
            message_type: message_type.into(),
            message_id: message_id.into(),
            peer_cii: peer_cii.map(|c| c.0),
            summary: summary.into(),
            rejection_reason: None,
            prev_hash: String::new(),
            entry_hash: String::new(),
        })
    }

    pub fn append_recv(
        &self,
        message_type: impl Into<String>,
        message_id: impl Into<String>,
        peer_cii: Option<ContextualId>,
        summary: impl Into<String>,
    ) -> Result<LogEntry> {
        self.append_entry(LogEntry {
            timestamp: Utc::now(),
            direction: LogDirection::Recv,
            message_type: message_type.into(),
            message_id: message_id.into(),
            peer_cii: peer_cii.map(|c| c.0),
            summary: summary.into(),
            rejection_reason: None,
            prev_hash: String::new(),
            entry_hash: String::new(),
        })
    }

    pub fn append_recv_rejected(
        &self,
        message_type: impl Into<String>,
        message_id: impl Into<String>,
        peer_cii: Option<ContextualId>,
        summary: impl Into<String>,
        reason: RejectionReason,
    ) -> Result<LogEntry> {
        self.append_entry(LogEntry {
            timestamp: Utc::now(),
            direction: LogDirection::RecvRejected,
            message_type: message_type.into(),
            message_id: message_id.into(),
            peer_cii: peer_cii.map(|c| c.0),
            summary: summary.into(),
            rejection_reason: Some(reason.into()),
            prev_hash: String::new(),
            entry_hash: String::new(),
        })
    }

    /// Mirror an in-memory [`AuditRecord`] into the transparent log.
    pub fn append_audit_record(&self, record: &AuditRecord) -> Result<LogEntry> {
        let direction = match record.direction {
            Direction::Outbound => LogDirection::Sent,
            Direction::Inbound => LogDirection::Recv,
        };
        let message_id = format!("seq-{}", record.seq);
        let summary = audit_summary(record);
        self.append_entry(LogEntry {
            timestamp: record.timestamp,
            direction,
            message_type: record.message_type.clone(),
            message_id,
            peer_cii: record.peer_cii.as_ref().map(|c| c.0.clone()),
            summary,
            rejection_reason: None,
            prev_hash: String::new(),
            entry_hash: String::new(),
        })
    }

    pub fn query(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        filter: Option<&LogFilter>,
    ) -> Result<Vec<LogEntry>> {
        let mut out = Vec::new();
        for entry in self.read_all_entries()? {
            if entry.timestamp < from || entry.timestamp > to {
                continue;
            }
            if let Some(f) = filter {
                if !matches_filter(&entry, f) {
                    continue;
                }
            }
            out.push(entry);
        }
        Ok(out)
    }

    pub fn stats(&self, period: Duration) -> Result<LogStats> {
        let to = Utc::now();
        let from = to - chrono::Duration::from_std(period).unwrap_or(chrono::Duration::zero());
        let entries = self.query(from, to, None)?;
        let mut stats = LogStats::default();
        stats.total_entries = entries.len() as u64;
        for e in entries {
            match e.direction {
                LogDirection::Sent => stats.sent += 1,
                LogDirection::Recv => stats.recv += 1,
                LogDirection::RecvRejected => stats.recv_rejected += 1,
            }
        }
        Ok(stats)
    }

    pub fn export(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> Result<Vec<u8>> {
        let entries = self.query(from, to, None)?;
        serde_json::to_vec_pretty(&entries)
            .map_err(|e| FstpError::PersistenceError(format!("export json: {e}")))
    }

    pub fn verify_integrity(&self) -> Result<TransparentIntegrityReport> {
        let entries = self.read_all_entries()?;
        let mut expected_prev = read_chain_anchor(&self.log_dir);
        for (idx, entry) in entries.iter().enumerate() {
            if entry.prev_hash != expected_prev {
                return Ok(TransparentIntegrityReport {
                    valid: false,
                    entries_checked: idx as u64,
                    first_broken_index: Some(idx as u64),
                    expected_prev_hash: Some(expected_prev),
                    actual_prev_hash: Some(entry.prev_hash.clone()),
                    detail: Some("prev_hash chain break".into()),
                });
            }
            let recomputed = compute_entry_hash(entry)?;
            if recomputed != entry.entry_hash {
                return Ok(TransparentIntegrityReport {
                    valid: false,
                    entries_checked: idx as u64,
                    first_broken_index: Some(idx as u64),
                    expected_prev_hash: None,
                    actual_prev_hash: None,
                    detail: Some("entry_hash mismatch (tampered entry)".into()),
                });
            }
            if let Err(e) = forbid_sensitive_fields(entry) {
                return Ok(TransparentIntegrityReport {
                    valid: false,
                    entries_checked: idx as u64,
                    first_broken_index: Some(idx as u64),
                    expected_prev_hash: None,
                    actual_prev_hash: None,
                    detail: Some(e.to_string()),
                });
            }
            expected_prev = entry.entry_hash.clone();
        }
        Ok(TransparentIntegrityReport {
            valid: true,
            entries_checked: entries.len() as u64,
            first_broken_index: None,
            expected_prev_hash: None,
            actual_prev_hash: None,
            detail: None,
        })
    }

    fn read_all_entries(&self) -> Result<Vec<LogEntry>> {
        let mut entries = Vec::new();
        let mut rotated: Vec<PathBuf> = list_log_segments(&self.log_dir)?
            .into_iter()
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n != ACTIVE_LOG_NAME)
            })
            .collect();
        rotated.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
        for path in rotated {
            entries.extend(read_entries_from_path(&path)?);
        }
        if self.active_path.exists() {
            entries.extend(read_entries_from_path(&self.active_path)?);
        }
        Ok(entries)
    }

    fn maybe_rotate(&self) -> Result<()> {
        if !self.active_path.exists() {
            return Ok(());
        }
        let len = fs::metadata(&self.active_path)
            .map_err(|e| io_err("stat active log", e))?
            .len();
        if len < self.max_file_bytes {
            return Ok(());
        }
        let rotated_name = {
            let mut seq = self
                .rotation_seq
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *seq += 1;
            format!("transparent_log.{seq:016}.jsonl")
        };
        let rotated_path = self.log_dir.join(&rotated_name);
        fs::rename(&self.active_path, &rotated_path)
            .map_err(|e| io_err("rotate log file", e))?;
        let gz_path = self.log_dir.join(format!("{rotated_name}.gz"));
        compress_file_gzip(&rotated_path, &gz_path)?;
        fs::remove_file(&rotated_path).map_err(|e| io_err("remove rotated plain", e))?;
        self.prune_rotated()?;
        Ok(())
    }

    fn prune_rotated(&self) -> Result<()> {
        let mut gz_files: Vec<PathBuf> = fs::read_dir(&self.log_dir)
            .map_err(|e| io_err("read logs dir", e))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("transparent_log.") && n.ends_with(".jsonl.gz"))
                    .unwrap_or(false)
            })
            .collect();
        gz_files.sort();
        if gz_files.len() <= self.max_rotated_files {
            return Ok(());
        }
        let remove_count = gz_files.len() - self.max_rotated_files;
        let to_remove: Vec<_> = gz_files.into_iter().take(remove_count).collect();
        if let Some(last_removed) = to_remove.last() {
            if let Ok(entries) = read_entries_from_path(last_removed) {
                if let Some(last) = entries.last() {
                    write_chain_anchor(&self.log_dir, &last.entry_hash)?;
                }
            }
        }
        for path in to_remove {
            fs::remove_file(path).map_err(|e| io_err("prune old log", e))?;
        }
        Ok(())
    }
}

fn audit_summary(record: &AuditRecord) -> String {
    let mut parts = vec![record.message_type.to_uppercase()];
    if let Some(count) = record.block_count {
        parts.push(format!("blocks={count}"));
    }
    if let Some(hash) = &record.block_hash {
        parts.push(format!("ref={}", &hash.to_hex()[..16]));
    }
    if let Some(link) = record.link_id {
        parts.push(format!("link={link}"));
    }
    parts.join(" | ")
}

fn matches_filter(entry: &LogEntry, filter: &LogFilter) -> bool {
    if !filter.include_rejected && entry.direction == LogDirection::RecvRejected {
        return false;
    }
    if let Some(dir) = filter.direction {
        if entry.direction != dir {
            return false;
        }
    }
    if let Some(ref mt) = filter.message_type {
        if &entry.message_type != mt {
            return false;
        }
    }
    if let Some(ref peer) = filter.peer_cii {
        if entry.peer_cii.as_deref() != Some(peer.0.as_str()) {
            return false;
        }
    }
    true
}

#[derive(Serialize)]
struct EntryDigest<'a> {
    timestamp: DateTime<Utc>,
    direction: LogDirection,
    message_type: &'a str,
    message_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_cii: Option<&'a str>,
    summary: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rejection_reason: Option<&'a TransparentRejectionReason>,
    prev_hash: &'a str,
}

fn compute_entry_hash(entry: &LogEntry) -> Result<String> {
    let digest = EntryDigest {
        timestamp: entry.timestamp,
        direction: entry.direction,
        message_type: &entry.message_type,
        message_id: &entry.message_id,
        peer_cii: entry.peer_cii.as_deref(),
        summary: &entry.summary,
        rejection_reason: entry.rejection_reason.as_ref(),
        prev_hash: &entry.prev_hash,
    };
    let json = serde_json::to_string(&digest)
        .map_err(|e| FstpError::PersistenceError(format!("digest json: {e}")))?;
    Ok(Sha256Hash::digest(json.as_bytes()).to_hex())
}

/// Reject entries that embed forbidden metadata (AGR-104 acceptance test).
pub fn forbid_sensitive_fields(entry: &LogEntry) -> Result<()> {
    const FORBIDDEN: &[&str] = &[
        "gii:",
        "GII:",
        "@",
        "password",
        "private_key",
        "mnemonic",
        "\"payload\"",
        "\"content\"",
        "\"credential_json\"",
        "\"frontier_hashes\"",
    ];
    let blob = serde_json::to_string(entry)
        .map_err(|e| FstpError::PersistenceError(format!("forbid check json: {e}")))?;
    let lower = blob.to_lowercase();
    for needle in FORBIDDEN {
        if lower.contains(&needle.to_lowercase()) {
            return Err(FstpError::PersistenceError(format!(
                "forbidden transparent log field content: {needle}"
            )));
        }
    }
    if let Some(peer) = &entry.peer_cii {
        if peer.contains("gii:") {
            return Err(FstpError::PersistenceError(
                "peer_cii must not contain GII".into(),
            ));
        }
    }
    Ok(())
}

fn read_chain_anchor(log_dir: &Path) -> String {
    let path = log_dir.join(CHAIN_ANCHOR_NAME);
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| GENESIS_HASH.to_string())
}

fn write_chain_anchor(log_dir: &Path, hash: &str) -> Result<()> {
    fs::write(log_dir.join(CHAIN_ANCHOR_NAME), hash).map_err(|e| io_err("write anchor", e))
}

fn detect_rotation_seq(log_dir: &Path) -> u64 {
    list_log_segments(log_dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|path| {
            let name = path.file_name()?.to_str()?;
            let rest = name.strip_prefix("transparent_log.")?;
            let seq_str = rest.strip_suffix(".jsonl.gz").or_else(|| rest.strip_suffix(".jsonl"))?;
            seq_str.parse::<u64>().ok()
        })
        .max()
        .unwrap_or(0)
}

fn restore_chain_tip(log_dir: &Path, active_path: &Path) -> Result<String> {
    let mut rotated: Vec<PathBuf> = list_log_segments(log_dir)?
        .into_iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n != ACTIVE_LOG_NAME)
        })
        .collect();
    rotated.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    let mut tip = GENESIS_HASH.to_string();
    for path in rotated {
        for entry in read_entries_from_path(&path)? {
            tip = entry.entry_hash;
        }
    }
    if active_path.exists() {
        for entry in read_entries_from_path(active_path)? {
            tip = entry.entry_hash;
        }
    }
    Ok(tip)
}

fn read_last_entry_hash(path: &Path) -> Result<String> {
    let file = File::open(path).map_err(|e| io_err("open log for tip", e))?;
    let reader = BufReader::new(file);
    let mut last = GENESIS_HASH.to_string();
    for line in reader.lines() {
        let line = line.map_err(|e| io_err("read log line", e))?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: LogEntry = serde_json::from_str(&line)
            .map_err(|e| FstpError::PersistenceError(format!("parse log line: {e}")))?;
        last = entry.entry_hash;
    }
    Ok(last)
}

fn read_entries_from_path(path: &Path) -> Result<Vec<LogEntry>> {
    let reader: Box<dyn BufRead> = if path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with(".gz"))
    {
        let file = File::open(path).map_err(|e| io_err("open gz log", e))?;
        Box::new(BufReader::new(GzDecoder::new(file)))
    } else {
        let file = File::open(path).map_err(|e| io_err("open log segment", e))?;
        Box::new(BufReader::new(file))
    };
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|e| io_err("read segment line", e))?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: LogEntry = serde_json::from_str(&line)
            .map_err(|e| FstpError::PersistenceError(format!("parse segment: {e}")))?;
        entries.push(entry);
    }
    Ok(entries)
}

fn list_log_segments(log_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    if !log_dir.exists() {
        return Ok(paths);
    }
    for entry in fs::read_dir(log_dir).map_err(|e| io_err("list logs", e))? {
        let entry = entry.map_err(|e| io_err("dir entry", e))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ACTIVE_LOG_NAME {
            paths.push(entry.path());
        } else if name.starts_with("transparent_log.") && name.ends_with(".jsonl.gz") {
            paths.push(entry.path());
        } else if name.starts_with("transparent_log.") && name.ends_with(".jsonl") {
            paths.push(entry.path());
        }
    }
    Ok(paths)
}

fn compress_file_gzip(src: &Path, dst: &Path) -> Result<()> {
    let mut input = File::open(src).map_err(|e| io_err("open for gzip", e))?;
    let mut buf = Vec::new();
    input
        .read_to_end(&mut buf)
        .map_err(|e| io_err("read for gzip", e))?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&buf)
        .map_err(|e| io_err("gzip write", e))?;
    let compressed = encoder.finish().map_err(|e| io_err("gzip finish", e))?;
    let mut out = File::create(dst).map_err(|e| io_err("create gz", e))?;
    out.write_all(&compressed)
        .map_err(|e| io_err("write gz", e))?;
    Ok(())
}

fn io_err(ctx: &str, e: std::io::Error) -> FstpError {
    FstpError::PersistenceError(format!("{ctx}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use uuid::Uuid;

    fn temp_log_dir() -> PathBuf {
        std::env::temp_dir().join(format!("fstp-tlog-{}", Uuid::new_v4()))
    }

    #[test]
    fn hash_chain_and_verify_integrity() {
        let dir = temp_log_dir();
        let log = TransparentLog::open(&dir).unwrap();
        log.append_sent("record_hash", "msg-1", None, "DECISION #1")
            .unwrap();
        log.append_recv(
            "federation_event",
            "msg-2",
            Some(ContextualId::new("cii:peer-a")),
            "INSTANCE_ALIVE",
        )
        .unwrap();
        let report = log.verify_integrity().unwrap();
        assert!(report.valid, "{report:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn detects_tampered_entry_hash() {
        let dir = temp_log_dir();
        let log = TransparentLog::open(&dir).unwrap();
        let entry = log
            .append_sent("record_hash", "msg-1", None, "ok")
            .unwrap();
        let active = dir.join(ACTIVE_LOG_NAME);
        let mut tampered = entry;
        tampered.entry_hash = "ff".repeat(32);
        fs::write(&active, format!("{}\n", serde_json::to_string(&tampered).unwrap()))
            .unwrap();
        let report = log.verify_integrity().unwrap();
        assert!(!report.valid);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn detects_removed_intermediate_entry() {
        let dir = temp_log_dir();
        let log = TransparentLog::open(&dir).unwrap();
        log.append_sent("a", "1", None, "one").unwrap();
        log.append_sent("b", "2", None, "two").unwrap();
        log.append_sent("c", "3", None, "three").unwrap();
        let active = dir.join(ACTIVE_LOG_NAME);
        let lines: Vec<_> = fs::read_to_string(&active)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        fs::write(&active, format!("{}\n{}", lines[0], lines[2])).unwrap();
        let report = log.verify_integrity().unwrap();
        assert!(!report.valid);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn forbidden_fields_rejected_on_append() {
        let dir = temp_log_dir();
        let log = TransparentLog::open(&dir).unwrap();
        let mut bad = log
            .append_sent("record_hash", "ok", None, "clean")
            .unwrap();
        bad.summary = "contains gii:secret".into();
        let err = log.append_entry(bad).unwrap_err();
        assert!(err.to_string().contains("forbidden"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_updates_chain_anchor() {
        let dir = temp_log_dir();
        let log = TransparentLog::open_with_limits(&dir, 256, 2).unwrap();
        for i in 0..6 {
            log.append_sent("t", format!("{i}"), None, format!("s{i}"))
                .unwrap();
        }
        let anchor = read_chain_anchor(&dir);
        assert_ne!(anchor, GENESIS_HASH);
        let report = log.verify_integrity().unwrap();
        assert!(report.valid, "{report:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_preserves_chain() {
        let dir = temp_log_dir();
        let log = Arc::new(TransparentLog::open_with_limits(&dir, 256, 30).unwrap());
        for i in 0..20 {
            log.append_sent("record_hash", format!("m-{i}"), None, format!("entry {i}"))
                .unwrap();
        }
        assert!(dir.read_dir().unwrap().count() >= 2);
        let report = log.verify_integrity().unwrap();
        assert!(report.valid, "{report:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn recv_rejected_has_reason() {
        let dir = temp_log_dir();
        let log = TransparentLog::open(&dir).unwrap();
        let entry = log
            .append_recv_rejected(
                "credential_presentation",
                "bad-1",
                None,
                "invalid VC",
                RejectionReason::InvalidSignature,
            )
            .unwrap();
        assert_eq!(entry.direction, LogDirection::RecvRejected);
        assert_eq!(
            entry.rejection_reason,
            Some(TransparentRejectionReason::InvalidSignature)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_is_standalone_json() {
        let dir = temp_log_dir();
        let log = TransparentLog::open(&dir).unwrap();
        log.append_sent("record_hash", "x", None, "test").unwrap();
        let from = Utc::now() - chrono::Duration::hours(1);
        let exported = log.export(from, Utc::now()).unwrap();
        let parsed: Vec<LogEntry> = serde_json::from_slice(&exported).unwrap();
        assert_eq!(parsed.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ten_k_entries_export_verify_under_five_seconds() {
        let dir = temp_log_dir();
        let log = TransparentLog::open(&dir).unwrap();
        for i in 0..10_000 {
            log.append_sent("record_hash", format!("id-{i}"), None, format!("n={i}"))
                .unwrap();
        }
        let start = std::time::Instant::now();
        let report = log.verify_integrity().unwrap();
        assert!(report.valid);
        let from = Utc::now() - chrono::Duration::hours(1);
        let _bytes = log.export(from, Utc::now()).unwrap();
        assert!(
            start.elapsed().as_secs() < 5,
            "took {:?}",
            start.elapsed()
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
