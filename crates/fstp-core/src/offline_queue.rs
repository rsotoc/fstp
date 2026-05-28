//! In-memory offline outbound queue (AGR-102).

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::types::{FstpError, FederationEndpoint, LinkId, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundTaskKind {
    SyncPeer,
    IdentityHeartbeat,
}

#[derive(Debug, Clone)]
pub struct OutboundTask {
    pub id: Uuid,
    pub enqueued_at: DateTime<Utc>,
    pub link_id: LinkId,
    pub endpoint: FederationEndpoint,
    pub kind: OutboundTaskKind,
    pub attempts: u32,
}

#[derive(Debug, Clone, Default)]
pub struct OfflineQueueStats {
    pub queued: usize,
    pub dropped_total: u64,
    pub drained_total: u64,
}

#[derive(Debug)]
pub struct OfflineOutboundQueue {
    capacity: usize,
    tasks: Mutex<VecDeque<OutboundTask>>,
    dropped_total: Mutex<u64>,
    drained_total: Mutex<u64>,
}

impl OfflineOutboundQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            tasks: Mutex::new(VecDeque::new()),
            dropped_total: Mutex::new(0),
            drained_total: Mutex::new(0),
        }
    }

    pub fn enqueue(
        &self,
        link_id: LinkId,
        endpoint: FederationEndpoint,
        kind: OutboundTaskKind,
    ) -> Result<Uuid> {
        let task = OutboundTask {
            id: Uuid::new_v4(),
            enqueued_at: Utc::now(),
            link_id,
            endpoint,
            kind,
            attempts: 0,
        };
        let id = task.id;
        let mut q = self.tasks.lock().map_err(lock_err)?;
        if q.len() >= self.capacity {
            if let Some(dropped) = q.pop_front() {
                tracing::warn!(
                    task_id = %dropped.id,
                    kind = ?dropped.kind,
                    "Offline queue full — dropping oldest task"
                );
                *self.dropped_total.lock().map_err(lock_err)? += 1;
            }
        }
        q.push_back(task);
        Ok(id)
    }

    pub fn len(&self) -> usize {
        self.tasks.lock().map(|q| q.len()).unwrap_or(0)
    }

    pub fn stats(&self) -> OfflineQueueStats {
        OfflineQueueStats {
            queued: self.len(),
            dropped_total: *self.dropped_total.lock().unwrap_or_else(|e| e.into_inner()),
            drained_total: *self.drained_total.lock().unwrap_or_else(|e| e.into_inner()),
        }
    }

    pub fn drain_batch(&self, max: usize) -> Vec<OutboundTask> {
        let mut q = match self.tasks.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let n = max.min(q.len());
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            if let Some(task) = q.pop_front() {
                out.push(task);
            }
        }
        if !out.is_empty() {
            *self.drained_total.lock().unwrap_or_else(|e| e.into_inner()) += out.len() as u64;
        }
        out
    }

    pub fn requeue_failed(&self, mut task: OutboundTask) {
        task.attempts = task.attempts.saturating_add(1);
        if let Ok(mut q) = self.tasks.lock() {
            q.push_back(task);
        }
    }
}

/// Exponential backoff with jitter cap (1s → 5min).
pub fn backoff_delay(attempt: u32) -> Duration {
    let exp = attempt.min(9);
    let secs = (1u64 << exp).min(300);
    Duration::from_secs(secs)
}

fn lock_err<T>(_: T) -> FstpError {
    FstpError::PersistenceError("offline queue lock poisoned".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_oldest_when_full() {
        let q = OfflineOutboundQueue::new(2);
        let ep = FederationEndpoint::new("https://a.example", "aa");
        let id1 = q
            .enqueue(Uuid::new_v4(), ep.clone(), OutboundTaskKind::SyncPeer)
            .unwrap();
        let _id2 = q
            .enqueue(Uuid::new_v4(), ep.clone(), OutboundTaskKind::SyncPeer)
            .unwrap();
        let id3 = q
            .enqueue(Uuid::new_v4(), ep, OutboundTaskKind::SyncPeer)
            .unwrap();
        assert_eq!(q.len(), 2);
        assert_eq!(q.stats().dropped_total, 1);
        let batch = q.drain_batch(10);
        assert!(!batch.iter().any(|t| t.id == id1));
        assert!(batch.iter().any(|t| t.id == id3));
    }

    #[test]
    fn backoff_grows_capped() {
        assert_eq!(backoff_delay(0), Duration::from_secs(1));
        assert_eq!(backoff_delay(3), Duration::from_secs(8));
        assert_eq!(backoff_delay(9), Duration::from_secs(300));
    }
}
