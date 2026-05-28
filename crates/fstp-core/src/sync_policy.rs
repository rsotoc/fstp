//! Sync policy loaded from `config/sync_policy.json` (AGR-102).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{FstpError, Result};

pub const DEFAULT_HEARTBEAT_INTERVAL_MINS: u64 = 60;
pub const MIN_HEARTBEAT_INTERVAL_MINS: u64 = 15;
pub const MAX_HEARTBEAT_INTERVAL_MINS: u64 = 240;
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_RESPONSE_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_OFFLINE_QUEUE_CAPACITY: usize = 1000;
pub const DEFAULT_MAX_SEND_RETRIES: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncPolicy {
    /// Heartbeat interval in minutes (15–240, default 60).
    #[serde(default = "default_heartbeat_interval_mins")]
    pub heartbeat_interval_mins: u64,
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_response_timeout_secs")]
    pub response_timeout_secs: u64,
    #[serde(default = "default_offline_queue_capacity")]
    pub offline_queue_capacity: usize,
    #[serde(default = "default_max_send_retries")]
    pub max_send_retries: u32,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

impl Default for SyncPolicy {
    fn default() -> Self {
        Self {
            heartbeat_interval_mins: DEFAULT_HEARTBEAT_INTERVAL_MINS,
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
            response_timeout_secs: DEFAULT_RESPONSE_TIMEOUT_SECS,
            offline_queue_capacity: DEFAULT_OFFLINE_QUEUE_CAPACITY,
            max_send_retries: DEFAULT_MAX_SEND_RETRIES,
            updated_at: None,
        }
    }
}

impl SyncPolicy {
    pub fn heartbeat_interval_mins_clamped(&self) -> u64 {
        self.heartbeat_interval_mins
            .clamp(MIN_HEARTBEAT_INTERVAL_MINS, MAX_HEARTBEAT_INTERVAL_MINS)
    }

    pub fn heartbeat_interval_secs(&self) -> u64 {
        self.heartbeat_interval_mins_clamped()
            .saturating_mul(60)
    }

    pub fn validate(&self) -> Result<()> {
        if self.heartbeat_interval_mins < MIN_HEARTBEAT_INTERVAL_MINS
            || self.heartbeat_interval_mins > MAX_HEARTBEAT_INTERVAL_MINS
        {
            return Err(FstpError::PersistenceError(format!(
                "heartbeat_interval_mins must be between {MIN_HEARTBEAT_INTERVAL_MINS} and {MAX_HEARTBEAT_INTERVAL_MINS}"
            )));
        }
        Ok(())
    }
}

pub fn default_sync_policy() -> SyncPolicy {
    SyncPolicy::default()
}

fn default_heartbeat_interval_mins() -> u64 {
    DEFAULT_HEARTBEAT_INTERVAL_MINS
}

fn default_connect_timeout_secs() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_SECS
}

fn default_response_timeout_secs() -> u64 {
    DEFAULT_RESPONSE_TIMEOUT_SECS
}

fn default_offline_queue_capacity() -> usize {
    DEFAULT_OFFLINE_QUEUE_CAPACITY
}

fn default_max_send_retries() -> u32 {
    DEFAULT_MAX_SEND_RETRIES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_heartbeat_within_bounds() {
        let p = SyncPolicy::default();
        assert_eq!(p.heartbeat_interval_mins_clamped(), 60);
    }

    #[test]
    fn clamps_high_heartbeat() {
        let p = SyncPolicy {
            heartbeat_interval_mins: 999,
            ..Default::default()
        };
        assert_eq!(p.heartbeat_interval_mins_clamped(), 240);
    }
}
