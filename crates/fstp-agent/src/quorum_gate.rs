//! In-memory quorum approval for protected SA operations (AGR-106).

use chrono::{DateTime, Utc};
use fstp_core::quorum::QuorumConfig;
use rand::RngCore;
use std::time::Duration;

/// Default lifetime of a maintenance unlock after M-of-N share submission.
pub const DEFAULT_APPROVAL_TTL_SECS: u64 = 900;

#[derive(Debug, Clone)]
pub struct QuorumGate {
    pub config: Option<QuorumConfig>,
    approval_token: Option<String>,
    approval_expires_at: Option<DateTime<Utc>>,
}

impl Default for QuorumGate {
    fn default() -> Self {
        Self {
            config: None,
            approval_token: None,
            approval_expires_at: None,
        }
    }
}

impl QuorumGate {
    pub fn is_initialized(&self) -> bool {
        self.config.as_ref().is_some_and(|c| c.initialized)
    }

    pub fn grant_approval(&mut self, ttl: Duration) -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = hex::encode(bytes);
        self.approval_token = Some(token.clone());
        self.approval_expires_at = Some(Utc::now() + chrono::Duration::from_std(ttl).unwrap_or(chrono::TimeDelta::seconds(900)));
        token
    }

    pub fn approval_active(&self) -> bool {
        match (&self.approval_token, &self.approval_expires_at) {
            (Some(_), Some(expires)) => Utc::now() <= *expires,
            _ => false,
        }
    }

    pub fn verify_token(&self, presented: Option<&str>) -> bool {
        let Some(expected) = self.approval_token.as_ref() else {
            return false;
        };
        let Some(expires) = self.approval_expires_at else {
            return false;
        };
        if Utc::now() > expires {
            return false;
        }
        presented.is_some_and(|t| constant_time_eq(t.trim(), expected))
    }

    pub fn requires_quorum_for_federation_terminate(&self) -> bool {
        self.is_initialized()
    }
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_valid_until_expiry() {
        let mut gate = QuorumGate::default();
        let token = gate.grant_approval(Duration::from_secs(60));
        assert!(gate.verify_token(Some(&token)));
        assert!(!gate.verify_token(Some("wrong")));
    }
}
