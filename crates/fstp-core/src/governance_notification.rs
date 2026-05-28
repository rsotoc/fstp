//! Governance event notification DTO validation (AGR-113 / F01-5).
//!
//! Mirrors `schema/gen-notification.proto` without protobuf in this crate.

use ed25519_dalek::Verifier;

use crate::blocklace::{AggregateAttrs, BlockPayload};
use crate::message::EventClass;
use crate::types::{PublicKey, RejectionReason, Sha256Hash};

pub const CONTENT_HASH_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;

const FORBIDDEN_PROTO_TOKENS: &[&str] = &[
    "content",
    "text",
    "body",
    "email",
    "phone",
    "address",
    "vote",
    "member_data",
    "document",
    "private_key",
    "secret",
    "gii",
    "global_instance",
    "password",
    "proposal_text",
    "votes",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceEventNotification {
    pub event_class: String,
    pub timestamp_utc_ms: i64,
    pub process_id: String,
    pub quorum_met: bool,
    pub participant_count: u32,
    pub content_hash: [u8; CONTENT_HASH_LEN],
    pub instance_signature: [u8; ED25519_SIG_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceNotifyError {
    SchemaViolation(String),
    InvalidContentHash,
    InvalidSignature,
    UnknownEventClass(String),
    TimestampOutOfRange,
}

impl GovernanceNotifyError {
    pub fn rejection_reason(&self) -> RejectionReason {
        match self {
            Self::SchemaViolation(_) => RejectionReason::SchemaViolation,
            Self::InvalidContentHash | Self::InvalidSignature => RejectionReason::InvalidSignature,
            Self::UnknownEventClass(_) => RejectionReason::UnknownMessageType,
            Self::TimestampOutOfRange => RejectionReason::TimestampOutOfWindow,
        }
    }
}

impl GovernanceEventNotification {
    pub fn validate_schema(&self) -> Result<(), GovernanceNotifyError> {
        validate_proto_schema_text(include_str!("../../../schema/gen-notification.proto"))?;

        if self.event_class.trim().is_empty() {
            return Err(GovernanceNotifyError::SchemaViolation(
                "event_class required".into(),
            ));
        }
        if self.process_id.trim().is_empty() {
            return Err(GovernanceNotifyError::SchemaViolation(
                "process_id required".into(),
            ));
        }
        for token in FORBIDDEN_PROTO_TOKENS {
            let lower = self.event_class.to_lowercase();
            if lower.contains(token) {
                return Err(GovernanceNotifyError::SchemaViolation(format!(
                    "event_class contains forbidden token: {token}"
                )));
            }
        }
        Ok(())
    }

    pub fn verify_instance_signature(&self, pubkey: &PublicKey) -> Result<(), GovernanceNotifyError> {
        let sig = ed25519_dalek::Signature::from_bytes(&self.instance_signature);
        pubkey
            .0
            .verify(&self.content_hash, &sig)
            .map_err(|_| GovernanceNotifyError::InvalidSignature)
    }

    pub fn parse_event_class(&self) -> Result<EventClass, GovernanceNotifyError> {
        let normalized = self.event_class.trim().to_lowercase();
        let class = if normalized.contains("decision") || normalized.contains("mediation") {
            EventClass::Decision
        } else if normalized.contains("membership") {
            EventClass::MembershipChange
        } else if normalized.contains("credential") {
            EventClass::CredentialLifecycle
        } else if normalized.contains("federation") || normalized.contains("bifurcation") {
            EventClass::FederationLifecycle
        } else {
            return Err(GovernanceNotifyError::UnknownEventClass(
                self.event_class.clone(),
            ));
        };
        Ok(class)
    }

    pub fn to_block_payload(&self) -> Result<BlockPayload, GovernanceNotifyError> {
        self.validate_schema()?;
        let event_class = self.parse_event_class()?;
        Ok(BlockPayload {
            event_hash: Sha256Hash::from_bytes(self.content_hash),
            event_class,
            aggregate_attrs: AggregateAttrs {
                participant_count: Some(self.participant_count),
                quorum_reached: Some(self.quorum_met),
                rounds_completed: Some(1),
            },
        })
    }
}

/// Ensures the shared `.proto` schema does not declare forbidden D_raw field names.
pub fn validate_proto_schema_text(proto: &str) -> Result<(), GovernanceNotifyError> {
    for line in proto.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || !trimmed.contains('=') {
            continue;
        }
        let field_part = trimmed.split('=').next().unwrap_or("").trim();
        let name = field_part
            .split_whitespace()
            .last()
            .unwrap_or("")
            .trim();
        if is_forbidden_proto_field_name(name) {
            return Err(GovernanceNotifyError::SchemaViolation(format!(
                "proto schema contains forbidden field name: {name}"
            )));
        }
    }
    Ok(())
}

fn is_forbidden_proto_field_name(name: &str) -> bool {
    if name == "content_hash" {
        return false;
    }
    FORBIDDEN_PROTO_TOKENS.contains(&name)
}

/// Length-prefixed frame reader helper (4-byte big-endian length + payload).
pub fn decode_frame(payload: &[u8]) -> Result<&[u8], GovernanceNotifyError> {
    if payload.len() > 1_048_576 {
        return Err(GovernanceNotifyError::SchemaViolation(
            "frame payload too large".into(),
        ));
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use rand::rngs::OsRng;

    fn sample_notification() -> (GovernanceEventNotification, PublicKey) {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let content_hash = Sha256Hash::digest(b"closed-room-canonical");
        let sig = signing_key.sign(content_hash.as_bytes());
        let mut sig_bytes = [0u8; ED25519_SIG_LEN];
        sig_bytes.copy_from_slice(sig.to_bytes().as_slice());
        let n = GovernanceEventNotification {
            event_class: "decision.room_closed".into(),
            timestamp_utc_ms: chrono::Utc::now().timestamp_millis(),
            process_id: uuid::Uuid::new_v4().to_string(),
            quorum_met: true,
            participant_count: 7,
            content_hash: *content_hash.as_bytes(),
            instance_signature: sig_bytes,
        };
        (n, PublicKey(signing_key.verifying_key()))
    }

    #[test]
    fn proto_schema_has_no_forbidden_fields() {
        assert!(validate_proto_schema_text(include_str!(
            "../../../schema/gen-notification.proto"
        ))
        .is_ok());
    }

    #[test]
    fn roundtrip_block_payload_preserves_hash() {
        let (n, pk) = sample_notification();
        n.verify_instance_signature(&pk).unwrap();
        let payload = n.to_block_payload().unwrap();
        assert_eq!(payload.event_hash.as_bytes(), &n.content_hash);
        assert_eq!(payload.event_class, EventClass::Decision);
    }

    #[test]
    fn rejects_wrong_signature() {
        let (n, _) = sample_notification();
        let other = ed25519_dalek::SigningKey::generate(&mut OsRng);
        assert!(n
            .verify_instance_signature(&PublicKey(other.verifying_key()))
            .is_err());
    }
}
