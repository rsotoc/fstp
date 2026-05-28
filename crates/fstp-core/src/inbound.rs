//! Inbound federation message validation (AGR-102).

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::crypto::verify_identity_event_signature;
use crate::message::FstpMessage;
use crate::types::{ContextualId, PublicKey, RejectionReason};

pub const DEFAULT_REPLAY_WINDOW_SECS: i64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundValidationError {
    CiiMismatch {
        got: ContextualId,
        expected: ContextualId,
    },
    UnknownCii(ContextualId),
    TimestampOutOfWindow {
        delta_secs: i64,
        window_secs: i64,
    },
    InvalidSignature,
    UnknownMessageType,
    ForbiddenField(String),
}

impl InboundValidationError {
    pub fn rejection_reason(&self) -> RejectionReason {
        match self {
            Self::CiiMismatch { .. } | Self::UnknownCii(_) => RejectionReason::UnknownCii,
            Self::TimestampOutOfWindow { .. } => RejectionReason::TimestampOutOfWindow,
            Self::InvalidSignature => RejectionReason::InvalidSignature,
            Self::UnknownMessageType => RejectionReason::UnknownMessageType,
            Self::ForbiddenField(_) => RejectionReason::SchemaViolation,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InboundValidator {
    pub replay_window_secs: i64,
}

impl Default for InboundValidator {
    fn default() -> Self {
        Self {
            replay_window_secs: DEFAULT_REPLAY_WINDOW_SECS,
        }
    }
}

impl InboundValidator {
    pub fn validate_peer_cii(
        &self,
        sender_cii: &ContextualId,
        expected_cii: &ContextualId,
    ) -> Result<(), InboundValidationError> {
        if sender_cii != expected_cii {
            return Err(InboundValidationError::CiiMismatch {
                got: sender_cii.clone(),
                expected: expected_cii.clone(),
            });
        }
        Ok(())
    }

    pub fn validate_timestamp(
        &self,
        timestamp: &DateTime<Utc>,
    ) -> Result<(), InboundValidationError> {
        let delta = (Utc::now() - *timestamp).num_seconds().abs();
        if delta > self.replay_window_secs {
            return Err(InboundValidationError::TimestampOutOfWindow {
                delta_secs: delta,
                window_secs: self.replay_window_secs,
            });
        }
        Ok(())
    }

    pub fn validate_context(
        &self,
        sender_cii: &ContextualId,
        expected_cii: &ContextualId,
        timestamp: &DateTime<Utc>,
    ) -> Result<(), InboundValidationError> {
        self.validate_peer_cii(sender_cii, expected_cii)?;
        self.validate_timestamp(timestamp)?;
        Ok(())
    }

    pub fn validate_fstp_message(
        &self,
        msg: &FstpMessage,
        sender_cii: &ContextualId,
        expected_cii: &ContextualId,
        peer_pubkey: &PublicKey,
    ) -> Result<(), InboundValidationError> {
        forbid_sensitive_json(msg)?;

        let emitter = match msg {
            FstpMessage::VerifiableCredential { issuer_cii, .. } => issuer_cii,
            _ => msg
                .emitter_cii()
                .ok_or(InboundValidationError::UnknownMessageType)?,
        };
        self.validate_peer_cii(emitter, expected_cii)?;
        self.validate_peer_cii(sender_cii, expected_cii)?;

        match msg {
            FstpMessage::IdentityEvent {
                event,
                instance_cii,
                pubkey,
                endpoint,
                timestamp,
                signature,
            } => {
                self.validate_timestamp(timestamp)?;
                verify_identity_event_signature(
                    event,
                    instance_cii,
                    pubkey,
                    endpoint,
                    timestamp,
                    signature,
                    peer_pubkey,
                )
                .map_err(|_| InboundValidationError::InvalidSignature)?;
            }
            FstpMessage::EventHash {
                instance_cii,
                timestamp_closed,
                signature,
                ..
            } => {
                self.validate_timestamp(timestamp_closed)?;
                self.validate_peer_cii(instance_cii, expected_cii)?;
                if signature.0.to_bytes() == [0u8; 64] {
                    return Err(InboundValidationError::InvalidSignature);
                }
            }
            FstpMessage::VerifiableCredential {
                issuer_cii,
                validity,
                signature,
                ..
            } => {
                self.validate_timestamp(&validity.issued_at)?;
                self.validate_peer_cii(issuer_cii, expected_cii)?;
                if signature.0.to_bytes() == [0u8; 64] {
                    return Err(InboundValidationError::InvalidSignature);
                }
            }
            FstpMessage::FederationControl {
                from_cii,
                timestamp,
                signature,
                ..
            } => {
                self.validate_timestamp(timestamp)?;
                self.validate_peer_cii(from_cii, expected_cii)?;
                if signature.0.to_bytes() == [0u8; 64] {
                    return Err(InboundValidationError::InvalidSignature);
                }
            }
        }
        Ok(())
    }

    /// Fuzz-safe: arbitrary JSON must not panic validation pipeline.
    pub fn inspect_untrusted_json(value: &serde_json::Value) -> Result<(), InboundValidationError> {
        forbid_sensitive_json_value(value)?;
        if let Ok(msg) = serde_json::from_value::<FstpMessage>(value.clone()) {
            forbid_sensitive_json(&msg)?;
        }
        Ok(())
    }
}

pub fn forbid_sensitive_json<T: Serialize>(value: &T) -> Result<(), InboundValidationError> {
    let json = serde_json::to_string(value).map_err(|e| {
        InboundValidationError::ForbiddenField(format!("serialize: {e}"))
    })?;
    forbid_sensitive_json_str(&json)
}

fn forbid_sensitive_json_value(value: &serde_json::Value) -> Result<(), InboundValidationError> {
    let json = value.to_string();
    forbid_sensitive_json_str(&json)
}

fn forbid_sensitive_json_str(json: &str) -> Result<(), InboundValidationError> {
    const FORBIDDEN: &[&str] = &[
        "\"content\"",
        "\"text\"",
        "\"body\"",
        "\"email\"",
        "\"phone\"",
        "\"address\"",
        "\"member_data\"",
        "\"document_content\"",
        "\"private_key\"",
        "\"secret\"",
        "\"gii\"",
        "\"global_instance\"",
        "\"password\"",
    ];
    let lower = json.to_lowercase();
    for needle in FORBIDDEN {
        if lower.contains(needle) {
            return Err(InboundValidationError::ForbiddenField(needle.to_string()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{CredentialType, CredentialValidity};
    use crate::types::Ed25519Sig;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn fuzz_untrusted_json_never_panics(blob in "\\PC*") {
            let value = serde_json::Value::String(blob);
            let _ = InboundValidator::inspect_untrusted_json(&value);
        }
    }

    #[test]
    fn rejects_forbidden_field_in_message() {
        let msg = FstpMessage::VerifiableCredential {
            subject_cii: ContextualId::new("cii:sub"),
            credential_type: CredentialType::InstitutionalMembership,
            claims: serde_json::json!({ "email": "x@y.com" }),
            issuer_cii: ContextualId::new("cii:issuer"),
            validity: CredentialValidity {
                issued_at: Utc::now(),
                valid_until: Utc::now(),
            },
            signature: Ed25519Sig(ed25519_dalek::Signature::from_bytes(&[1u8; 64])),
        };
        let err = forbid_sensitive_json(&msg).unwrap_err();
        assert!(matches!(err, InboundValidationError::ForbiddenField(_)));
    }

    #[test]
    fn timestamp_out_of_window() {
        let v = InboundValidator::default();
        let old = Utc::now() - chrono::Duration::hours(2);
        assert!(matches!(
            v.validate_timestamp(&old),
            Err(InboundValidationError::TimestampOutOfWindow { .. })
        ));
    }
}
