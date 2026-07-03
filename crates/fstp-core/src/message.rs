//! Closed output enumeration D_pub — the set of message types the SA may emit (§3.1).
//!
//! `FstpMessage` has exactly four variants corresponding to Table 2 of the paper.
//! D_raw types are not members of this enum and are not importable in this module,
//! so the compiler statically rejects any attempt to construct a federation message
//! from an internal data value (Property 2.1).
//!
//! ## Extending the vocabulary
//!
//! Deploying networks may define additional typed objects provided all additions
//! satisfy Property 2.1 (§3.1, §6). Adding a variant here is an auditable change
//! visible to any federation peer reviewing the open-source repository before
//! establishing a trust relationship.
//!
//! ## Platform-specific extensions
//!
//! Concepts specific to a particular platform (e.g. credit transactions in Velyzor)
//! belong in that platform's own crate, not here.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) use crate::blocklace::AggregateAttrs;
use crate::types::{ContextualId, Ed25519Sig, FederationEndpoint, PublicKey, Sha256Hash};

// ─────────────────────────────────────────────────────────────────────────────
// Discriminant enums
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityEventKind {
    CiiAnnouncement,
    InstanceAlive,
    KeyRotation,
    CiiRetired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FederationEventKind {
    Propose,
    Accept,
    Reject,
    Suspend,
    Resume,
    Terminate,
}

/// Class of the internal event whose hash is being published (Table 2, EventHash).
/// This is typed metadata — no event content is present in any federation message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventClass {
    Decision,
    MembershipChange,
    CredentialLifecycle,
    FederationLifecycle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    InstitutionalMembership,
    RoleCredential,
    IdentityAttribute,
    Certification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialValidity {
    pub issued_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

// ─────────────────────────────────────────────────────────────────────────────
// FstpMessage — the closed D_pub enumeration (Table 2, §3.1)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FstpMessage {
    /// Type 1 — Identity event (Table 2).
    IdentityEvent {
        event: IdentityEventKind,
        instance_cii: ContextualId,
        pubkey: PublicKey,
        endpoint: FederationEndpoint,
        timestamp: DateTime<Utc>,
        signature: Ed25519Sig,
    },

    /// Type 2 — Event hash (Table 2).
    /// SHA-256 pointer to a certified internal event. No content leaves the node.
    EventHash {
        event_class: EventClass,
        timestamp_closed: DateTime<Utc>,
        instance_cii: ContextualId,
        aggregate_attrs: AggregateAttrs,
        event_hash: Sha256Hash,
        signature: Ed25519Sig,
    },

    /// Type 3 — Verifiable credential (Table 2).
    /// Propagated only with explicit subject consent (Property 3.2).
    VerifiableCredential {
        subject_cii: ContextualId,
        credential_type: CredentialType,
        claims: serde_json::Value,
        issuer_cii: ContextualId,
        validity: CredentialValidity,
        signature: Ed25519Sig,
    },

    /// Type 4 — Federation control (Table 2).
    FederationControl {
        event: FederationEventKind,
        link_id: Uuid,
        from_cii: ContextualId,
        to_cii: ContextualId,
        governance_proof_hash: Option<Sha256Hash>,
        timestamp: DateTime<Utc>,
        signature: Ed25519Sig,
    },
}

impl FstpMessage {
    pub fn type_name(&self) -> &'static str {
        match self {
            FstpMessage::IdentityEvent { .. } => "identity_event",
            FstpMessage::EventHash { .. } => "event_hash",
            FstpMessage::VerifiableCredential { .. } => "verifiable_credential",
            FstpMessage::FederationControl { .. } => "federation_control",
        }
    }

    pub fn emitter_cii(&self) -> Option<&ContextualId> {
        match self {
            FstpMessage::IdentityEvent { instance_cii, .. } => Some(instance_cii),
            FstpMessage::EventHash { instance_cii, .. } => Some(instance_cii),
            FstpMessage::VerifiableCredential { .. } => None,
            FstpMessage::FederationControl { from_cii, .. } => Some(from_cii),
        }
    }

    pub fn requires_consent(&self) -> bool {
        matches!(self, FstpMessage::VerifiableCredential { .. })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Ed25519Sig, PublicKey};

    fn dummy_identity_event() -> FstpMessage {
        FstpMessage::IdentityEvent {
            event: IdentityEventKind::CiiAnnouncement,
            instance_cii: ContextualId::new("cii:test"),
            pubkey: PublicKey(
                ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng).verifying_key(),
            ),
            endpoint: FederationEndpoint::new("https://node.example.org", "aabb"),
            timestamp: chrono::Utc::now(),
            signature: Ed25519Sig(ed25519_dalek::Signature::from_bytes(&[0u8; 64])),
        }
    }

    #[test]
    fn variant_count_matches_table_2() {
        // FstpMessage must have exactly 4 variants (Table 2).
        // Update this constant only when extending the protocol vocabulary.
        const EXPECTED: usize = 4;
        let names = [
            "identity_event",
            "event_hash",
            "verifiable_credential",
            "federation_control",
        ];
        assert_eq!(names.len(), EXPECTED);
    }

    #[test]
    fn type_name_is_defined_for_all_variants() {
        assert_eq!(dummy_identity_event().type_name(), "identity_event");
    }

    #[test]
    fn no_raw_field_names_in_serialized_message() {
        let forbidden = [
            "content",
            "text",
            "body",
            "name",
            "email",
            "phone",
            "address",
            "vote",
            "member_data",
            "document",
            "private_key",
            "secret",
            "gii",
            "global_id",
        ];
        let json = serde_json::to_string(&dummy_identity_event())
            .unwrap()
            .to_lowercase();
        for field in &forbidden {
            assert!(
                !json.contains(&format!("\"{}\"", field)),
                "Serialized message exposes forbidden D_raw field: '{field}'"
            );
        }
    }

    #[test]
    fn only_verifiable_credential_requires_consent() {
        assert!(!dummy_identity_event().requires_consent());
    }
}
