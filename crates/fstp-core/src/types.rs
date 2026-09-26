//! Core domain types for FSTP (whitepaper §2.1 information partition, §3).
//! `Did`, `ContextualId`, `FederationEndpoint`, protocol errors and wire DTOs.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, FstpError>;

// ─────────────────────────────────────────────────────────────────────────────
// Criptografía e Identificadores Primarios
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sha256Hash(#[serde(with = "hex_serde")] [u8; 32]);

impl Sha256Hash {
    pub fn digest(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Self(hasher.finalize().into())
    }

    /// Construct from a raw 32-byte digest (e.g. domain EventHash from Velyzor).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Sha256Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Hash({}…)", &self.to_hex()[..16])
    }
}

impl fmt::Display for Sha256Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Ed25519Sig(#[serde(with = "dalek_sig_serde")] pub DalekSignature);

impl fmt::Debug for Ed25519Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sig_bytes = self.0.to_bytes();
        write!(f, "Ed25519Sig({}…)", &hex::encode(sig_bytes)[..16])
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PublicKey(#[serde(with = "dalek_vk_serde")] pub VerifyingKey);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", hex::encode(self.0.as_bytes()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tipos de Identidad Soberana
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did(pub String);

impl Did {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into().trim().to_lowercase())
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContextualId(pub String);

impl ContextualId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into().trim().to_lowercase())
    }
}

impl fmt::Display for ContextualId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub type LinkId = Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Puntos de enlace de la Federación (Saneados para mTLS)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationEndpoint {
    /// URL base HTTPS de la API de federación del par.
    pub url: String,
    /// Huella digital SHA-256 del certificado TLS del par (hex, minúsculas).
    pub cert_fingerprint: String,
}

impl FederationEndpoint {
    pub fn new(url: impl Into<String>, cert_fingerprint: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            cert_fingerprint: cert_fingerprint.into().trim().to_lowercase(),
        }
    }

    pub fn frontier_url(&self) -> String {
        format!("{}/fstp/sync/frontier", self.url.trim_end_matches('/'))
    }

    pub fn blocks_url(&self) -> String {
        format!("{}/fstp/sync/blocks", self.url.trim_end_matches('/'))
    }

    pub fn present_credential_url(&self) -> String {
        format!("{}/fstp/present-credential", self.url.trim_end_matches('/'))
    }

    pub fn identity_event_url(&self) -> String {
        format!(
            "{}/fstp/federation/identity",
            self.url.trim_end_matches('/')
        )
    }
}

impl fmt::Display for FederationEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Protocolo de Sincronización Distribución (Tipos)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontierRequest {
    pub sender_cii: ContextualId,
    pub link_id: LinkId,
    pub frontier: Vec<Sha256Hash>,
    pub timestamp: DateTime<Utc>,
    pub signature: Ed25519Sig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontierResponse {
    pub responder_cii: ContextualId,
    pub link_id: LinkId,
    pub missing_blocks: Vec<crate::blocklace::Block>,
    pub responder_frontier: Vec<Sha256Hash>,
    pub timestamp: DateTime<Utc>,
    pub signature: Ed25519Sig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    pub link_id: LinkId,
    pub peer_cii: ContextualId,
    pub blocks_sent: usize,
    pub blocks_received: usize,
    pub completed_at: DateTime<Utc>,
    pub outcome: SyncOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncOutcome {
    Success,
    PartialSync,
    Rejected { reason: RejectionReason },
    NetworkError,
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RejectionReason {
    CertFingerprintMismatch,
    UnknownCii,
    InvalidSignature,
    UnknownMessageType,
    TimestampOutOfWindow,
    SchemaViolation,
}

// ─────────────────────────────────────────────────────────────────────────────
// Sistema de Control de Errores del Dominio (FstpError)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum FstpError {
    #[error("cryptographic verification failed: {0}")]
    CryptoError(String),

    #[error("confinement violation: attempted to emit a D_raw value")]
    ConfinementViolation,

    #[error("re-emission refused: usage scope does not authorize the recipient and no fresh grant extends it")]
    ReemissionRefused,

    #[error("message rejected: {0:?}")]
    MessageRejected(RejectionReason),

    #[error("invalid DID: {0}")]
    InvalidDid(String),

    #[error("unknown CII: {0}")]
    UnknownCii(ContextualId),

    #[error("block not found: {0}")]
    BlockNotFound(Sha256Hash),

    #[error("event content not present (dangling pointer): {0}")]
    DanglingPointer(Sha256Hash),

    #[error("erasure already fulfilled for block: {0}")]
    ErasureAlreadyFulfilled(Sha256Hash),

    #[error(
        "TLS certificate fingerprint mismatch for peer {peer}: expected {expected}, got {actual}"
    )]
    CertFingerprintMismatch {
        peer: String,
        expected: String,
        actual: String,
    },

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("sync request failed for link {link_id}: {reason}")]
    SyncFailed { link_id: LinkId, reason: String },

    #[error("sync timed out after {secs}s for link {link_id}")]
    SyncTimeout { link_id: LinkId, secs: u64 },

    #[error("HTTP error {status}: {body}")]
    HttpError { status: u16, body: String },

    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("persistence error: {0}")]
    PersistenceError(String),

    #[error("invalid pod credentials (passphrase)")]
    InvalidCredentials,
}

// ─────────────────────────────────────────────────────────────────────────────
// Ayudantes de Serialización Internos (Serde Helpers)
// ─────────────────────────────────────────────────────────────────────────────

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

mod dalek_sig_serde {
    use ed25519_dalek::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &Signature, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(sig.to_bytes()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Signature, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes for Ed25519 signature"))?;
        Ok(Signature::from_bytes(&arr))
    }
}

mod dalek_vk_serde {
    use ed25519_dalek::VerifyingKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(vk: &VerifyingKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(vk.as_bytes()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<VerifyingKey, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;
        VerifyingKey::from_bytes(&arr).map_err(serde::de::Error::custom)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pruebas Unitarias de Robustez
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hash_is_deterministic() {
        let h1 = Sha256Hash::digest(b"fstp-test");
        let h2 = Sha256Hash::digest(b"fstp-test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn sha256_hash_differs_for_different_input() {
        let h1 = Sha256Hash::digest(b"fstp-test-a");
        let h2 = Sha256Hash::digest(b"fstp-test-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn sha256_hash_roundtrips_json() {
        let h = Sha256Hash::digest(b"roundtrip-test");
        let json = serde_json::to_string(&h).unwrap();
        let h2: Sha256Hash = serde_json::from_str(&json).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn federation_endpoint_builds_correct_urls() {
        let ep = FederationEndpoint::new("https://example.org", "aabbccdd");
        assert_eq!(ep.frontier_url(), "https://example.org/fstp/sync/frontier");
        assert_eq!(ep.blocks_url(), "https://example.org/fstp/sync/blocks");
    }

    #[test]
    fn federation_endpoint_strips_trailing_slash() {
        let ep = FederationEndpoint::new("https://example.org/", "aabbccdd");
        assert_eq!(ep.frontier_url(), "https://example.org/fstp/sync/frontier");
    }

    #[test]
    fn contextual_id_display() {
        let cii = ContextualId::new("cii:abc123");
        assert_eq!(cii.to_string(), "cii:abc123");
    }

    #[test]
    fn did_display() {
        let did = Did::new("did:key:z6Mk...");
        assert_eq!(did.to_string(), "did:key:z6mk...");
    }

    #[test]
    fn sync_outcome_serializes_rejection_reason() {
        let outcome = SyncOutcome::Rejected {
            reason: RejectionReason::CertFingerprintMismatch,
        };
        let json = serde_json::to_string(&outcome).unwrap();
        assert!(json.contains("CERT_FINGERPRINT_MISMATCH"));
    }
}
