//! Ed25519 signing key for the local node (§3.1 bilateral authentication).
//!
//! The `NodeSigner` holds the node's signing keypair. It is the only place in
//! the codebase that has access to the private key material; all other modules
//! receive a `NodeSigner` reference and call `sign_response` / `verify_response`
//! without ever touching the raw key bytes.
//!
//! **Canonical bytes contract** — what gets signed in a `FrontierResponse`:
//!
//!   response_bytes = responder_cii_bytes
//!                 || link_id_bytes (16)
//!                 || responder_frontier_hash_bytes (sorted, each 32)
//!                 || timestamp_unix_secs (8, little-endian)
//!
//! This binds the responder's identity, the specific federation link, the
//! frontier state asserted, and the timestamp in a single unforgeable
//! commitment. Missing blocks are intentionally excluded: they are
//! authenticated individually by their own block hashes and signatures.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::types::{ContextualId, Ed25519Sig, FstpError, LinkId, PublicKey, Result, Sha256Hash};

// ─────────────────────────────────────────────────────────────────────────────
// Canonical serialization helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Produces the canonical byte sequence that a `FrontierResponse` signature
/// must cover (see module-level doc for the field ordering rationale).
pub fn frontier_response_signable(
    responder_cii: &ContextualId,
    link_id: &LinkId,
    responder_frontier: &[Sha256Hash],
    timestamp: &DateTime<Utc>,
) -> Vec<u8> {
    let mut bytes = Vec::new();

    // 1. Responder CII — length-prefixed UTF-8 so different-length CIIs
    //    cannot produce the same byte sequence as a shorter CII with extra data.
    let cii_bytes = responder_cii.0.as_bytes();
    bytes.extend_from_slice(&(cii_bytes.len() as u32).to_le_bytes());
    bytes.extend_from_slice(cii_bytes);

    // 2. Link ID — fixed 16 bytes, no ambiguity
    bytes.extend_from_slice(link_id.as_bytes());

    // 3. Frontier hashes — sorted for determinism across implementations
    let mut sorted_frontier: Vec<&Sha256Hash> = responder_frontier.iter().collect();
    sorted_frontier.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    for hash in sorted_frontier {
        bytes.extend_from_slice(hash.as_bytes());
    }

    // 4. Timestamp — Unix seconds, little-endian
    bytes.extend_from_slice(&timestamp.timestamp().to_le_bytes());

    bytes
}

/// Canonical bytes for signing a `FrontierRequest` (symmetric to response).
pub fn frontier_request_signable(
    sender_cii: &ContextualId,
    link_id: &LinkId,
    sender_frontier: &[Sha256Hash],
    timestamp: &DateTime<Utc>,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    let cii_bytes = sender_cii.0.as_bytes();
    bytes.extend_from_slice(&(cii_bytes.len() as u32).to_le_bytes());
    bytes.extend_from_slice(cii_bytes);
    bytes.extend_from_slice(link_id.as_bytes());

    let mut sorted: Vec<&Sha256Hash> = sender_frontier.iter().collect();
    sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    for hash in sorted {
        bytes.extend_from_slice(hash.as_bytes());
    }
    bytes.extend_from_slice(&timestamp.timestamp().to_le_bytes());
    bytes
}

// ─────────────────────────────────────────────────────────────────────────────
// NodeSigner
// ─────────────────────────────────────────────────────────────────────────────

/// Holds the node's Ed25519 signing keypair. Create once at startup and store
/// in `ServerState`; pass `&NodeSigner` to components that need to sign or
/// verify — never the raw key material.
#[derive(Debug, Clone)]
pub struct NodeSigner {
    signing_key: SigningKey,
}

impl NodeSigner {
    /// Generate a fresh ephemeral keypair. Suitable for tests and dev nodes
    /// where key persistence is not required.
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Load from raw 32-byte seed (e.g. derived from the node's DID private key).
    ///
    /// The seed is the standard Ed25519 private key seed — not the expanded
    /// scalar. If you have a PEM-encoded key, extract the 32-byte seed with a
    /// DER parser before calling this.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    /// The public key corresponding to this signer. Include in `IdentityEvent`
    /// messages so federation peers can verify response signatures.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.signing_key.verifying_key())
    }

    /// Sign the canonical bytes of a `FrontierResponse`.
    pub fn sign_response(
        &self,
        responder_cii: &ContextualId,
        link_id: &LinkId,
        responder_frontier: &[Sha256Hash],
        timestamp: &DateTime<Utc>,
    ) -> Ed25519Sig {
        let bytes =
            frontier_response_signable(responder_cii, link_id, responder_frontier, timestamp);
        Ed25519Sig(self.signing_key.sign(&bytes))
    }

    /// Sign the canonical bytes of a `FrontierRequest`.
    pub fn sign_request(
        &self,
        sender_cii: &ContextualId,
        link_id: &LinkId,
        sender_frontier: &[Sha256Hash],
        timestamp: &DateTime<Utc>,
    ) -> Ed25519Sig {
        let bytes = frontier_request_signable(sender_cii, link_id, sender_frontier, timestamp);
        Ed25519Sig(self.signing_key.sign(&bytes))
    }

    /// Sign arbitrary canonical bytes (e.g. `PresentCredential` payloads).
    pub fn sign_bytes(&self, bytes: &[u8]) -> Ed25519Sig {
        Ed25519Sig(self.signing_key.sign(bytes))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Verification (used by the client after receiving a FrontierResponse)
// ─────────────────────────────────────────────────────────────────────────────

/// Verify the signature on a received `FrontierResponse`.
///
/// `responder_pubkey` must come from the peer's previously received
/// `IdentityEvent` — not from the response itself (that would be trivially
/// forgeable). The caller is responsible for the key lookup.
///
/// Returns `Ok(())` if the signature is valid, `Err(FstpError::CryptoError)`
/// otherwise.
pub fn verify_response_signature(
    responder_cii: &ContextualId,
    link_id: &LinkId,
    responder_frontier: &[Sha256Hash],
    timestamp: &DateTime<Utc>,
    signature: &Ed25519Sig,
    responder_pubkey: &PublicKey,
) -> Result<()> {
    let bytes = frontier_response_signable(responder_cii, link_id, responder_frontier, timestamp);

    responder_pubkey
        .0
        .verify(&bytes, &signature.0)
        .map_err(|e| {
            FstpError::CryptoError(format!(
                "FrontierResponse signature verification failed: {e}"
            ))
        })
}

/// Verify the signature on a received `FrontierRequest`.
pub fn verify_request_signature(
    sender_cii: &ContextualId,
    link_id: &LinkId,
    sender_frontier: &[Sha256Hash],
    timestamp: &DateTime<Utc>,
    signature: &Ed25519Sig,
    sender_pubkey: &PublicKey,
) -> Result<()> {
    let bytes = frontier_request_signable(sender_cii, link_id, sender_frontier, timestamp);
    sender_pubkey.0.verify(&bytes, &signature.0).map_err(|e| {
        FstpError::CryptoError(format!(
            "FrontierRequest signature verification failed: {e}"
        ))
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_frontier(n: u8) -> Vec<Sha256Hash> {
        (0..n).map(|i| Sha256Hash::digest(&[i])).collect()
    }

    fn sample_params() -> (ContextualId, LinkId, Vec<Sha256Hash>, DateTime<Utc>) {
        (
            ContextualId::new("cii:test-responder"),
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            make_frontier(3),
            Utc::now(),
        )
    }

    #[test]
    fn request_sign_and_verify_roundtrip() {
        let signer = NodeSigner::generate();
        let (cii, link_id, frontier, ts) = sample_params();
        let sig = signer.sign_request(&cii, &link_id, &frontier, &ts);
        assert!(verify_request_signature(
            &cii,
            &link_id,
            &frontier,
            &ts,
            &sig,
            &signer.public_key()
        )
        .is_ok());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let signer = NodeSigner::generate();
        let (cii, link_id, frontier, ts) = sample_params();

        let sig = signer.sign_response(&cii, &link_id, &frontier, &ts);
        let pubkey = signer.public_key();

        assert!(
            verify_response_signature(&cii, &link_id, &frontier, &ts, &sig, &pubkey).is_ok(),
            "Valid signature must verify"
        );
    }

    #[test]
    fn tampered_cii_fails_verification() {
        let signer = NodeSigner::generate();
        let (cii, link_id, frontier, ts) = sample_params();
        let sig = signer.sign_response(&cii, &link_id, &frontier, &ts);
        let pubkey = signer.public_key();

        let tampered_cii = ContextualId::new("cii:attacker");
        assert!(
            verify_response_signature(&tampered_cii, &link_id, &frontier, &ts, &sig, &pubkey)
                .is_err(),
            "Tampered CII must not verify"
        );
    }

    #[test]
    fn tampered_frontier_fails_verification() {
        let signer = NodeSigner::generate();
        let (cii, link_id, frontier, ts) = sample_params();
        let sig = signer.sign_response(&cii, &link_id, &frontier, &ts);
        let pubkey = signer.public_key();

        let mut tampered = frontier.clone();
        tampered.push(Sha256Hash::digest(b"extra"));
        assert!(
            verify_response_signature(&cii, &link_id, &tampered, &ts, &sig, &pubkey).is_err(),
            "Tampered frontier must not verify"
        );
    }

    #[test]
    fn wrong_key_fails_verification() {
        let signer_a = NodeSigner::generate();
        let signer_b = NodeSigner::generate();
        let (cii, link_id, frontier, ts) = sample_params();

        let sig = signer_a.sign_response(&cii, &link_id, &frontier, &ts);
        let wrong_pubkey = signer_b.public_key();

        assert!(
            verify_response_signature(&cii, &link_id, &frontier, &ts, &sig, &wrong_pubkey).is_err(),
            "Signature from signer_a must not verify under signer_b's key"
        );
    }

    #[test]
    fn frontier_order_is_deterministic() {
        // Frontiers with same hashes in different order must produce same signable bytes.
        let signer = NodeSigner::generate();
        let link_id = Uuid::new_v4();
        let ts = Utc::now();
        let cii = ContextualId::new("cii:order-test");

        let mut frontier_a = make_frontier(4);
        let mut frontier_b = frontier_a.clone();
        frontier_b.reverse(); // opposite order

        let sig_a = signer.sign_response(&cii, &link_id, &frontier_a, &ts);
        let pubkey = signer.public_key();

        // sig_a was produced with frontier_a; must also verify with frontier_b
        // because both produce the same sorted canonical bytes.
        assert!(
            verify_response_signature(&cii, &link_id, &frontier_b, &ts, &sig_a, &pubkey).is_ok(),
            "Frontier hash order must not affect signature validity"
        );
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [42u8; 32];
        let s1 = NodeSigner::from_seed(&seed);
        let s2 = NodeSigner::from_seed(&seed);
        assert_eq!(
            s1.public_key().0.as_bytes(),
            s2.public_key().0.as_bytes(),
            "Same seed must produce same public key"
        );
    }
}
