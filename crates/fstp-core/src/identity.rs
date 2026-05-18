//! Contextual identity model (whitepaper §3.2, Property 3.1).
//! `GlobalInstanceId` + HKDF derive unlinkable `ContextualId` per federation link.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use sha2::Sha256;
use uuid::Uuid;

use crate::types::{ContextualId, Did, FederationEndpoint};

// ─────────────────────────────────────────────────────────────────────────────
// Federation context
// ─────────────────────────────────────────────────────────────────────────────

/// The stable context of a bilateral federation relationship.
///
/// Used as the `info` parameter to HKDF-SHA256 when deriving CIIs. Changing
/// any byte of the context produces a statistically independent CII, ensuring
/// that each relationship has its own unlinkable identifier.
#[derive(Debug, Clone)]
pub struct FederationContext {
    /// Stable identifier for this relationship, generated at proposal time
    /// and shared by both parties.
    pub link_id: Uuid,
    /// HTTPS endpoint of the counterpart node.
    pub counterpart_endpoint: FederationEndpoint,
}

impl FederationContext {
    pub fn new(link_id: Uuid, counterpart_endpoint: FederationEndpoint) -> Self {
        Self {
            link_id,
            counterpart_endpoint,
        }
    }

    /// Canonical byte representation used as the HKDF `info` parameter.
    ///
    /// Format: `link_id_bytes (16) || url_bytes (variable)`.
    /// OPTIMIZACIÓN: Saneado y normalizado a minúsculas para asegurar que diferencias
    /// menores en el formato de URL no rompan la derivación determinista del CII.
    pub fn as_info_bytes(&self) -> Vec<u8> {
        let mut info = Vec::new();
        info.extend_from_slice(self.link_id.as_bytes());

        let sanitized_url = self.counterpart_endpoint.url
            .trim_end_matches('/')
            .to_lowercase();

        info.extend_from_slice(sanitized_url.as_bytes());
        info
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Global Instance Identity
// ─────────────────────────────────────────────────────────────────────────────

/// The global cryptographic identity of a node.
///
/// Wraps the node's DID and the key material used to derive CIIs. Never
/// transmitted in federation traffic — only used locally.
#[derive(Clone)]
pub struct GlobalInstanceId {
    did: Did,
    /// Input key material for HKDF. In production: derived from the node's
    /// DID private key bytes. Never transmitted or persisted in cleartext.
    ikm: Vec<u8>,
}

impl std::fmt::Debug for GlobalInstanceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlobalInstanceId")
            .field("did", &self.did)
            .field("ikm", &"<redacted>")
            .finish()
    }
}

impl GlobalInstanceId {
    pub fn new(did: Did, ikm: Vec<u8>) -> Self {
        Self { did, ikm }
    }

    /// Returns the GII's DID. For local use only — never put in a message.
    pub fn did(&self) -> &Did {
        &self.did
    }

    /// Derives the Contextual Identity for a specific federation relationship.
    ///
    /// Uses HKDF-SHA256:
    /// - IKM: the node's key material
    /// - salt: none (HKDF zero-length salt)
    /// - info: `link_id_bytes || counterpart_url_bytes`
    ///
    /// Output: 32 bytes, base64url-encoded, prefixed with `"cii:"`.
    pub fn derive_cii(&self, context: &FederationContext) -> ContextualId {
        Self::derive_cii_from_info(&self.ikm, &context.as_info_bytes())
    }

    /// Subject-scoped CII for portable identity (Ágora HU / Fase 2).
    ///
    /// Unlinkable across federation links and across subjects: HKDF info is
    /// `federation_context_bytes || subject_id` (length-prefixed UTF-8).
    ///
    /// `subject_id` is an opaque platform identifier (e.g. `citizen:42`).
    pub fn derive_subject_cii(
        &self,
        context: &FederationContext,
        subject_id: &str,
    ) -> ContextualId {
        let mut info = context.as_info_bytes();
        let subject_bytes = subject_id.trim().as_bytes();
        info.extend_from_slice(&(subject_bytes.len() as u32).to_le_bytes());
        info.extend_from_slice(subject_bytes);
        Self::derive_cii_from_info(&self.ikm, &info)
    }

    fn derive_cii_from_info(ikm: &[u8], info: &[u8]) -> ContextualId {
        let hk = Hkdf::<Sha256>::new(None, ikm);
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .expect("HKDF output length 32 is always within bounds");
        ContextualId::new(format!("cii:{}", URL_SAFE_NO_PAD.encode(okm)))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_gii(seed: &[u8]) -> GlobalInstanceId {
        GlobalInstanceId::new(Did::new("did:key:test"), seed.to_vec())
    }

    fn make_context(link_id: Uuid, url: &str) -> FederationContext {
        FederationContext::new(
            link_id,
            FederationEndpoint::new(url, "deadbeef"),
        )
    }

    /// Property: derive_cii is deterministic.
    #[test]
    fn cii_derivation_is_deterministic() {
        let gii = make_gii(b"test-key-material-32-bytes-here!");
        let ctx = make_context(
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            "https://example.com",
        );
        assert_eq!(gii.derive_cii(&ctx), gii.derive_cii(&ctx));
    }

    /// Property: different link IDs produce different CIIs (contextual isolation).
    #[test]
    fn different_link_ids_produce_different_ciis() {
        let gii = make_gii(b"test-key-material-32-bytes-here!");
        let ctx_a = make_context(
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            "https://example.com",
        );
        let ctx_b = make_context(
            Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap(),
            "https://example.com",
        );
        assert_ne!(gii.derive_cii(&ctx_a), gii.derive_cii(&ctx_b));
    }

    /// Property: different URLs produce different CIIs (contextual isolation across endpoints).
    #[test]
    fn different_urls_produce_different_ciis() {
        let gii = make_gii(b"test-key-material-32-bytes-here!");
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let ctx_a = make_context(id, "https://node-a.example.com");
        let ctx_b = make_context(id, "https://node-b.example.com");
        assert_ne!(
            gii.derive_cii(&ctx_a),
            gii.derive_cii(&ctx_b),
            "Different counterpart URLs must produce different CIIs for the same link_id"
        );
    }

    /// Property: cert fingerprint rotation does NOT change the CII.
    #[test]
    fn cert_rotation_does_not_change_cii() {
        let gii = make_gii(b"test-key-material-32-bytes-here!");
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let url = "https://example.com";

        let ctx_old_cert = FederationContext::new(
            id,
            FederationEndpoint::new(url, "old-fingerprint"),
        );
        let ctx_new_cert = FederationContext::new(
            id,
            FederationEndpoint::new(url, "new-fingerprint"),
        );
        assert_eq!(
            gii.derive_cii(&ctx_old_cert),
            gii.derive_cii(&ctx_new_cert),
            "CII must be stable across TLS certificate rotations"
        );
    }

    /// Property: different GIIs produce different CIIs for the same context.
    #[test]
    fn different_giis_produce_different_ciis() {
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let ctx = make_context(id, "https://example.com");
        let gii_a = make_gii(b"key-material-node-a-32-bytes!!!!");
        let gii_b = make_gii(b"key-material-node-b-32-bytes!!!!");
        assert_ne!(gii_a.derive_cii(&ctx), gii_b.derive_cii(&ctx));
    }

    /// CII always starts with the "cii:" prefix.
    #[test]
    fn cii_has_correct_prefix() {
        let gii = make_gii(b"test-key-material-32-bytes-here!");
        let ctx = make_context(Uuid::new_v4(), "https://example.com");

        // CORRECCIÓN: Se utiliza to_string() para evaluar el prefijo a través del trait Display
        // evitando el pánico por acceso al campo privado de la tupla.
        assert!(gii.derive_cii(&ctx).to_string().starts_with("cii:"));
    }

    /// Subject CIIs differ from link-level CIIs and across subjects.
    #[test]
    fn subject_cii_isolated_per_subject_and_link() {
        let gii = make_gii(b"test-key-material-32-bytes-here!");
        let link = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let ctx = make_context(link, "https://example.com");

        let link_cii = gii.derive_cii(&ctx);
        let sub_a = gii.derive_subject_cii(&ctx, "citizen:1");
        let sub_b = gii.derive_subject_cii(&ctx, "citizen:2");

        assert_ne!(link_cii, sub_a);
        assert_ne!(sub_a, sub_b);

        let ctx_other = make_context(
            Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap(),
            "https://example.com",
        );
        assert_ne!(
            gii.derive_subject_cii(&ctx, "citizen:1"),
            gii.derive_subject_cii(&ctx_other, "citizen:1")
        );
    }

    /// GII key material does not appear literally in the CII string.
    #[test]
    fn cii_does_not_contain_raw_ikm() {
        let ikm = b"my-secret-key-material-32-bytes!";
        let gii = make_gii(ikm);
        let ctx = make_context(Uuid::new_v4(), "https://example.com");
        let cii = gii.derive_cii(&ctx);
        assert!(
            !cii.to_string().contains(std::str::from_utf8(ikm).unwrap()),
            "CII must not contain raw key material"
        );
    }
}