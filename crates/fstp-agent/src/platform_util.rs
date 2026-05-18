//! Platform integration helpers (whitepaper §3.2).
//! Deterministic `link_id` derivation for directory bootstrap and residence scope.

use uuid::Uuid;

/// Deterministic link id from two opaque strings (residence scope, dev peer pairs, etc.).
pub fn link_id_from_pair(left: &str, right: &str) -> Uuid {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(left.as_bytes());
    hasher.update(b":");
    hasher.update(right.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}
