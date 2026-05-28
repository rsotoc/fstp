//! Stable node IKM resolution for HKDF / Ed25519 signer seed (production FSTP).

use std::fs;
use std::path::Path;

use fstp_core::types::FstpError;

/// Resolve 32+ byte IKM for [`GlobalInstanceId`] derivation.
pub fn resolve_node_ikm() -> Result<Vec<u8>, FstpError> {
    if let Ok(path) = std::env::var("FSTP_NODE_IKM_FILE") {
        if !path.trim().is_empty() {
            return load_ikm_file(Path::new(path.trim()));
        }
    }
    if let Ok(raw) = std::env::var("FSTP_NODE_IKM") {
        if !raw.trim().is_empty() {
            return parse_ikm_value(raw.trim());
        }
    }
    if crate::production::is_production_profile() {
        return Err(FstpError::PersistenceError(
            "FSTP_PROFILE=production requires FSTP_NODE_IKM (32 bytes or 64 hex) or FSTP_NODE_IKM_FILE"
                .into(),
        ));
    }
    tracing::warn!(
        "FSTP_NODE_IKM not set — using ephemeral random IKM. \
         CIIs will change on restart. Set FSTP_NODE_IKM for stable identities."
    );
    Ok(ephemeral_ikm())
}

pub fn signer_seed_from_ikm(ikm: &[u8]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    let src = if ikm.len() >= 32 { &ikm[..32] } else { ikm };
    seed[..src.len()].copy_from_slice(src);
    seed
}

fn load_ikm_file(path: &Path) -> Result<Vec<u8>, FstpError> {
    let bytes = fs::read(path).map_err(|e| {
        FstpError::PersistenceError(format!("read FSTP_NODE_IKM_FILE {}: {e}", path.display()))
    })?;
    let trimmed: Vec<u8> = bytes
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if trimmed.len() == 64 && trimmed.iter().all(|b| b.is_ascii_hexdigit()) {
        let hex = std::str::from_utf8(&trimmed)
            .map_err(|e| FstpError::PersistenceError(format!("IKM file hex utf8: {e}")))?;
        return parse_ikm_hex(hex);
    }
    if trimmed.len() == 32 {
        return Ok(trimmed);
    }
    Err(FstpError::PersistenceError(format!(
        "FSTP_NODE_IKM_FILE must contain 32 raw bytes or 64 hex chars (got {} bytes)",
        trimmed.len()
    )))
}

fn parse_ikm_value(value: &str) -> Result<Vec<u8>, FstpError> {
    if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return parse_ikm_hex(value);
    }
    Ok(value.as_bytes().to_vec())
}

fn parse_ikm_hex(hex: &str) -> Result<Vec<u8>, FstpError> {
    let bytes = hex::decode(hex.trim()).map_err(|e| {
        FstpError::PersistenceError(format!("FSTP_NODE_IKM hex decode: {e}"))
    })?;
    if bytes.len() != 32 {
        return Err(FstpError::PersistenceError(format!(
            "IKM must be 32 bytes after hex decode (got {})",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn ephemeral_ikm() -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut h);
    h.finish().to_le_bytes().repeat(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_ikm() {
        let hex = "42".repeat(64);
        let ikm = parse_ikm_value(&hex).unwrap();
        assert_eq!(ikm.len(), 32);
    }
}
