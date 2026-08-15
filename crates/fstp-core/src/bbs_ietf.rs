//! IETF CFRG BBS (draft-irtf-cfrg-bbs-signatures-10) via zkryptium.
//!
//! Dual-profile with [`crate::bbs_plus`] (Ursa). Not wire-compatible with Ursa proofs.
//! Ciphersuite: BLS12-381-SHA-256. See velizor-dev-docs/tickets/ssi/AGR-DT-IETF-BBS.md.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use zkryptium::bbsplus::ciphersuites::{BbsCiphersuite, Bls12381Sha256};
use zkryptium::bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey};
use zkryptium::keys::pair::KeyPair;
use zkryptium::schemes::algorithms::BbsBls12381Sha256;
use zkryptium::schemes::generics::{PoKSignature, Signature};

use crate::types::{FstpError, Result};

/// Product / agent proof type for IETF CFRG profile (distinct from Ursa `BbsBlsSignature2020`).
pub const PROOF_TYPE: &str = "BbsIetfCfrgSignature2025";

/// Default domain header when caller omits `header_hex`.
pub const DEFAULT_HEADER: &[u8] = b"fstp-bbs-ietf-v1";

pub const CIPHERSUITE: &str = "BLS12-381-SHA-256";
pub const CRYPTO_PROFILE: &str = "BBS_IETF_CFRG";
pub const DRAFT: &str = "draft-irtf-cfrg-bbs-signatures-10";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BbsIetfKeyPairHex {
    pub public_key_hex: String,
    pub secret_key_hex: String,
    /// Retained for API parity with Ursa; IETF keygen does not bind message count.
    pub message_count: usize,
    pub crypto_profile: String,
    pub ciphersuite: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BbsIetfSignRequest {
    pub messages_hex: Vec<String>,
    pub secret_key_hex: String,
    pub public_key_hex: String,
    #[serde(default)]
    pub header_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BbsIetfSignResponse {
    pub signature_hex: String,
    pub public_key_hex: String,
    pub crypto_profile: String,
    pub proof_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BbsIetfDeriveProofRequest {
    pub messages_hex: Vec<String>,
    pub signature_hex: String,
    pub public_key_hex: String,
    pub revealed_indices: Vec<usize>,
    #[serde(default)]
    pub nonce_hex: Option<String>,
    #[serde(default)]
    pub header_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BbsIetfDerivedProofBundle {
    pub proof_type: String,
    pub public_key_hex: String,
    pub signature_hex: String,
    pub proof_hex: String,
    pub nonce_hex: String,
    pub revealed_indices: Vec<usize>,
    pub crypto_profile: String,
    pub ciphersuite: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BbsIetfVerifyProofRequest {
    pub public_key_hex: String,
    pub proof_hex: String,
    pub nonce_hex: String,
    pub revealed_indices: Vec<usize>,
    /// Disclosed message octets (hex), same order as `revealed_indices`.
    pub disclosed_messages_hex: Vec<String>,
    #[serde(default)]
    pub header_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BbsIetfVerifyProofResponse {
    pub valid: bool,
    pub crypto_profile: String,
}

/// Capability blob for agent /status and Velyzor zk-capabilities.
pub fn capability_metadata() -> serde_json::Value {
    serde_json::json!({
        "cryptoProfile": CRYPTO_PROFILE,
        "ciphersuite": CIPHERSUITE,
        "draft": DRAFT,
        "crate": "zkryptium",
        "proofType": PROOF_TYPE,
        "wireCompatibleWithUrsa": false,
        "holderWasm": {
            "shortTerm": "fstp-proxy-ietf-derive",
            "mediumTerm": "@mattrglobal/pairing_crypto"
        }
    })
}

pub fn generate_key_pair(message_count: usize) -> Result<BbsIetfKeyPairHex> {
    let count = message_count.clamp(1, 64);
    let mut key_material = vec![0u8; Bls12381Sha256::IKM_LEN.max(32)];
    rand::thread_rng().fill_bytes(&mut key_material);
    let kp = KeyPair::<BbsBls12381Sha256>::generate(&key_material, None, None).map_err(ietf_err)?;
    Ok(BbsIetfKeyPairHex {
        public_key_hex: hex::encode(kp.public_key().to_bytes()),
        secret_key_hex: hex::encode(kp.private_key().to_bytes()),
        message_count: count,
        crypto_profile: CRYPTO_PROFILE.to_string(),
        ciphersuite: CIPHERSUITE.to_string(),
    })
}

pub fn sign_messages(req: &BbsIetfSignRequest) -> Result<BbsIetfSignResponse> {
    let sk = decode_secret_key(&req.secret_key_hex)?;
    let pk = decode_public_key(&req.public_key_hex)?;
    let messages = decode_raw_messages(&req.messages_hex)?;
    let header = decode_header(req.header_hex.as_deref())?;

    let signature = Signature::<BbsBls12381Sha256>::sign(
        Some(&messages),
        &sk,
        &pk,
        Some(&header),
    )
    .map_err(ietf_err)?;

    Ok(BbsIetfSignResponse {
        signature_hex: hex::encode(signature.to_bytes()),
        public_key_hex: req.public_key_hex.clone(),
        crypto_profile: CRYPTO_PROFILE.to_string(),
        proof_type: PROOF_TYPE.to_string(),
    })
}

pub fn derive_proof(req: &BbsIetfDeriveProofRequest) -> Result<BbsIetfDerivedProofBundle> {
    let pk = decode_public_key(&req.public_key_hex)?;
    let messages = decode_raw_messages(&req.messages_hex)?;
    let header = decode_header(req.header_hex.as_deref())?;
    let signature_bytes = hex::decode(req.signature_hex.trim())
        .map_err(|e| FstpError::PersistenceError(format!("ietf bbs signature hex: {e}")))?;

    let nonce = match &req.nonce_hex {
        Some(h) if !h.trim().is_empty() => hex::decode(h.trim())
            .map_err(|e| FstpError::PersistenceError(format!("ietf bbs nonce hex: {e}")))?,
        _ => {
            let mut n = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut n);
            n
        }
    };

    let proof = PoKSignature::<BbsBls12381Sha256>::proof_gen(
        &pk,
        &signature_bytes,
        Some(&header),
        Some(&nonce),
        Some(&messages),
        Some(&req.revealed_indices),
    )
    .map_err(ietf_err)?;

    Ok(BbsIetfDerivedProofBundle {
        proof_type: PROOF_TYPE.to_string(),
        public_key_hex: req.public_key_hex.clone(),
        signature_hex: req.signature_hex.clone(),
        proof_hex: hex::encode(proof.to_bytes()),
        nonce_hex: hex::encode(&nonce),
        revealed_indices: req.revealed_indices.clone(),
        crypto_profile: CRYPTO_PROFILE.to_string(),
        ciphersuite: CIPHERSUITE.to_string(),
    })
}

pub fn verify_proof(req: &BbsIetfVerifyProofRequest) -> Result<BbsIetfVerifyProofResponse> {
    if req.disclosed_messages_hex.len() != req.revealed_indices.len() {
        return Err(FstpError::PersistenceError(
            "ietf bbs: disclosed_messages_hex length must match revealed_indices".into(),
        ));
    }
    let pk = decode_public_key(&req.public_key_hex)?;
    let header = decode_header(req.header_hex.as_deref())?;
    let nonce = hex::decode(req.nonce_hex.trim())
        .map_err(|e| FstpError::PersistenceError(format!("ietf bbs nonce hex: {e}")))?;
    let proof_bytes = hex::decode(req.proof_hex.trim())
        .map_err(|e| FstpError::PersistenceError(format!("ietf bbs proof hex: {e}")))?;
    let disclosed = decode_raw_messages(&req.disclosed_messages_hex)?;

    let proof = PoKSignature::<BbsBls12381Sha256>::from_bytes(&proof_bytes).map_err(ietf_err)?;

    let ok = proof
        .proof_verify(
            &pk,
            Some(&disclosed),
            Some(&req.revealed_indices),
            Some(&header),
            Some(&nonce),
        )
        .is_ok();

    Ok(BbsIetfVerifyProofResponse {
        valid: ok,
        crypto_profile: CRYPTO_PROFILE.to_string(),
    })
}

fn decode_header(header_hex: Option<&str>) -> Result<Vec<u8>> {
    match header_hex {
        Some(h) if !h.trim().is_empty() => hex::decode(h.trim())
            .map_err(|e| FstpError::PersistenceError(format!("ietf bbs header hex: {e}"))),
        _ => Ok(DEFAULT_HEADER.to_vec()),
    }
}

fn decode_public_key(hex_str: &str) -> Result<BBSplusPublicKey> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| FstpError::PersistenceError(format!("ietf bbs public key hex: {e}")))?;
    BBSplusPublicKey::from_bytes(&bytes)
        .map_err(|_| FstpError::CryptoError("ietf bbs public key decode".into()))
}

fn decode_secret_key(hex_str: &str) -> Result<BBSplusSecretKey> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| FstpError::PersistenceError(format!("ietf bbs secret key hex: {e}")))?;
    BBSplusSecretKey::from_bytes(&bytes)
        .map_err(|_| FstpError::CryptoError("ietf bbs secret key decode".into()))
}

fn decode_raw_messages(hex_list: &[String]) -> Result<Vec<Vec<u8>>> {
    hex_list
        .iter()
        .map(|h| {
            hex::decode(h.trim())
                .map_err(|e| FstpError::PersistenceError(format!("ietf bbs message hex: {e}")))
        })
        .collect()
}

fn ietf_err(e: zkryptium::errors::Error) -> FstpError {
    FstpError::CryptoError(format!("ietf bbs: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_metadata_is_dual_profile_aware() {
        let meta = capability_metadata();
        assert_eq!(meta["cryptoProfile"], CRYPTO_PROFILE);
        assert_eq!(meta["wireCompatibleWithUrsa"], false);
    }

    #[test]
    fn sign_derive_verify_roundtrip_sha256() {
        let raw = vec![
            b"membershipId|\"abc\"".to_vec(),
            b"role|\"member\"".to_vec(),
            b"score|42".to_vec(),
        ];
        let messages_hex: Vec<String> = raw.iter().map(|m| hex::encode(m)).collect();

        let keys = generate_key_pair(raw.len()).unwrap();
        let sign_resp = sign_messages(&BbsIetfSignRequest {
            messages_hex: messages_hex.clone(),
            secret_key_hex: keys.secret_key_hex.clone(),
            public_key_hex: keys.public_key_hex.clone(),
            header_hex: None,
        })
        .unwrap();

        let derived = derive_proof(&BbsIetfDeriveProofRequest {
            messages_hex: messages_hex.clone(),
            signature_hex: sign_resp.signature_hex,
            public_key_hex: keys.public_key_hex.clone(),
            revealed_indices: vec![0, 2],
            nonce_hex: None,
            header_hex: None,
        })
        .unwrap();

        let disclosed: Vec<String> = derived
            .revealed_indices
            .iter()
            .map(|&i| messages_hex[i].clone())
            .collect();

        let verify = verify_proof(&BbsIetfVerifyProofRequest {
            public_key_hex: keys.public_key_hex,
            proof_hex: derived.proof_hex,
            nonce_hex: derived.nonce_hex,
            revealed_indices: vec![0, 2],
            disclosed_messages_hex: disclosed,
            header_hex: None,
        })
        .unwrap();

        assert!(verify.valid);
        assert_eq!(derived.proof_type, PROOF_TYPE);
    }

    #[test]
    fn hidden_message_not_required_for_verify() {
        let messages_hex = vec![
            hex::encode(b"public|\"yes\""),
            hex::encode(b"secret|\"no\""),
        ];
        let keys = generate_key_pair(2).unwrap();
        let sign_resp = sign_messages(&BbsIetfSignRequest {
            messages_hex: messages_hex.clone(),
            secret_key_hex: keys.secret_key_hex,
            public_key_hex: keys.public_key_hex.clone(),
            header_hex: None,
        })
        .unwrap();

        let derived = derive_proof(&BbsIetfDeriveProofRequest {
            messages_hex: messages_hex.clone(),
            signature_hex: sign_resp.signature_hex,
            public_key_hex: keys.public_key_hex.clone(),
            revealed_indices: vec![0],
            nonce_hex: Some(hex::encode(b"verifier-nonce-32-bytes!!!!!!!!!!")),
            header_hex: None,
        })
        .unwrap();

        let verify = verify_proof(&BbsIetfVerifyProofRequest {
            public_key_hex: keys.public_key_hex,
            proof_hex: derived.proof_hex,
            nonce_hex: derived.nonce_hex,
            revealed_indices: vec![0],
            disclosed_messages_hex: vec![messages_hex[0].clone()],
            header_hex: None,
        })
        .unwrap();

        assert!(verify.valid);
    }
}
