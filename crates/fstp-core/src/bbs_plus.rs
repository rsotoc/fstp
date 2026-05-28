//! BBS+ selective disclosure (AGR-DT-274 spike).
//!
//! Canonical message encoding for VC subjects: sorted keys, each message is
//! `fieldName + "|" + utf8(json(value))`.

use bbs::errors::BBSError;
use bbs::issuer::Issuer;
use bbs::keys::{PublicKey, SecretKey};
use bbs::messages::ProofMessage;
use bbs::prelude::*;
use bbs::signature::{Signature, SIGNATURE_COMPRESSED_SIZE};
use bbs::verifier::Verifier;
use bbs::{pm_hidden_raw, pm_revealed_raw, ProofNonce, SignatureMessage, SignatureProof};
use bbs::FR_COMPRESSED_SIZE;
use bbs::ToVariableLengthBytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::types::{FstpError, Result};

const PROOF_TYPE: &str = "BbsBlsSignature2020";

/// Hex-encoded BBS+ key material for JSON APIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BbsKeyPairHex {
    pub public_key_hex: String,
    pub secret_key_hex: String,
    pub message_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BbsSignRequest {
    pub messages_hex: Vec<String>,
    pub secret_key_hex: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BbsSignResponse {
    pub signature_hex: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BbsDeriveProofRequest {
    pub messages_hex: Vec<String>,
    pub signature_hex: String,
    pub public_key_hex: String,
    pub revealed_indices: Vec<usize>,
    pub nonce_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BbsDerivedProofBundle {
    pub proof_type: String,
    pub public_key_hex: String,
    pub signature_hex: String,
    pub proof_hex: String,
    pub nonce_hex: String,
    pub revealed_indices: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BbsVerifyProofRequest {
    pub public_key_hex: String,
    pub proof_hex: String,
    pub nonce_hex: String,
    pub revealed_indices: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BbsVerifyProofResponse {
    pub valid: bool,
    pub revealed_messages_hex: Vec<String>,
}

/// Build sorted canonical messages from a VC subject map (JSON values).
pub fn canonical_messages_from_subject(
    subject: &BTreeMap<String, serde_json::Value>,
) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::with_capacity(subject.len());
    for (key, value) in subject {
        let json = serde_json::to_string(value).map_err(FstpError::SerializationError)?;
        let mut msg = key.as_bytes().to_vec();
        msg.push(b'|');
        msg.extend_from_slice(json.as_bytes());
        out.push(msg);
    }
    Ok(out)
}

pub fn generate_key_pair(message_count: usize) -> Result<BbsKeyPairHex> {
    let (pk, sk) = Issuer::new_keys(message_count).map_err(bbs_err)?;
    Ok(BbsKeyPairHex {
        public_key_hex: hex::encode(pk.to_bytes_compressed_form()),
        secret_key_hex: hex::encode(sk.to_bytes_compressed_form()),
        message_count,
    })
}

pub fn sign_messages(req: &BbsSignRequest) -> Result<BbsSignResponse> {
    let pk = decode_public_key(&req.public_key_hex)?;
    let sk = decode_secret_key(&req.secret_key_hex)?;
    let messages = decode_messages(&req.messages_hex)?;
    let signature = Issuer::sign(&messages, &sk, &pk).map_err(bbs_err)?;
    Ok(BbsSignResponse {
        signature_hex: hex::encode(signature.to_bytes_compressed_form()),
        public_key_hex: req.public_key_hex.clone(),
    })
}

pub fn derive_proof(req: &BbsDeriveProofRequest) -> Result<BbsDerivedProofBundle> {
    let pk = decode_public_key(&req.public_key_hex)?;
    let messages = decode_messages(&req.messages_hex)?;
    let signature = decode_signature(&req.signature_hex)?;

    let proof_request =
        Verifier::new_proof_request(&req.revealed_indices, &pk).map_err(bbs_err)?;

    let nonce = match &req.nonce_hex {
        Some(h) => decode_nonce(h)?,
        None => Verifier::generate_proof_nonce(),
    };

    let proof_messages: Vec<ProofMessage> = (0..messages.len())
        .map(|i| {
            if req.revealed_indices.contains(&i) {
                pm_revealed_raw!(messages[i])
            } else {
                pm_hidden_raw!(messages[i])
            }
        })
        .collect();

    let pok = Prover::commit_signature_pok(&proof_request, &proof_messages, &signature)
        .map_err(bbs_err)?;

    let challenge = Prover::create_challenge_hash(&[pok.clone()], None, &nonce).map_err(bbs_err)?;
    let proof = Prover::generate_signature_pok(pok, &challenge).map_err(bbs_err)?;

    Ok(BbsDerivedProofBundle {
        proof_type: PROOF_TYPE.to_string(),
        public_key_hex: req.public_key_hex.clone(),
        signature_hex: req.signature_hex.clone(),
        proof_hex: hex::encode(proof.to_bytes_compressed_form()),
        nonce_hex: hex::encode(nonce.to_bytes_compressed_form()),
        revealed_indices: req.revealed_indices.clone(),
    })
}

pub fn verify_proof(req: &BbsVerifyProofRequest) -> Result<BbsVerifyProofResponse> {
    let pk = decode_public_key(&req.public_key_hex)?;
    let proof = decode_proof(&req.proof_hex)?;
    let nonce = decode_nonce(&req.nonce_hex)?;

    let proof_request =
        Verifier::new_proof_request(&req.revealed_indices, &pk).map_err(bbs_err)?;

    match Verifier::verify_signature_pok(&proof_request, &proof, &nonce) {
        Ok(revealed) => {
            let revealed_messages_hex = revealed
                .iter()
                .map(|m| hex::encode(m.to_bytes_compressed_form()))
                .collect();
            Ok(BbsVerifyProofResponse {
                valid: true,
                revealed_messages_hex,
            })
        }
        Err(e) => {
            tracing::debug!("bbs proof verification failed: {:?}", e);
            Ok(BbsVerifyProofResponse {
                valid: false,
                revealed_messages_hex: vec![],
            })
        }
    }
}

fn decode_public_key(hex_str: &str) -> Result<PublicKey> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| FstpError::PersistenceError(format!("bbs public key hex: {e}")))?;
    PublicKey::from_bytes_compressed_form(&bytes).map_err(bbs_err)
}

fn decode_secret_key(hex_str: &str) -> Result<SecretKey> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| FstpError::PersistenceError(format!("bbs secret key hex: {e}")))?;
    let arr: [u8; FR_COMPRESSED_SIZE] = bytes
        .try_into()
        .map_err(|_| FstpError::PersistenceError("bbs secret key wrong length".into()))?;
    Ok(SecretKey::from(arr))
}

fn decode_signature(hex_str: &str) -> Result<Signature> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| FstpError::PersistenceError(format!("bbs signature hex: {e}")))?;
    let arr: [u8; SIGNATURE_COMPRESSED_SIZE] = bytes
        .try_into()
        .map_err(|_| FstpError::PersistenceError("bbs signature wrong length".into()))?;
    Ok(Signature::from(arr))
}

fn decode_proof(hex_str: &str) -> Result<SignatureProof> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| FstpError::PersistenceError(format!("bbs proof hex: {e}")))?;
    SignatureProof::from_bytes_compressed_form(&bytes).map_err(bbs_err)
}

fn decode_nonce(hex_str: &str) -> Result<ProofNonce> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| FstpError::PersistenceError(format!("bbs nonce hex: {e}")))?;
    let arr: [u8; FR_COMPRESSED_SIZE] = bytes
        .try_into()
        .map_err(|_| FstpError::PersistenceError("bbs nonce wrong length".into()))?;
    Ok(ProofNonce::from(arr))
}

fn decode_messages(hex_list: &[String]) -> Result<Vec<SignatureMessage>> {
    hex_list
        .iter()
        .map(|h| {
            let bytes = hex::decode(h.trim())
                .map_err(|e| FstpError::PersistenceError(format!("bbs message hex: {e}")))?;
            Ok(SignatureMessage::hash(&bytes))
        })
        .collect()
}

fn bbs_err(e: BBSError) -> FstpError {
    FstpError::CryptoError(format!("bbs: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_derive_verify_roundtrip() {
        let raw = vec![
            b"membershipId|\"abc\"".to_vec(),
            b"role|\"member\"".to_vec(),
            b"score|42".to_vec(),
        ];
        let messages_hex: Vec<String> = raw.iter().map(|m| hex::encode(m)).collect();

        let keys = generate_key_pair(raw.len()).unwrap();
        let sign_resp = sign_messages(&BbsSignRequest {
            messages_hex: messages_hex.clone(),
            secret_key_hex: keys.secret_key_hex.clone(),
            public_key_hex: keys.public_key_hex.clone(),
        })
        .unwrap();

        let derived = derive_proof(&BbsDeriveProofRequest {
            messages_hex: messages_hex.clone(),
            signature_hex: sign_resp.signature_hex,
            public_key_hex: keys.public_key_hex.clone(),
            revealed_indices: vec![0, 2],
            nonce_hex: None,
        })
        .unwrap();

        let verify = verify_proof(&BbsVerifyProofRequest {
            public_key_hex: keys.public_key_hex,
            proof_hex: derived.proof_hex,
            nonce_hex: derived.nonce_hex,
            revealed_indices: vec![0, 2],
        })
        .unwrap();

        assert!(verify.valid);
        assert_eq!(verify.revealed_messages_hex.len(), 2);
    }

    #[test]
    fn hidden_message_not_in_proof() {
        let messages_hex = vec![
            hex::encode(b"public|\"yes\""),
            hex::encode(b"secret|\"no\""),
        ];
        let keys = generate_key_pair(2).unwrap();
        let sign_resp = sign_messages(&BbsSignRequest {
            messages_hex: messages_hex.clone(),
            secret_key_hex: keys.secret_key_hex.clone(),
            public_key_hex: keys.public_key_hex.clone(),
        })
        .unwrap();

        let derived = derive_proof(&BbsDeriveProofRequest {
            messages_hex: messages_hex.clone(),
            signature_hex: sign_resp.signature_hex,
            public_key_hex: keys.public_key_hex.clone(),
            revealed_indices: vec![0],
            nonce_hex: None,
        })
        .unwrap();

        let verify = verify_proof(&BbsVerifyProofRequest {
            public_key_hex: keys.public_key_hex,
            proof_hex: derived.proof_hex,
            nonce_hex: derived.nonce_hex,
            revealed_indices: vec![0],
        })
        .unwrap();

        assert!(verify.valid);
        assert_eq!(verify.revealed_messages_hex.len(), 1);
    }
}
