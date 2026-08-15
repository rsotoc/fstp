//! Institutional DID recovery — Shamir M-de-N (AGR-106).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sharks::{Share, Sharks};

use crate::types::{Did, FstpError, Result};

/// Quorum policy stored in `config/quorum.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QuorumConfig {
    pub threshold: u8,
    pub total_shares: u8,
    pub admins: Vec<QuorumAdmin>,
    #[serde(default)]
    pub initialized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QuorumAdmin {
    pub share_index: u8,
    pub name: String,
    pub public_key_hex: String,
}

/// Submitted share for recovery (hex-encoded `sharks::Share` bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumShareSubmission {
    pub share_index: u8,
    pub share_hex: String,
}

/// DID succession act after M-of-N recovery (persisted in pod).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccessionRecord {
    pub record_id: String,
    pub old_did: String,
    pub new_did: String,
    pub reason: SuccessionReason,
    pub timestamp_utc: chrono::DateTime<chrono::Utc>,
    pub quorum_signatures_hex: Vec<String>,
    pub old_did_signature_hex: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SuccessionReason {
    KeyCompromise,
    KeyLoss,
    PlannedRotation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShamirSplitResult {
    pub shares: Vec<StoredShare>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredShare {
    pub share_index: u8,
    pub share_hex: String,
}

/// Validates quorum parameters (2 ≤ m ≤ n ≤ 255).
pub fn validate_quorum_config(config: &QuorumConfig) -> Result<()> {
    if config.threshold < 2 {
        return Err(FstpError::PersistenceError(
            "quorum threshold must be at least 2".into(),
        ));
    }
    if config.total_shares < config.threshold {
        return Err(FstpError::PersistenceError(
            "total_shares must be >= threshold".into(),
        ));
    }
    if config.admins.len() != config.total_shares as usize {
        return Err(FstpError::PersistenceError(format!(
            "expected {} admin entries, got {}",
            config.total_shares,
            config.admins.len()
        )));
    }
    let mut indices: Vec<u8> = config.admins.iter().map(|a| a.share_index).collect();
    indices.sort_unstable();
    indices.dedup();
    if indices.len() != config.admins.len() {
        return Err(FstpError::PersistenceError("duplicate share_index in admins".into()));
    }
    for admin in &config.admins {
        parse_admin_pubkey(&admin.public_key_hex)?;
    }
    Ok(())
}

/// Splits a 32-byte Ed25519 seed into `n` shares requiring `m` to reconstruct.
pub fn shamir_split(secret: &[u8; 32], threshold: u8, total_shares: u8) -> Result<ShamirSplitResult> {
    if threshold < 2 || total_shares < threshold {
        return Err(FstpError::PersistenceError("invalid m-of-n parameters".into()));
    }
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(secret.as_slice());
    let mut shares = Vec::with_capacity(total_shares as usize);
    for (i, share) in dealer.take(total_shares as usize).enumerate() {
        let share_index = (i as u8) + 1;
        shares.push(StoredShare {
            share_index,
            share_hex: hex::encode(Vec::<u8>::from(&share)),
        });
    }
    Ok(ShamirSplitResult { shares })
}

/// Reconstructs the secret from at least `threshold` shares.
pub fn shamir_combine(submissions: &[QuorumShareSubmission], threshold: u8) -> Result<[u8; 32]> {
    if submissions.len() < threshold as usize {
        return Err(FstpError::PersistenceError(format!(
            "need at least {threshold} shares, got {}",
            submissions.len()
        )));
    }
    let sharks = Sharks(threshold);
    let mut shares: Vec<Share> = Vec::with_capacity(submissions.len());
    for sub in submissions.iter().take(threshold as usize) {
        let bytes = hex::decode(sub.share_hex.trim())
            .map_err(|e| FstpError::PersistenceError(format!("share hex decode: {e}")))?;
        let share = Share::try_from(bytes.as_slice()).map_err(|e| {
            FstpError::PersistenceError(format!("invalid share {}: {e}", sub.share_index))
        })?;
        shares.push(share);
    }
    let recovered = sharks.recover(&shares).map_err(|e| {
        FstpError::PersistenceError(format!("Shamir recovery failed: {e}"))
    })?;
    let recovered_bytes: &[u8] = recovered.as_ref();
    let arr: [u8; 32] = recovered_bytes.try_into().map_err(|_| {
        FstpError::PersistenceError("recovered secret must be 32 bytes".into())
    })?;
    Ok(arr)
}

/// Canonical bytes signed by each quorum admin during recovery.
pub fn succession_admin_signable(
    record_id: &str,
    old_did: &Did,
    new_did: &Did,
    elder_index: u8,
) -> Vec<u8> {
    format!(
        "fstp-quorum-v1|{record_id}|{old}|{new}|admin={elder_index}",
        old = old_did.0,
        new = new_did.0
    )
    .into_bytes()
}

pub fn sign_with_seed(seed: &[u8; 32], message: &[u8]) -> Result<String> {
    let signing_key = SigningKey::from_bytes(seed);
    let sig: Signature = signing_key.sign(message);
    Ok(hex::encode(sig.to_bytes()))
}

pub fn verify_admin_signature(pubkey_hex: &str, message: &[u8], signature_hex: &str) -> Result<()> {
    let vk = parse_admin_pubkey(pubkey_hex)?;
    let sig_bytes = hex::decode(signature_hex.trim())
        .map_err(|e| FstpError::PersistenceError(format!("signature hex decode: {e}")))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| {
        FstpError::PersistenceError(format!("invalid signature bytes: {e}"))
    })?;
    vk.verify(message, &sig)
        .map_err(|_| FstpError::PersistenceError("quorum admin signature invalid".into()))
}

fn parse_admin_pubkey(hex_str: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| FstpError::PersistenceError(format!("pubkey hex decode: {e}")))?;
    let arr = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        FstpError::PersistenceError("admin public_key must be 32-byte Ed25519".into())
    })?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| FstpError::PersistenceError(format!("invalid Ed25519 public key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> QuorumConfig {
        QuorumConfig {
            threshold: 2,
            total_shares: 3,
            admins: vec![
                QuorumAdmin {
                    share_index: 1,
                    name: "A".into(),
                    public_key_hex: admin_pubkey_hex(1),
                },
                QuorumAdmin {
                    share_index: 2,
                    name: "B".into(),
                    public_key_hex: admin_pubkey_hex(2),
                },
                QuorumAdmin {
                    share_index: 3,
                    name: "C".into(),
                    public_key_hex: admin_pubkey_hex(3),
                },
            ],
            initialized: false,
        }
    }

    fn admin_pubkey_hex(seed: u8) -> String {
        let mut sk = [0u8; 32];
        sk[31] = seed;
        let signing = SigningKey::from_bytes(&sk);
        hex::encode(signing.verifying_key().as_bytes())
    }

    #[test]
    fn validate_config_rejects_invalid_m_of_n() {
        let mut cfg = sample_config();
        cfg.threshold = 1;
        assert!(validate_quorum_config(&cfg).is_err());
    }

    #[test]
    fn shamir_2_of_3_all_pairs_recover() {
        let secret = [42u8; 32];
        let split = shamir_split(&secret, 2, 3).unwrap();
        let pairs = [(0, 1), (0, 2), (1, 2)];
        for (a, b) in pairs {
            let subs = [
                QuorumShareSubmission {
                    share_index: split.shares[a].share_index,
                    share_hex: split.shares[a].share_hex.clone(),
                },
                QuorumShareSubmission {
                    share_index: split.shares[b].share_index,
                    share_hex: split.shares[b].share_hex.clone(),
                },
            ];
            let recovered = shamir_combine(&subs, 2).unwrap();
            assert_eq!(recovered, secret);
        }
    }

    #[test]
    fn shamir_1_of_3_fails_without_leaking() {
        let secret = [7u8; 32];
        let split = shamir_split(&secret, 2, 3).unwrap();
        let subs = [QuorumShareSubmission {
            share_index: split.shares[0].share_index,
            share_hex: split.shares[0].share_hex.clone(),
        }];
        let err = shamir_combine(&subs, 2).unwrap_err();
        assert!(err.to_string().contains("need at least"));
        let wrong = shamir_combine(&subs, 2);
        assert!(wrong.is_err());
        // Still cannot recover with 1 share
        assert_ne!(
            shamir_combine(
                &[QuorumShareSubmission {
                    share_index: 1,
                    share_hex: "00".repeat(8),
                }],
                2
            )
            .ok(),
            Some(secret)
        );
    }

    #[test]
    fn shamir_single_random_share_never_recovers_secret() {
        let secret = [11u8; 32];
        let split = shamir_split(&secret, 2, 3).unwrap();
        for _ in 0..100 {
            let bogus = QuorumShareSubmission {
                share_index: 1,
                share_hex: hex::encode([0u8; 16]),
            };
            let got = shamir_combine(&[bogus], 2);
            assert!(got.is_err());
            assert_ne!(got.ok(), Some(secret));
        }
        let subs = [QuorumShareSubmission {
            share_index: split.shares[0].share_index,
            share_hex: split.shares[0].share_hex.clone(),
        }];
        assert!(shamir_combine(&subs, 2).is_err());
    }

    #[test]
    fn admin_succession_signature_roundtrip() {
        let mut seed = [0u8; 32];
        seed[0] = 9;
        let msg = succession_admin_signable("rec-1", &Did::new("did:old"), &Did::new("did:new"), 1);
        let sig = sign_with_seed(&seed, &msg).unwrap();
        let vk_hex = hex::encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes());
        verify_admin_signature(&vk_hex, &msg, &sig).unwrap();
    }
}
