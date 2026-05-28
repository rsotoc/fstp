//! Trusted issuer registry bootstrap (HU-03 / production FSTP).

use ed25519_dalek::VerifyingKey;
use fstp_core::pod_store::{EncryptedPodStore, PodPath, PodStore};
use fstp_core::registry::IssuerRegistry;
use fstp_core::types::{Did, FstpError, PublicKey, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrustedIssuerEntry {
    did: String,
    #[serde(alias = "pubkey_hex")]
    pubkey_hex: String,
}

/// Load issuers from env + encrypted pod file; optionally persist env snapshot to pod.
pub fn bootstrap_trusted_issuers(
    pod: &EncryptedPodStore,
    registry: &mut IssuerRegistry,
) -> Result<u32> {
    if let Ok(json) = std::env::var("FSTP_TRUSTED_ISSUERS_JSON") {
        if !json.trim().is_empty() {
            let n = register_json(registry, &json)?;
            if n > 0 {
                let _ = pod.write(&PodPath::trusted_issuers(), &json);
                tracing::info!(
                    count = n,
                    path = %PodPath::trusted_issuers().0.display(),
                    "Persisted FSTP_TRUSTED_ISSUERS_JSON into encrypted pod"
                );
            }
        }
    }

    let path = PodPath::trusted_issuers();
    if pod.exists(&path) {
        let json: String = pod.read(&path)?;
        let n = register_json(registry, &json)?;
        tracing::info!(count = n, "Trusted issuers loaded from pod config");
        return Ok(n);
    }

    Ok(0)
}

pub fn register_json(registry: &mut IssuerRegistry, json: &str) -> Result<u32> {
    let list: Vec<TrustedIssuerEntry> =
        serde_json::from_str(json).map_err(FstpError::SerializationError)?;
    let mut loaded = 0u32;
    for entry in list {
        if register_one(registry, &entry.did, &entry.pubkey_hex)? {
            loaded += 1;
            tracing::info!(did = %entry.did, "trusted issuer registered");
        }
    }
    Ok(loaded)
}

pub fn register_one(registry: &mut IssuerRegistry, did: &str, pubkey_hex: &str) -> Result<bool> {
    let bytes = hex::decode(pubkey_hex.trim())
        .map_err(|e| FstpError::PersistenceError(format!("pubkey hex: {e}")))?;
    let arr = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        FstpError::PersistenceError("pubkeyHex must be 32 bytes (64 hex chars)".into())
    })?;
    let vk = VerifyingKey::from_bytes(&arr)
        .map_err(|e| FstpError::PersistenceError(format!("invalid Ed25519 pubkey: {e}")))?;
    registry.register(Did::new(did), PublicKey(vk));
    Ok(true)
}

/// Serialize the full registry for `config/trusted_issuers.json` in the encrypted pod.
pub fn registry_to_json(registry: &IssuerRegistry) -> Result<String> {
    let entries: Vec<TrustedIssuerEntry> = registry
        .entries()
        .into_iter()
        .map(|(did, pk)| TrustedIssuerEntry {
            did,
            pubkey_hex: hex::encode(pk.0.as_bytes()),
        })
        .collect();
    serde_json::to_string(&entries).map_err(FstpError::SerializationError)
}

pub fn persist_registry_to_pod(
    pod: &EncryptedPodStore,
    registry: &IssuerRegistry,
) -> Result<()> {
    let json = registry_to_json(registry)?;
    pod.write(&PodPath::trusted_issuers(), &json)?;
    Ok(())
}
