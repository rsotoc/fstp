//! Credential verification (whitepaper §3.1 proof without exposure, HU-03).
//! Shared by gRPC `VerifyCredential` and `POST /rpc/verify-credential`.

use ed25519_dalek::Verifier;
use fstp_core::{
    blocklace::{AggregateAttrs, BlockPayload},
    message::EventClass,
    types::{ContextualId, Did, Ed25519Sig, Sha256Hash},
    BlocklaceStore,
};

use super::SharedState;

#[derive(Debug, Clone)]
pub struct VerifyCredentialInput {
    pub did: String,
    pub credential_json: String,
    pub signature_hex: String,
    pub pubkey_hex: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyCredentialOutput {
    pub is_valid: bool,
    pub error_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_version: Option<String>,
}

/// Verifies an issuer signature and appends a credential-lifecycle block.
pub async fn verify_credential(
    state: &SharedState,
    input: VerifyCredentialInput,
) -> VerifyCredentialOutput {
    let trust_caller_pubkey = std::env::var("FSTP_GRPC_TRUST_CALLER_PUBKEY")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let verifying_key = {
        let state_read = state.read().await;
        if let Some(pk) = state_read.issuer_registry.lookup(&Did::new(&input.did)) {
            pk.0
        } else if trust_caller_pubkey {
            match parse_pubkey_hex(&input.pubkey_hex) {
                Ok(k) => k,
                Err(msg) => return invalid(msg),
            }
        } else {
            tracing::warn!(
                did = %input.did,
                "verify-credential: issuer not in registry"
            );
            return VerifyCredentialOutput {
                is_valid: false,
                error_message: "issuer DID not in trusted registry; set FSTP_GRPC_TRUST_CALLER_PUBKEY=true for local dev only".into(),
                contract_version: contract_version(),
            };
        }
    };

    let signature_bytes = match hex::decode(input.signature_hex.trim()) {
        Ok(b) => b,
        Err(_) => return invalid("invalid signature hex format"),
    };

    let dalek_signature = match ed25519_dalek::Signature::from_slice(&signature_bytes) {
        Ok(s) => s,
        Err(e) => return invalid(format!("invalid Ed25519 signature bytes: {e}")),
    };

    if verifying_key
        .verify(input.credential_json.as_bytes(), &dalek_signature)
        .is_err()
    {
        tracing::warn!(did = %input.did, "verify-credential: signature verification failed");
        return VerifyCredentialOutput {
            is_valid: false,
            error_message: "Ed25519 signature verification failed".into(),
            contract_version: contract_version(),
        };
    }

    let _cii = ContextualId::new(&input.did);
    let signature = Ed25519Sig(dalek_signature);
    let payload = BlockPayload {
        event_hash: Sha256Hash::digest(input.credential_json.as_bytes()),
        event_class: EventClass::CredentialLifecycle,
        aggregate_attrs: AggregateAttrs {
            participant_count: Some(1),
            quorum_reached: Some(true),
            rounds_completed: Some(1),
        },
    };

    let mut state_guard = state.write().await;
    match state_guard.blocklace.append(payload, signature) {
        Ok(block) => {
            tracing::info!(
                block_hash = %block.block_hash,
                did = %input.did,
                "verify-credential: block appended"
            );
            VerifyCredentialOutput {
                is_valid: true,
                error_message: String::new(),
                contract_version: contract_version(),
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "verify-credential: blocklace append rejected");
            VerifyCredentialOutput {
                is_valid: false,
                error_message: e.to_string(),
                contract_version: contract_version(),
            }
        }
    }
}

fn parse_pubkey_hex(hex_str: &str) -> Result<ed25519_dalek::VerifyingKey, String> {
    let pubkey_bytes =
        hex::decode(hex_str.trim()).map_err(|_| "invalid public key hex format".to_string())?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| "Ed25519 public key must be 32 bytes".to_string())?;
    ed25519_dalek::VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|e| format!("invalid Ed25519 public key: {e}"))
}

fn invalid(msg: impl Into<String>) -> VerifyCredentialOutput {
    VerifyCredentialOutput {
        is_valid: false,
        error_message: msg.into(),
        contract_version: contract_version(),
    }
}

fn contract_version() -> Option<String> {
    std::env::var("FSTP_CONTRACT_VERSION")
        .ok()
        .or_else(|| Some("1.0.0".into()))
}
