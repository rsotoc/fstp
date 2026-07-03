//! Production profile guardrails (whitepaper §5 Deployment).

use std::path::Path;

use fstp_core::registry::IssuerRegistry;
use fstp_core::types::{Did, FstpError};

use crate::quorum_gate::QuorumGate;

/// Validates environment before serving federation traffic.
pub fn enforce_production_profile() {
    if !is_production_profile() {
        return;
    }

    for flag in [
        "FSTP_DEV_INSECURE_OUTBOUND",
        "FSTP_DEV_TRUST_PRESENT_CREDENTIAL",
        "FSTP_GRPC_TRUST_CALLER_PUBKEY",
    ] {
        if env_is_true(flag) {
            panic!(
                "FSTP_PROFILE=production but {flag} is enabled — remove dev flags (see docs/MTLS-PRODUCTION.md)"
            );
        }
    }

    if std::env::var("FSTP_NODE_IKM").is_err() && std::env::var("FSTP_NODE_IKM_FILE").is_err() {
        panic!(
            "FSTP_PROFILE=production requires stable identity: set FSTP_NODE_IKM (64 hex) or FSTP_NODE_IKM_FILE"
        );
    }

    if std::env::var("FSTP_NODE_DID")
        .map(|d| d.trim().is_empty())
        .unwrap_or(true)
    {
        panic!("FSTP_PROFILE=production requires FSTP_NODE_DID");
    }

    if std::env::var("FSTP_POD_PASSPHRASE")
        .map(|p| p.trim().is_empty())
        .unwrap_or(true)
    {
        panic!("FSTP_PROFILE=production requires FSTP_POD_PASSPHRASE");
    }

    for (var, label) in [
        ("FSTP_CERT_PATH", "server TLS certificate"),
        ("FSTP_KEY_PATH", "server TLS private key"),
        ("FSTP_CLIENT_CA_PATH", "peer mTLS client CA"),
    ] {
        let path = std::env::var(var).unwrap_or_default();
        if path.trim().is_empty() || !Path::new(path.trim()).exists() {
            panic!(
                "FSTP_PROFILE=production requires {var} pointing to an existing {label} file"
            );
        }
    }

    if !governance_socket_enabled_explicit() && std::env::var("FSTP_GOVERNANCE_SOCKET_ENABLED").is_err()
    {
        tracing::info!(
            "FSTP_PROFILE=production: governance Unix socket enabled by default (set FSTP_GOVERNANCE_SOCKET_ENABLED=false to disable)"
        );
    }

    tracing::info!("FSTP production profile: dev TLS bypass flags are disabled");
}

/// After issuer registry is populated.
pub fn validate_production_issuers(registry: &IssuerRegistry, node_did: &Did) -> Result<(), FstpError> {
    if !is_production_profile() {
        return Ok(());
    }
    if registry.len() < 2 {
        return Err(FstpError::PersistenceError(
            "production requires at least two trusted issuers (node + Velyzor institutional) — \
             set FSTP_TRUSTED_ISSUERS_JSON or config/trusted_issuers.json in pod"
                .into(),
        ));
    }
    let governance_did = std::env::var("FSTP_GOVERNANCE_ISSUER_DID")
        .or_else(|_| std::env::var("VELYZOR_COMMON_ISSUER_DID"))
        .or_else(|_| std::env::var("AGORA_COMMON_ISSUER_DID"))
        .unwrap_or_default();
    if !governance_did.trim().is_empty() {
        if registry.lookup(&Did::new(governance_did.trim())).is_none() {
            return Err(FstpError::PersistenceError(format!(
                "production governance issuer DID {} not in trusted issuer registry",
                governance_did.trim()
            )));
        }
    } else if registry.lookup(node_did).is_none() {
        return Err(FstpError::PersistenceError(
            "node DID missing from issuer registry".into(),
        ));
    }
    Ok(())
}

/// Production SA must have initialized Shamir quorum (`config/quorum.json`).
pub fn validate_production_quorum(gate: &QuorumGate) -> Result<(), FstpError> {
    if !is_production_profile() {
        return Ok(());
    }
    if std::env::var("FSTP_QUORUM_DEV_SKIP")
        .map(|v| env_is_true_val(&v))
        .unwrap_or(false)
    {
        tracing::warn!("FSTP_QUORUM_DEV_SKIP enabled — skipping quorum requirement (non-production only)");
        return Ok(());
    }
    if !gate.is_initialized() {
        return Err(FstpError::PersistenceError(
            "FSTP_PROFILE=production requires initialized quorum — POST /fstp/admin/quorum/setup"
                .into(),
        ));
    }
    Ok(())
}

pub fn is_production_profile() -> bool {
    std::env::var("FSTP_PROFILE")
        .map(|p| p.trim().eq_ignore_ascii_case("production"))
        .unwrap_or(false)
}

/// Governance socket defaults on in production unless explicitly disabled.
pub fn governance_socket_enabled() -> bool {
    match std::env::var("FSTP_GOVERNANCE_SOCKET_ENABLED") {
        Ok(v) => env_is_true_val(&v),
        Err(_) => is_production_profile(),
    }
}

fn governance_socket_enabled_explicit() -> bool {
    std::env::var("FSTP_GOVERNANCE_SOCKET_ENABLED").is_ok()
}

fn env_is_true(name: &str) -> bool {
    std::env::var(name)
        .map(|v| env_is_true_val(&v))
        .unwrap_or(false)
}

fn env_is_true_val(v: &str) -> bool {
    v == "true" || v == "1"
}
