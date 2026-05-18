//! Production profile guardrails (whitepaper §5 Deployment).
//!
//! When `FSTP_PROFILE=production`, dev-only TLS bypass flags must not be set.

/// Validates environment before serving federation traffic.
pub fn enforce_production_profile() {
    let profile = std::env::var("FSTP_PROFILE").unwrap_or_default();
    if profile.trim().eq_ignore_ascii_case("production") {
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
        tracing::info!("FSTP production profile: dev TLS bypass flags are disabled");
    }
}

fn env_is_true(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}
