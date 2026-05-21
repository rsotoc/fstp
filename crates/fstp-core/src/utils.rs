//! Stateless helper functions used across FSTP modules.
//!
//! Nothing in this module carries state or depends on the runtime.
//! Functions here are pure utilities: time, encoding, certificate
//! fingerprinting.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

/// Returns the current UTC timestamp.
///
/// Centralised here so that all modules use the same source of time
/// and tests can trivially locate every call site.
pub fn now_utc() -> DateTime<Utc> {
    Utc::now()
}

/// Computes the SHA-256 fingerprint of a DER-encoded TLS certificate.
///
/// The fingerprint is returned as a lowercase hex string (64 characters).
/// This is the value stored in `FederationEndpoint::cert_fingerprint`.
///
/// # Arguments
///
/// * `cert_der` — the raw DER bytes of the certificate.
pub fn cert_fingerprint(cert_der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    hex::encode(hasher.finalize())
}

/// Verifies that the fingerprint of a presented certificate matches the
/// expected value stored for a peer.
///
/// Returns `true` if the fingerprints match, `false` otherwise.
/// OPTIMIZACIÓN: Realiza la comparación en tiempo constante sobre los bytes nativos
/// del Hash SHA-256, evitando la decodificación intermedia a String Hex para cerrar
/// fugas de información por canales laterales (Timing Side-Channels).
pub fn verify_cert_fingerprint(cert_der: &[u8], expected: &str) -> bool {
    // 1. Calculamos el hash crudo en bytes
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let actual_bytes = hasher.finalize();

    // 2. Decodificamos el hash esperado (hex) a bytes para comparar manzanas con manzanas
    let expected_bytes = match hex::decode(expected) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    if actual_bytes.len() != expected_bytes.len() {
        return false;
    }

    // 3. Comparación estricta en tiempo constante sobre los buffers de bytes nativos
    actual_bytes
        .iter()
        .zip(expected_bytes.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Checks whether a UTC timestamp is within the acceptance window
/// of ±`window_secs` seconds from now.
///
/// Used to reject replayed or stale messages. The default window in
/// the FSTP protocol is ±300 seconds (5 minutes).
/// OPTIMIZACIÓN: Migrado a timestamps numéricos puros para evitar APIs obsoletas de Chrono.
pub fn timestamp_in_window(ts: &DateTime<Utc>, window_secs: i64) -> bool {
    let now_ts = Utc::now().timestamp();
    let msg_ts = ts.timestamp();
    let skew = (now_ts - msg_ts).abs();
    skew <= window_secs
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_fingerprint_is_deterministic() {
        let der = b"fake-cert-der-bytes";
        assert_eq!(cert_fingerprint(der), cert_fingerprint(der));
    }

    #[test]
    fn cert_fingerprint_differs_for_different_input() {
        assert_ne!(cert_fingerprint(b"cert-a"), cert_fingerprint(b"cert-b"));
    }

    #[test]
    fn verify_cert_fingerprint_accepts_correct() {
        let der = b"fake-cert-der-bytes";
        let fp = cert_fingerprint(der);
        assert!(verify_cert_fingerprint(der, &fp));
    }

    #[test]
    fn verify_cert_fingerprint_rejects_wrong() {
        assert!(!verify_cert_fingerprint(
            b"cert-a",
            &cert_fingerprint(b"cert-b")
        ));
    }

    // CORRECCIÓN: Uso de try_seconds().unwrap() para cumplir con las especificaciones modernas de Chrono
    #[test]
    fn timestamp_in_window_accepts_recent() {
        let ts = Utc::now() - chrono::Duration::try_seconds(60).unwrap();
        assert!(timestamp_in_window(&ts, 300));
    }

    #[test]
    fn timestamp_in_window_rejects_old() {
        let ts = Utc::now() - chrono::Duration::try_seconds(400).unwrap();
        assert!(!timestamp_in_window(&ts, 300));
    }

    #[test]
    fn timestamp_in_window_rejects_future() {
        let ts = Utc::now() + chrono::Duration::try_seconds(400).unwrap();
        assert_eq!(timestamp_in_window(&ts, 300), false);
    }
}
