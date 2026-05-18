//! Trusted issuer registry (whitepaper §3.1, §4.1).
//! Maps institutional `Did` to Ed25519 keys for verify-credential and federation.

use std::collections::HashMap;

use crate::types::{Did, PublicKey};

/// Maps issuer DIDs to Ed25519 public keys (Phase 2 — no caller-supplied keys).
#[derive(Debug, Default, Clone)]
pub struct IssuerRegistry {
    by_did: HashMap<String, PublicKey>,
}

impl IssuerRegistry {
    pub fn register(&mut self, did: Did, pubkey: PublicKey) {
        self.by_did.insert(did.0.clone(), pubkey);
    }

    pub fn lookup(&self, did: &Did) -> Option<&PublicKey> {
        self.by_did.get(&did.0)
    }

    pub fn len(&self) -> usize {
        self.by_did.len()
    }
}
