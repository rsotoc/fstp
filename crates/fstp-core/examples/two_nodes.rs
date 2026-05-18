//! Two-node federation example.
//!
//! Demonstrates the core FSTP synchronization protocol (§3.3, §5.1) using only
//! `fstp-core` — no HTTP server, no TLS, no gRPC. Two in-memory nodes diverge
//! and then synchronize, exercising:
//!
//! - Blocklace append and frontier tracking
//! - O(Δ) sync_delta computation
//! - merge_blocks with incremental frontier update
//! - verify_chain integrity check on both sides
//! - NodeSigner / verify_response_signature bilateral authentication
//! - AuditLog structured output
//!
//! Run with:
//!   cargo run --example two_nodes

use fstp_core::{
    audit::AuditLog,
    blocklace::{AggregateAttrs, BlockPayload, BlocklaceStore, InMemoryBlocklace},
    crypto::{verify_response_signature, NodeSigner},
    message::EventClass,
    types::{ContextualId, Ed25519Sig, LinkId, Sha256Hash},
    utils::now_utc,
};
use uuid::Uuid;

fn dummy_sig() -> Ed25519Sig {
    Ed25519Sig(ed25519_dalek::Signature::from_bytes(&[0u8; 64]))
}

fn payload(seed: u8) -> BlockPayload {
    BlockPayload {
        event_hash: Sha256Hash::digest(&[seed]),
        event_class: EventClass::Decision,
        aggregate_attrs: AggregateAttrs {
            participant_count: Some(5),
            quorum_reached: Some(true),
            rounds_completed: Some(1),
        },
    }
}

fn main() {
    println!("═══════════════════════════════════════════════════════");
    println!("  FSTP — Two-Node Federation Example");
    println!("  Demonstrates O(Δ) sync without network or TLS");
    println!("═══════════════════════════════════════════════════════\n");

    // ── 1. Node identity ─────────────────────────────────────────────────────
    let signer_a = NodeSigner::generate();
    let signer_b = NodeSigner::generate();
    let cii_a = ContextualId::new("cii:node-a");
    let cii_b = ContextualId::new("cii:node-b");
    let link_id: LinkId = Uuid::new_v4();
    let audit_a = AuditLog::new();
    let audit_b = AuditLog::new();

    println!("Node A pubkey: {}", hex::encode(signer_a.public_key().0.as_bytes()));
    println!("Node B pubkey: {}", hex::encode(signer_b.public_key().0.as_bytes()));
    println!("Federation link: {link_id}\n");

    // ── 2. Shared genesis block ───────────────────────────────────────────────
    let mut bl_a = InMemoryBlocklace::new();
    let mut bl_b = InMemoryBlocklace::new();

    let genesis = bl_a.append(payload(0), dummy_sig()).unwrap();
    bl_b.merge_blocks(vec![genesis.clone()]).unwrap();
    println!("[Shared] Genesis block: {}", genesis.block_hash);

    // ── 3. Divergence — each node appends locally ─────────────────────────────
    let block_a1 = bl_a.append(payload(1), dummy_sig()).unwrap();
    let block_a2 = bl_a.append(payload(2), dummy_sig()).unwrap();
    let block_b1 = bl_b.append(payload(3), dummy_sig()).unwrap();

    println!("\n[Divergence]");
    println!("  Node A: +2 local blocks ({}, {})",
        block_a1.block_hash, block_a2.block_hash);
    println!("  Node B: +1 local block  ({})", block_b1.block_hash);
    println!("  A frontier size: {}", bl_a.frontier().len());
    println!("  B frontier size: {}", bl_b.frontier().len());

    // ── 4. Frontier exchange — compute deltas ─────────────────────────────────
    let delta_a_to_b = bl_a.sync_delta(&bl_b.frontier());
    let delta_b_to_a = bl_b.sync_delta(&bl_a.frontier());

    println!("\n[Sync delta]");
    println!("  A → B: {} block(s) to send", delta_a_to_b.len());
    println!("  B → A: {} block(s) to send", delta_b_to_a.len());

    // ── 5. Bilateral authentication — sign and verify frontier responses ───────
    let ts_a = now_utc();
    let frontier_a = bl_a.frontier();
    let sig_a = signer_a.sign_response(&cii_a, &link_id, &frontier_a, &ts_a);

    let ts_b = now_utc();
    let frontier_b = bl_b.frontier();
    let sig_b = signer_b.sign_response(&cii_b, &link_id, &frontier_b, &ts_b);

    // B verifies A's response using A's public key (looked up from IdentityEvent,
    // not from the response itself)
    verify_response_signature(&cii_a, &link_id, &frontier_a, &ts_a, &sig_a, &signer_a.public_key())
        .expect("B must accept A's signed frontier");
    println!("\n[Auth] B verified A's FrontierResponse signature ✓");

    verify_response_signature(&cii_b, &link_id, &frontier_b, &ts_b, &sig_b, &signer_b.public_key())
        .expect("A must accept B's signed frontier");
    println!("[Auth] A verified B's FrontierResponse signature ✓");

    // Tampered signature must be rejected
    let tampered_sig = signer_b.sign_response(&cii_a, &link_id, &frontier_a, &ts_a);
    let rejected = verify_response_signature(
        &cii_a, &link_id, &frontier_a, &ts_a, &tampered_sig, &signer_a.public_key()
    );
    assert!(rejected.is_err(), "Tampered signature must be rejected");
    println!("[Auth] Tampered signature correctly rejected ✓");

    // ── 6. Merge — both nodes converge ────────────────────────────────────────
    bl_b.merge_blocks(delta_a_to_b).unwrap();
    bl_a.merge_blocks(delta_b_to_a).unwrap();

    println!("\n[After sync]");
    println!("  Node A: {} total blocks, frontier size {}",
        bl_a.verify_chain().total_blocks, bl_a.frontier().len());
    println!("  Node B: {} total blocks, frontier size {}",
        bl_b.verify_chain().total_blocks, bl_b.frontier().len());

    // ── 7. Integrity verification ─────────────────────────────────────────────
    let report_a = bl_a.verify_chain();
    let report_b = bl_b.verify_chain();

    assert!(report_a.valid, "Node A chain must be valid: {:?}", report_a.corrupted_blocks);
    assert!(report_b.valid, "Node B chain must be valid: {:?}", report_b.corrupted_blocks);
    assert_eq!(report_a.total_blocks, report_b.total_blocks,
        "Both nodes must hold the same number of blocks after sync");

    println!("\n[Integrity] Both chains valid ✓");
    println!("[Integrity] Block count consistent ({} blocks each) ✓", report_a.total_blocks);

    // ── 8. Audit log ──────────────────────────────────────────────────────────
    audit_a.record_outbound("event_hash", Some(cii_b.clone()), Some(link_id), None, Some(2));
    audit_a.record_inbound("block_push", Some(cii_b.clone()), Some(link_id), None, Some(1));
    audit_b.record_outbound("event_hash", Some(cii_a.clone()), Some(link_id), None, Some(1));
    audit_b.record_inbound("block_push", Some(cii_a.clone()), Some(link_id), None, Some(2));

    println!("\n[Audit] Node A: {} record(s) logged", audit_a.len());
    println!("[Audit] Node B: {} record(s) logged", audit_b.len());

    println!("\n═══════════════════════════════════════════════════════");
    println!("  All assertions passed — protocol is working correctly");
    println!("═══════════════════════════════════════════════════════");
}
