//! Experimental Validation Suite for the FSTP Protocol.
//!
//! Provides empirical evidence of eventual consistency and cryptographic
//! integrity (§5.1). Uses only `fstp-core` types — no HTTP server, no TLS.
//! The sync logic is exercised directly on `InMemoryBlocklace` instances,
//! which is the correct abstraction for protocol validation.

use std::collections::HashSet;

use fstp_core::blocklace::{AggregateAttrs, BlockPayload, BlocklaceStore, InMemoryBlocklace};
use fstp_core::crypto::NodeSigner;
use fstp_core::message::EventClass;
use fstp_core::types::{ContextualId, Ed25519Sig, LinkId, Sha256Hash};

fn test_payload(content: &[u8], class: EventClass) -> BlockPayload {
    BlockPayload {
        event_hash: Sha256Hash::digest(content),
        event_class: class,
        aggregate_attrs: AggregateAttrs {
            participant_count: Some(3),
            quorum_reached: Some(true),
            rounds_completed: Some(1),
        },
    }
}

fn mock_sig() -> Ed25519Sig {
    Ed25519Sig(ed25519_dalek::Signature::from_bytes(&[0u8; 64]))
}

// ─────────────────────────────────────────────────────────────────────────────
// §5.1 — Three-node federation: eventual consistency and integrity
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn three_node_eventual_consistency_and_integrity() {
    // ── 1. Three independent nodes — no shared state ──────────────────────
    let mut bl_a = InMemoryBlocklace::new();
    let mut bl_b = InMemoryBlocklace::new();
    let mut bl_c = InMemoryBlocklace::new();

    // ── 2. Concurrent local activity (divergence) ─────────────────────────
    let block_a1 = bl_a
        .append(
            test_payload(b"Decision from Island A", EventClass::Decision),
            mock_sig(),
        )
        .unwrap();

    let block_b1 = bl_b
        .append(
            test_payload(
                b"Membership change at Island B",
                EventClass::MembershipChange,
            ),
            mock_sig(),
        )
        .unwrap();

    // At this point: A=[a1], B=[b1], C=[]
    assert_ne!(
        block_a1.block_hash, block_b1.block_hash,
        "Independently produced blocks must have distinct hashes"
    );

    // ── 3. Bilateral sync: A ↔ B ─────────────────────────────────────────
    let delta_a_to_b = bl_a.sync_delta(&bl_b.frontier());
    bl_b.merge_blocks(delta_a_to_b).unwrap();

    let delta_b_to_a = bl_b.sync_delta(&bl_a.frontier());
    bl_a.merge_blocks(delta_b_to_a).unwrap();

    // After A↔B: both hold 2 blocks
    assert_eq!(bl_a.verify_chain().total_blocks, 2);
    assert_eq!(bl_b.verify_chain().total_blocks, 2);

    // ── 4. Propagation: B → C ────────────────────────────────────────────
    let delta_b_to_c = bl_b.sync_delta(&bl_c.frontier());
    bl_c.merge_blocks(delta_b_to_c).unwrap();

    // ── 5. Integrity: all chains valid ───────────────────────────────────
    let report_a = bl_a.verify_chain();
    let report_b = bl_b.verify_chain();
    let report_c = bl_c.verify_chain();

    assert!(
        report_a.valid,
        "Island A chain corrupt: {:?}",
        report_a.corrupted_blocks
    );
    assert!(
        report_b.valid,
        "Island B chain corrupt: {:?}",
        report_b.corrupted_blocks
    );
    assert!(
        report_c.valid,
        "Island C chain corrupt: {:?}",
        report_c.corrupted_blocks
    );

    // ── 6. Eventual consistency: all nodes hold the same blocks ──────────
    assert_eq!(report_a.total_blocks, 2, "Island A: unexpected block count");
    assert_eq!(report_b.total_blocks, 2, "Island B: unexpected block count");
    assert_eq!(report_c.total_blocks, 2, "Island C: unexpected block count");

    // ── 7. Frontier homogeneity: same frontier hash set across all nodes ─
    let frontier_a: HashSet<_> = bl_a.frontier().into_iter().collect();
    let frontier_b: HashSet<_> = bl_b.frontier().into_iter().collect();
    let frontier_c: HashSet<_> = bl_c.frontier().into_iter().collect();

    assert_eq!(frontier_a, frontier_b, "A and B frontiers diverged");
    assert_eq!(frontier_b, frontier_c, "B and C frontiers diverged");
}

// ─────────────────────────────────────────────────────────────────────────────
// §5.1 — External audit: hash link between local record and federation log
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn external_audit_hash_link() {
    // Node A holds a certified decision. Node C is the aggregation node.
    let mut bl_a = InMemoryBlocklace::new();
    let mut bl_c = InMemoryBlocklace::new();

    let decision_content = b"Motion to approve budget 2026";
    let payload = test_payload(decision_content, EventClass::Decision);
    let event_hash_a = payload.event_hash.clone();

    bl_a.append(payload, mock_sig()).unwrap();

    // A sends its EventHash to C (simulating the federation message)
    let delta = bl_a.sync_delta(&bl_c.frontier());
    bl_c.merge_blocks(delta).unwrap();

    // External auditor: recomputes hash from the original record and
    // checks it against what C holds in its Blocklace.
    let recomputed = Sha256Hash::digest(decision_content);
    assert_eq!(
        recomputed, event_hash_a,
        "Recomputed hash must match what A originally certified"
    );

    // C's Blocklace contains a block pointing to event_hash_a —
    // verify that the block is present and the chain is intact.
    let report_c = bl_c.verify_chain();
    assert!(report_c.valid);
    assert_eq!(report_c.total_blocks, 1);

    // The auditor can confirm integrity without accessing event content:
    // they hold event_hash_a (from A's disclosure) and verify it matches
    // the block in C's tamper-evident log.
    let block = bl_c
        .frontier()
        .iter()
        .filter_map(|h| bl_c.get_block(h))
        .find(|b| b.payload.event_hash == event_hash_a);

    assert!(
        block.is_some(),
        "C must hold a block referencing A's event hash — proof without exposure"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// §3.1 — Bilateral authentication: signed frontier responses
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn bilateral_authentication_with_real_signatures() {
    use fstp_core::crypto::verify_response_signature;
    use uuid::Uuid;

    let signer_a = NodeSigner::generate();
    let signer_b = NodeSigner::generate();
    let cii_a = ContextualId::new("cii:island-a");
    let cii_b = ContextualId::new("cii:island-b");
    let link_id: LinkId = Uuid::new_v4();

    let mut bl_a = InMemoryBlocklace::new();
    bl_a.append(test_payload(b"event-1", EventClass::Decision), mock_sig())
        .unwrap();
    let frontier_a = bl_a.frontier();
    let ts = fstp_core::utils::now_utc();

    let sig_a = signer_a.sign_response(&cii_a, &link_id, &frontier_a, &ts);

    // B verifies A's response using A's registered public key
    assert!(
        verify_response_signature(
            &cii_a,
            &link_id,
            &frontier_a,
            &ts,
            &sig_a,
            &signer_a.public_key()
        )
        .is_ok(),
        "Valid signature must verify"
    );

    // Tampered CII must be rejected
    assert!(
        verify_response_signature(
            &cii_b,
            &link_id,
            &frontier_a,
            &ts,
            &sig_a,
            &signer_a.public_key()
        )
        .is_err(),
        "Tampered CII must not verify"
    );

    // Wrong key must be rejected
    assert!(
        verify_response_signature(
            &cii_a,
            &link_id,
            &frontier_a,
            &ts,
            &sig_a,
            &signer_b.public_key()
        )
        .is_err(),
        "Signature from A must not verify under B's key"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// §3.3 — Erasure without integrity loss (dangling pointer mechanism)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn erasure_preserves_chain_integrity() {
    use fstp_core::blocklace::ErasureReason;

    let mut bl = InMemoryBlocklace::new();

    let personal_payload = test_payload(
        b"personal data subject to GDPR Art.17",
        EventClass::MembershipChange,
    );
    let event_hash = personal_payload.event_hash.clone();

    bl.append(personal_payload, mock_sig()).unwrap();
    bl.append(
        test_payload(b"subsequent governance event", EventClass::Decision),
        mock_sig(),
    )
    .unwrap();

    // Fulfill erasure request — content deleted, block becomes a dangling pointer
    bl.fulfill_erasure(event_hash, ErasureReason::DataSubjectRequest)
        .unwrap();

    let report = bl.verify_chain();
    assert!(
        report.valid,
        "Chain must remain valid after erasure: {:?}",
        report.corrupted_blocks
    );
    assert_eq!(
        report.dangling_pointers, 1,
        "Exactly one dangling pointer expected"
    );
    assert_eq!(
        report.total_blocks, 2,
        "Block count unchanged — pointer persists"
    );
}
