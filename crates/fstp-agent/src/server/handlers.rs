//! HTTP handler functions for the FSTP federation API.
//!
//! Each handler drives a complete `SaTransaction` cycle (§3.1, Figure 2):
//!   Idle → Validating → Composing → Transmitting → Logging → Idle
//!
//! The state machine enforces two invariants structurally:
//! - Every operation produces an audit record (Logging is the only terminal state).
//! - D_raw types cannot appear in any outbound artifact (SaOutboundArtifact is closed).

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};

use ed25519_dalek::Verifier;
use fstp_core::blocklace::{AggregateAttrs, Block, BlockPayload, BlocklaceStore};
use fstp_core::crypto::verify_request_signature;
use fstp_core::identity::FederationContext;
use fstp_core::inbound::InboundValidationError;
use fstp_core::message::{
    CredentialType, CredentialValidity, EventClass, FederationEventKind, FstpMessage,
    IdentityEventKind,
};
use fstp_core::sa_machine::{
    Idle, OperationOutcome, OperationRecord, SaOutboundArtifact, SaTransaction, TransmitOutcome,
    ValidationContext,
};
use fstp_core::types::{
    ContextualId, Did, Ed25519Sig, FederationEndpoint, FrontierRequest, FrontierResponse,
    Sha256Hash,
};
use fstp_core::utils::now_utc;

use crate::server::auth::{dev_trust_present_credential, PeerIdentity};
use crate::server::verify_credential::{verify_credential, VerifyCredentialInput};
use crate::server::SharedState;

// ─────────────────────────────────────────────────────────────────────────────
// POST /rpc/verify-credential  — Velyzor outbound contract v1 (no mTLS)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyCredentialHttpRequest {
    pub did: String,
    pub credential_json: String,
    pub signature_hex: String,
    pub pubkey_hex: String,
}

pub async fn verify_credential_http_handler(
    State(state): State<SharedState>,
    Json(req): Json<VerifyCredentialHttpRequest>,
) -> Response {
    let out = verify_credential(
        &state,
        VerifyCredentialInput {
            did: req.did,
            credential_json: req.credential_json,
            signature_hex: req.signature_hex,
            pubkey_hex: req.pubkey_hex,
        },
    )
    .await;
    let status = if out.is_valid {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, Json(out)).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /fstp/sync/frontier
// ─────────────────────────────────────────────────────────────────────────────

pub async fn frontier_handler(
    State(state): State<SharedState>,
    Extension(peer_identity): Extension<PeerIdentity>,
    Json(payload): Json<FrontierRequest>,
) -> Response {
    let state_read = state.read().await;
    let audit = state_read.audit.clone();
    let own_cii = state_read.own_cii.clone();
    drop(state_read);

    // ── Idle → Validating ──────────────────────────────────────────────────
    let tx = SaTransaction::<Idle>::begin(audit.clone());
    let validating = tx.start_validation();

    let ctx = ValidationContext {
        sender_cii: payload.sender_cii.clone(),
        expected_cii: peer_identity.entry.peer_cii.clone(),
        timestamp: payload.timestamp,
        replay_window_secs: 300,
    };

    let composing = match validating.validate(&ctx) {
        Ok(c) => c,
        Err((logging_tx, ve)) => {
            let record = OperationRecord {
                operation_id: logging_tx.operation_id,
                message_type: "FrontierRequest".into(),
                peer_cii: Some(payload.sender_cii.clone()),
                link_id: Some(payload.link_id),
                block_count: None,
                outcome: OperationOutcome::ValidationFailed(format!("{ve:?}")),
                duration_ms: 0,
            };
            logging_tx.log_and_complete(record);
            return (StatusCode::BAD_REQUEST, "VALIDATION_FAILED").into_response();
        }
    };

    // Verify FrontierRequest signature (Phase 2).
    {
        let state_read = state.read().await;
        if let Err(e) = verify_request_signature(
            &payload.sender_cii,
            &payload.link_id,
            &payload.frontier,
            &payload.timestamp,
            &payload.signature,
            &peer_identity.entry.peer_pubkey,
        ) {
            drop(state_read);
            tracing::warn!(error = %e, "FrontierRequest signature invalid");
            let state_read = state.read().await;
            state_read.audit.record_inbound_rejected(
                "frontier_request",
                Some(payload.sender_cii.clone()),
                "INVALID_REQUEST_SIGNATURE",
                fstp_core::types::RejectionReason::InvalidSignature,
            );
            drop(state_read);
            return (StatusCode::UNAUTHORIZED, "INVALID_REQUEST_SIGNATURE").into_response();
        }
    }

    // ── Composing: build D_pub artifact ───────────────────────────────────
    let state_read = state.read().await;
    let missing_blocks: Vec<Block> = state_read.blocklace.sync_delta(&payload.frontier);
    let local_frontier = state_read.blocklace.frontier();
    let timestamp = now_utc();
    let signature =
        state_read
            .signer
            .sign_response(&own_cii, &payload.link_id, &local_frontier, &timestamp);
    drop(state_read);

    let block_count = missing_blocks.len();

    let artifact = SaOutboundArtifact::FrontierResponse {
        responder_cii: own_cii.clone(),
        link_id: payload.link_id,
        blocks: missing_blocks.clone(),
        frontier: local_frontier.clone(),
        timestamp,
        signature: signature.clone(),
    };

    // ── Transmitting → Logging ─────────────────────────────────────────────
    let transmitting = composing.compose(artifact);

    let response = FrontierResponse {
        responder_cii: own_cii,
        link_id: payload.link_id,
        missing_blocks,
        responder_frontier: local_frontier,
        timestamp,
        signature,
    };

    let (logging_tx, _) = transmitting.record_transmission(TransmitOutcome::Sent);

    let record = OperationRecord {
        operation_id: logging_tx.operation_id,
        message_type: "FrontierResponse".into(),
        peer_cii: Some(payload.sender_cii),
        link_id: Some(payload.link_id),
        block_count: Some(block_count),
        outcome: OperationOutcome::Success,
        duration_ms: (now_utc() - logging_tx.started_at).num_milliseconds(),
    };
    logging_tx.log_and_complete(record);

    Json(response).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /fstp/sync/blocks
// ─────────────────────────────────────────────────────────────────────────────

pub async fn blocks_handler(
    State(state): State<SharedState>,
    Extension(peer_identity): Extension<PeerIdentity>,
    Json(incoming_blocks): Json<Vec<Block>>,
) -> Response {
    if incoming_blocks.is_empty() {
        return (StatusCode::OK, "No blocks received").into_response();
    }

    let block_count = incoming_blocks.len();

    // Inbound blocks pass through Validating (hash integrity is checked by
    // merge_blocks via compute_hash) then go straight to Logging — there is
    // no outbound artifact to compose or transmit.
    let state_read = state.read().await;
    let audit = state_read.audit.clone();
    drop(state_read);

    let tx = SaTransaction::<Idle>::begin(audit);
    let validating = tx.start_validation();

    // For inbound block pushes the "sender CII" is authenticated via mTLS;
    // we use a permissive validation context (CIIs match by construction).
    let ctx = ValidationContext {
        sender_cii: peer_identity.entry.peer_cii.clone(),
        expected_cii: peer_identity.entry.peer_cii.clone(),
        timestamp: now_utc(),
        replay_window_secs: 300,
    };

    let composing = match validating.validate(&ctx) {
        Ok(c) => c,
        Err((logging_tx, ve)) => {
            let record = OperationRecord {
                operation_id: logging_tx.operation_id,
                message_type: "BlockPush".into(),
                peer_cii: peer_identity.cii.clone(),
                link_id: None,
                block_count: Some(block_count),
                outcome: OperationOutcome::ValidationFailed(format!("{ve:?}")),
                duration_ms: 0,
            };
            logging_tx.log_and_complete(record);
            return (StatusCode::BAD_REQUEST, "VALIDATION_FAILED").into_response();
        }
    };

    // Merge the blocks — hash integrity is checked inside merge_blocks
    let merge_result = {
        let mut state_write = state.write().await;
        state_write.blocklace.merge_blocks(incoming_blocks)
    };

    let (outcome, status) = match merge_result {
        Ok(()) => (OperationOutcome::Success, StatusCode::OK),
        Err(e) => (
            OperationOutcome::ValidationFailed(e.to_string()),
            StatusCode::BAD_REQUEST,
        ),
    };

    // Inbound operation: skip Transmitting, go directly to Logging.
    // The audit record is always written regardless of outcome.
    let logging_tx = composing.skip_transmit();
    let record = OperationRecord {
        operation_id: logging_tx.operation_id,
        message_type: "BlockPush".into(),
        peer_cii: peer_identity.cii.clone(),
        link_id: None,
        block_count: Some(block_count),
        outcome: outcome.clone(),
        duration_ms: (now_utc() - logging_tx.started_at).num_milliseconds(),
    };
    logging_tx.log_and_complete(record);

    match outcome {
        OperationOutcome::Success => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "success" })),
        )
            .into_response(),
        _ => (status, "MERGE_FAILED").into_response(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /fstp/health
// ─────────────────────────────────────────────────────────────────────────────

pub async fn health_handler(State(state): State<SharedState>) -> Response {
    let state_guard = state.read().await;
    let report = state_guard.blocklace.verify_chain();
    let peer_count = state_guard.federation.len();
    let audit_len = state_guard.audit.len();

    let status = if report.valid {
        StatusCode::OK
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };

    let body = serde_json::json!({
        "valid":           report.valid,
        "total_blocks":    report.total_blocks,
        "frontier_size":   report.frontier_size,
        "dangling_pointers": report.dangling_pointers,
        "corrupted_blocks": report.corrupted_blocks.len(),
        "peer_count":      peer_count,
        "audit_records":   audit_len,
    });

    (status, Json(body)).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /fstp/admin/peers  — runtime peer registration (Hito 1 / Velyzor)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct RegisterPeerRequest {
    pub peer_cii: String,
    pub link_id: uuid::Uuid,
    pub cert_fingerprint: String,
    pub endpoint_url: String,
    /// Hex-encoded Ed25519 public key of the peer (32 bytes).
    /// Received via the peer's IdentityEvent during link establishment.
    pub peer_pubkey_hex: String,
    /// Institutional DID for HU-06 lookup (optional, Phase 3).
    pub peer_did: Option<String>,
}

/// **POST /fstp/admin/peers**
///
/// Registers a new federation peer without restarting the agent.
/// Must be protected by network policy (loopback-only or separate auth)
/// in production — it is not protected by mTLS middleware.
///
/// Returns 201 on success, 400 if pubkey is malformed, 409 if already registered.
pub async fn register_peer_handler(
    State(state): State<SharedState>,
    Json(req): Json<RegisterPeerRequest>,
) -> Response {
    use crate::server::FederationEntry;
    use fstp_core::types::{ContextualId, FederationEndpoint, PublicKey};

    let pubkey_bytes = match hex::decode(&req.peer_pubkey_hex) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid peer_pubkey_hex"})),
            )
                .into_response()
        }
    };

    let pubkey_array: [u8; 32] = match pubkey_bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "peer_pubkey_hex must be 32 bytes"})),
            )
                .into_response()
        }
    };

    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&pubkey_array) {
        Ok(k) => k,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("invalid Ed25519 pubkey: {e}")})),
            )
                .into_response()
        }
    };

    let mut state_guard = state.write().await;

    if state_guard.federation.contains_key(&req.cert_fingerprint) {
        if state_guard.upsert_peer_metadata(
            &req.cert_fingerprint,
            &req.endpoint_url,
            req.peer_did.clone(),
            PublicKey(verifying_key),
        ) {
            tracing::info!(
                peer_cii = %req.peer_cii,
                link_id = %req.link_id,
                peer_did = ?req.peer_did,
                "Admin: federation peer metadata updated (upsert)"
            );
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "updated",
                    "peer_cii": req.peer_cii,
                    "link_id": req.link_id.to_string(),
                })),
            )
                .into_response();
        }
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "peer already registered"})),
        )
            .into_response();
    }

    state_guard.register_peer(FederationEntry {
        peer_cii: ContextualId::new(&req.peer_cii),
        link_id: req.link_id,
        cert_fingerprint: req.cert_fingerprint.clone(),
        endpoint: FederationEndpoint::new(&req.endpoint_url, &req.cert_fingerprint),
        peer_did: req.peer_did.clone(),
        peer_pubkey: PublicKey(verifying_key),
    });

    tracing::info!(
        peer_cii = %req.peer_cii,
        link_id  = %req.link_id,
        "Admin: new federation peer registered at runtime"
    );

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status":   "registered",
            "peer_cii": req.peer_cii,
            "link_id":  req.link_id.to_string(),
        })),
    )
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /fstp/present-credential  — portable identity (Phase 2)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct PresentCredentialRequest {
    pub link_id: uuid::Uuid,
    pub counterpart_url: String,
    pub subject_id: String,
    pub credential_type: CredentialType,
    pub claims: serde_json::Value,
    pub issuer_did: String,
    pub validity: CredentialValidity,
    pub signature_hex: String,
}

#[derive(Debug, serde::Serialize)]
struct PresentCredentialSignable<'a> {
    link_id: uuid::Uuid,
    counterpart_url: &'a str,
    subject_id: &'a str,
    credential_type: &'a CredentialType,
    claims: &'a serde_json::Value,
    issuer_did: &'a str,
    validity: &'a CredentialValidity,
}

/// **POST /fstp/present-credential**
///
/// Federated peer presents a VC on behalf of a subject with consent.
/// Derives `subject_cii` via HKDF and records an `EventHash` in the Blocklace.
pub async fn present_credential_handler(
    State(state): State<SharedState>,
    peer_identity: Option<Extension<PeerIdentity>>,
    Json(req): Json<PresentCredentialRequest>,
) -> Response {
    let peer_identity = match resolve_peer_identity(state.clone(), peer_identity, &req).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let signable = match serde_json::to_vec(&PresentCredentialSignable {
        link_id: req.link_id,
        counterpart_url: &req.counterpart_url,
        subject_id: &req.subject_id,
        credential_type: &req.credential_type,
        claims: &req.claims,
        issuer_did: &req.issuer_did,
        validity: &req.validity,
    }) {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "INVALID_PAYLOAD").into_response();
        }
    };

    let issuer_did = Did::new(&req.issuer_did);
    let signature = match parse_ed25519_sig_hex(&req.signature_hex) {
        Ok(s) => s,
        Err(status) => return status.into_response(),
    };

    let (subject_cii, audit) = {
        let state_read = state.read().await;
        let issuer_pk = match state_read.issuer_registry.lookup(&issuer_did) {
            Some(pk) => pk.clone(),
            None => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({"error": "issuer not in trusted registry"})),
                )
                    .into_response();
            }
        };

        if issuer_pk.0.verify(&signable, &signature.0).is_err() {
            tracing::warn!(issuer = %req.issuer_did, "PresentCredential signature invalid");
            return (StatusCode::UNAUTHORIZED, "INVALID_CREDENTIAL_SIGNATURE").into_response();
        }

        let ctx = FederationContext::new(
            req.link_id,
            FederationEndpoint::new(&req.counterpart_url, &peer_identity.cert_fingerprint),
        );
        let subject_cii = state_read.gii.derive_subject_cii(&ctx, &req.subject_id);
        (subject_cii, state_read.audit.clone())
    };

    let tx = SaTransaction::<Idle>::begin(audit);
    let validating = tx.start_validation();
    let ctx = ValidationContext {
        sender_cii: peer_identity.entry.peer_cii.clone(),
        expected_cii: peer_identity.entry.peer_cii.clone(),
        timestamp: now_utc(),
        replay_window_secs: 300,
    };
    let composing = match validating.validate(&ctx) {
        Ok(c) => c,
        Err((logging_tx, ve)) => {
            let record = OperationRecord {
                operation_id: logging_tx.operation_id,
                message_type: "verifiable_credential".into(),
                peer_cii: peer_identity.cii.clone(),
                link_id: Some(req.link_id),
                block_count: None,
                outcome: OperationOutcome::ValidationFailed(format!("{ve:?}")),
                duration_ms: 0,
            };
            logging_tx.log_and_complete(record);
            return (StatusCode::BAD_REQUEST, "VALIDATION_FAILED").into_response();
        }
    };

    let payload = BlockPayload {
        event_hash: Sha256Hash::digest(&signable),
        event_class: EventClass::CredentialLifecycle,
        aggregate_attrs: AggregateAttrs {
            participant_count: Some(1),
            quorum_reached: Some(true),
            rounds_completed: Some(1),
        },
    };
    let block_hash = {
        let mut state_write = state.write().await;
        match state_write.blocklace.append(payload, signature.clone()) {
            Ok(block) => format!("{}", block.block_hash),
            Err(e) => {
                tracing::error!(error = %e, "PresentCredential blocklace append failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "BLOCKLACE_APPEND_FAILED")
                    .into_response();
            }
        }
    };
    let artifact = SaOutboundArtifact::VerifiableCredential {
        subject_cii: subject_cii.clone(),
        credential_type: format!("{:?}", req.credential_type),
        claims: req.claims.clone(),
        issuer_cii: ContextualId::new(&req.issuer_did),
        valid_until: Some(req.validity.valid_until),
        signature,
    };
    let transmitting = composing.compose(artifact);
    let (logging_tx, _) = transmitting.record_transmission(TransmitOutcome::Sent);
    let record = OperationRecord {
        operation_id: logging_tx.operation_id,
        message_type: "verifiable_credential".into(),
        peer_cii: peer_identity.cii.clone(),
        link_id: Some(req.link_id),
        block_count: None,
        outcome: OperationOutcome::Success,
        duration_ms: (now_utc() - logging_tx.started_at).num_milliseconds(),
    };
    logging_tx.log_and_complete(record);

    crate::velyzor_notify::notify_presentation(
        &req.counterpart_url,
        &req.subject_id,
        &format!("{:?}", req.credential_type),
        &subject_cii,
    )
    .await;

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status": "recorded",
            "subject_cii": subject_cii.0,
            "block_hash": block_hash,
        })),
    )
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /fstp/federation/control  — federation lifecycle (Phase 2)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct FederationControlHttpRequest {
    pub link_id: uuid::Uuid,
    pub event: FederationEventKind,
    pub from_cii: String,
    pub to_cii: String,
    pub governance_proof_hash: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub signature_hex: String,
}

#[derive(Debug, serde::Serialize)]
struct FederationControlSignable<'a> {
    link_id: uuid::Uuid,
    event: &'a FederationEventKind,
    from_cii: &'a str,
    to_cii: &'a str,
    governance_proof_hash: Option<&'a str>,
    timestamp: chrono::DateTime<chrono::Utc>,
}

pub async fn federation_control_handler(
    State(state): State<SharedState>,
    Extension(peer_identity): Extension<PeerIdentity>,
    headers: axum::http::HeaderMap,
    Json(req): Json<FederationControlHttpRequest>,
) -> Response {
    if req.from_cii != peer_identity.entry.peer_cii.0 {
        return (StatusCode::FORBIDDEN, "FROM_CII_MISMATCH").into_response();
    }

    if matches!(
        req.event,
        FederationEventKind::Terminate | FederationEventKind::Reject
    ) {
        let state_read = state.read().await;
        if let Some(denied) =
            super::quorum_admin::require_quorum_token(&state_read, &headers)
        {
            return denied;
        }
    }

    let signable = match serde_json::to_vec(&FederationControlSignable {
        link_id: req.link_id,
        event: &req.event,
        from_cii: &req.from_cii,
        to_cii: &req.to_cii,
        governance_proof_hash: req.governance_proof_hash.as_deref(),
        timestamp: req.timestamp,
    }) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "INVALID_PAYLOAD").into_response(),
    };

    let signature = match parse_ed25519_sig_hex(&req.signature_hex) {
        Ok(s) => s,
        Err(status) => return status.into_response(),
    };

    if let Err(e) = peer_identity
        .entry
        .peer_pubkey
        .0
        .verify(&signable, &signature.0)
    {
        tracing::warn!(error = %e, "FederationControl signature invalid");
        return (StatusCode::UNAUTHORIZED, "INVALID_CONTROL_SIGNATURE").into_response();
    }

    let _proof_hash = req
        .governance_proof_hash
        .as_ref()
        .and_then(|h| hex::decode(h).ok())
        .map(|b| Sha256Hash::digest(&b));

    let audit = {
        let state_read = state.read().await;
        state_read.audit.clone()
    };

    let tx = SaTransaction::<Idle>::begin(audit);
    let validating = tx.start_validation();
    let ctx = ValidationContext {
        sender_cii: peer_identity.entry.peer_cii.clone(),
        expected_cii: peer_identity.entry.peer_cii.clone(),
        timestamp: req.timestamp,
        replay_window_secs: 300,
    };
    let composing = match validating.validate(&ctx) {
        Ok(c) => c,
        Err((logging_tx, ve)) => {
            let record = OperationRecord {
                operation_id: logging_tx.operation_id,
                message_type: "federation_control".into(),
                peer_cii: peer_identity.cii.clone(),
                link_id: Some(req.link_id),
                block_count: None,
                outcome: OperationOutcome::ValidationFailed(format!("{ve:?}")),
                duration_ms: 0,
            };
            logging_tx.log_and_complete(record);
            return (StatusCode::BAD_REQUEST, "VALIDATION_FAILED").into_response();
        }
    };

    let payload = BlockPayload {
        event_hash: Sha256Hash::digest(&signable),
        event_class: EventClass::FederationLifecycle,
        aggregate_attrs: AggregateAttrs {
            participant_count: Some(2),
            quorum_reached: Some(matches!(
                req.event,
                FederationEventKind::Accept | FederationEventKind::Resume
            )),
            rounds_completed: None,
        },
    };
    let block_hash = {
        let mut state_write = state.write().await;
        match state_write.blocklace.append(payload, signature.clone()) {
            Ok(block) => format!("{}", block.block_hash),
            Err(e) => {
                tracing::error!(error = %e, "FederationControl blocklace append failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "BLOCKLACE_APPEND_FAILED")
                    .into_response();
            }
        }
    };

    let control_type = match req.event {
        FederationEventKind::Propose | FederationEventKind::Accept => {
            fstp_core::sa_machine::FederationControlType::Establish
        }
        FederationEventKind::Terminate | FederationEventKind::Reject => {
            fstp_core::sa_machine::FederationControlType::Terminate
        }
        FederationEventKind::Suspend | FederationEventKind::Resume => {
            fstp_core::sa_machine::FederationControlType::Update
        }
    };

    let artifact = SaOutboundArtifact::FederationControl {
        control_type,
        from_cii: ContextualId::new(&req.from_cii),
        to_cii: ContextualId::new(&req.to_cii),
        link_id: req.link_id,
        signature,
    };
    let transmitting = composing.compose(artifact);
    let (logging_tx, _) = transmitting.record_transmission(TransmitOutcome::Sent);
    let record = OperationRecord {
        operation_id: logging_tx.operation_id,
        message_type: "federation_control".into(),
        peer_cii: peer_identity.cii.clone(),
        link_id: Some(req.link_id),
        block_count: None,
        outcome: OperationOutcome::Success,
        duration_ms: (now_utc() - logging_tx.started_at).num_milliseconds(),
    };
    logging_tx.log_and_complete(record);

    let event_hash = Sha256Hash::digest(&signable);
    crate::velyzor_notify::notify_federation_event(
        EventClass::FederationLifecycle,
        &req.from_cii,
        &event_hash,
        req.link_id,
    )
    .await;

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "status": "accepted",
            "event": req.event,
            "block_hash": block_hash,
        })),
    )
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /fstp/federation/identity  — IdentityEvent (heartbeat, CII announcement)
// ─────────────────────────────────────────────────────────────────────────────

pub async fn identity_event_handler(
    State(state): State<SharedState>,
    Extension(peer_identity): Extension<PeerIdentity>,
    Json(msg): Json<FstpMessage>,
) -> Response {
    let FstpMessage::IdentityEvent { instance_cii, .. } = &msg else {
        let state_read = state.read().await;
        state_read.audit.record_inbound_rejected(
            "identity_event",
            None,
            "NOT_IDENTITY_EVENT",
            fstp_core::types::RejectionReason::UnknownMessageType,
        );
        return (StatusCode::BAD_REQUEST, "NOT_IDENTITY_EVENT").into_response();
    };

    let expected = peer_identity.entry.peer_cii.clone();
    let validation = {
        let state_read = state.read().await;
        state_read.inbound_validator.validate_fstp_message(
            &msg,
            &expected,
            &expected,
            &peer_identity.entry.peer_pubkey,
        )
    };

    if let Err(err) = validation {
        let reason = err.rejection_reason();
        let summary = format!("{err:?}");
        let state_read = state.read().await;
        state_read.audit.record_inbound_rejected(
            "identity_event",
            Some(instance_cii.clone()),
            summary,
            reason,
        );
        let status = match err {
            InboundValidationError::InvalidSignature => StatusCode::UNAUTHORIZED,
            _ => StatusCode::BAD_REQUEST,
        };
        return (status, "IDENTITY_EVENT_REJECTED").into_response();
    }

    if !matches!(
        &msg,
        FstpMessage::IdentityEvent {
            event: IdentityEventKind::InstanceAlive,
            ..
        }
    ) {
        tracing::info!(?msg, "Identity event accepted (non-heartbeat)");
    }

    let state_read = state.read().await;
    state_read.audit.record_inbound(
        "identity_event",
        Some(instance_cii.clone()),
        Some(peer_identity.entry.link_id),
        None,
        None,
    );
    drop(state_read);

    (StatusCode::OK, Json(serde_json::json!({ "status": "accepted" }))).into_response()
}

async fn resolve_peer_identity(
    state: SharedState,
    ext: Option<Extension<PeerIdentity>>,
    req: &PresentCredentialRequest,
) -> Result<PeerIdentity, Response> {
    if let Some(Extension(peer)) = ext {
        return Ok(peer);
    }
    if !dev_trust_present_credential() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "client certificate required for present-credential",
        )
            .into_response());
    }
    let entry = {
        let state_read = state.read().await;
        state_read
            .federation
            .values()
            .find(|e| e.link_id == req.link_id)
            .cloned()
    };
    let entry = entry.ok_or_else(|| {
        (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "unknown link_id — register peer via POST /fstp/admin/peers"
            })),
        )
            .into_response()
    })?;
    let fingerprint = entry.cert_fingerprint.clone();
    Ok(PeerIdentity {
        cii: Some(entry.peer_cii.clone()),
        cert_fingerprint: fingerprint,
        entry,
    })
}

fn parse_ed25519_sig_hex(hex_str: &str) -> Result<Ed25519Sig, StatusCode> {
    let bytes = hex::decode(hex_str.trim()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let sig = ed25519_dalek::Signature::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Ed25519Sig(sig))
}
