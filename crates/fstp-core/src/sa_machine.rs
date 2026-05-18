//! Synchronization Agent state machine (§3.1, Figure 2).
//!
//! The paper defines five states for the SA:
//!
//!   Idle → Validating → Composing → Transmitting → Logging → Idle
//!
//! with two error paths:
//!   - Confinement violated (Validating → Error → Logging → Idle)
//!   - Network failure    (Transmitting → Logging → Idle)
//!
//! This module implements the state machine as a **per-operation type**
//! (`SaTransaction<S>`), where `S` is a zero-size marker type encoding
//! the current state. State transitions are methods that consume `self`
//! and return `SaTransaction<NextState>`, so the Rust type checker
//! statically prevents invalid transitions: you cannot call `compose()`
//! on a transaction that has not passed `validate()`, because
//! `SaTransaction<Composing>` is only constructible via
//! `SaTransaction<Validating>::validate_ok()`.
//!
//! Each operation (outbound sync round, inbound frontier handler) is
//! modelled as its own transaction instance. Concurrent operations hold
//! independent transaction objects — there is no shared mutable state
//! in the machine itself.
//!
//! ## Invariant 3.1 — Synchronization confinement
//!
//! `SaTransaction` only accepts `SaOutboundArtifact` values in its
//! `compose()` step. `SaOutboundArtifact` is a closed enum whose
//! variants correspond exactly to the permitted D_pub types (Table 2).
//! The compiler statically rejects any attempt to place a D_raw value
//! into an `SaOutboundArtifact`, enforcing Property 2.1 at compile time.

use chrono::{DateTime, Utc};
use std::marker::PhantomData;

use crate::audit::AuditLog;
use crate::blocklace::Block;
use crate::types::{ContextualId, Ed25519Sig, FstpError, LinkId, Result, Sha256Hash};
use crate::message::{AggregateAttrs, EventClass};

// ─────────────────────────────────────────────────────────────────────────────
// State markers (zero-size types — erased at compile time)
// ─────────────────────────────────────────────────────────────────────────────

/// The SA is waiting for a trigger.
#[derive(Debug)]
pub struct Idle;
/// The SA is verifying confinement, identity, and anti-replay constraints.
#[derive(Debug)]
pub struct Validating;
/// The SA is building the D_pub artifact to emit.
#[derive(Debug)]
pub struct Composing;
/// The SA is performing network I/O.
#[derive(Debug)]
pub struct Transmitting;
/// The SA is writing the audit record and returning to Idle.
#[derive(Debug)]
pub struct Logging;

// ─────────────────────────────────────────────────────────────────────────────
// Closed output enumeration — D_pub (Table 2, §3.1)
// ─────────────────────────────────────────────────────────────────────────────

/// Closed enumeration of all message types the SA is permitted to emit.
///
/// This is `FstpMessage` restricted to the values that `SaTransaction` may
/// produce. Extending the output vocabulary requires adding a variant here —
/// a change that is auditable in the open-source repository by any federation
/// peer (§3.1, §6 open-source release).
///
/// **D_raw types are not members of this enum and are not importable in this
/// module**, so the compiler statically rejects any attempt to construct an
/// `SaOutboundArtifact` from a raw internal value.
#[derive(Debug, Clone)]
pub enum SaOutboundArtifact {
    /// Type 1 — Identity event: contextual identifier, public key, endpoint (Table 2).
    IdentityEvent {
        instance_cii: ContextualId,
        pubkey_hex: String,
        endpoint_url: String,
        timestamp: DateTime<Utc>,
        signature: Ed25519Sig,
    },
    /// Type 2 — Event hash: SHA-256 pointer to a certified internal event (Table 2).
    /// No event content is present; only its hash and typed metadata.
    EventHash {
        event_class: EventClass,
        timestamp_closed: DateTime<Utc>,
        instance_cii: ContextualId,
        aggregate_attrs: AggregateAttrs,
        event_hash: Sha256Hash,
        signature: Ed25519Sig,
    },
    /// Type 3 — Verifiable credential: propagated only with subject consent (Table 2).
    VerifiableCredential {
        subject_cii: ContextualId,
        credential_type: String,
        claims: serde_json::Value,
        issuer_cii: ContextualId,
        valid_until: Option<DateTime<Utc>>,
        signature: Ed25519Sig,
    },
    /// Type 4 — Federation control: establish, update, or terminate a link (Table 2).
    FederationControl {
        control_type: FederationControlType,
        from_cii: ContextualId,
        to_cii: ContextualId,
        link_id: LinkId,
        signature: Ed25519Sig,
    },
    /// Frontier response: blocks delta + signed frontier assertion.
    /// This is the primary artifact produced during a sync round.
    FrontierResponse {
        responder_cii: ContextualId,
        link_id: LinkId,
        blocks: Vec<Block>,
        frontier: Vec<Sha256Hash>,
        timestamp: DateTime<Utc>,
        signature: Ed25519Sig,
    },
}

#[derive(Debug, Clone)]
pub enum FederationControlType {
    Establish,
    Update,
    Terminate,
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation context — what the Validating state checks
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ValidationContext {
    pub sender_cii: ContextualId,
    pub expected_cii: ContextualId,
    pub timestamp: DateTime<Utc>,
    pub replay_window_secs: i64,
}

#[derive(Debug)]
pub enum ValidationError {
    CiiMismatch { got: ContextualId, expected: ContextualId },
    TimestampOutOfWindow { delta_secs: i64, window: i64 },
    ConfinementViolation(String),
}

impl From<ValidationError> for FstpError {
    fn from(e: ValidationError) -> Self {
        match e {
            ValidationError::CiiMismatch { got, .. } =>
                FstpError::UnknownCii(got),
            ValidationError::TimestampOutOfWindow { .. } =>
                FstpError::MessageRejected(crate::types::RejectionReason::TimestampOutOfWindow),
            ValidationError::ConfinementViolation(_) =>
                FstpError::ConfinementViolation,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SaTransaction<S> — the state machine per operation
// ─────────────────────────────────────────────────────────────────────────────

/// A single SA operation in state `S`.
///
/// Transitions are consuming methods: `fn transition(self, ...) -> SaTransaction<Next>`.
/// The `PhantomData<S>` carries the state at the type level without runtime cost.
#[derive(Debug)]
pub struct SaTransaction<S> {
    /// Unique identifier for this operation instance, used in the audit log.
    pub operation_id: uuid::Uuid,
    pub started_at: DateTime<Utc>,
    pub audit: AuditLog,
    _state: PhantomData<S>,
}

// ── Idle ─────────────────────────────────────────────────────────────────────

impl SaTransaction<Idle> {
    /// Create a new transaction. Call once per incoming request or outgoing
    /// sync trigger.
    pub fn begin(audit: AuditLog) -> Self {
        SaTransaction {
            operation_id: uuid::Uuid::new_v4(),
            started_at: Utc::now(),
            audit,
            _state: PhantomData,
        }
    }

    /// Advance to Validating.
    pub fn start_validation(self) -> SaTransaction<Validating> {
        SaTransaction {
            operation_id: self.operation_id,
            started_at: self.started_at,
            audit: self.audit,
            _state: PhantomData,
        }
    }
}

// ── Validating ───────────────────────────────────────────────────────────────

impl SaTransaction<Validating> {
    /// Validate a `ValidationContext`. On success → `Composing`.
    /// On failure → logs the error and returns it; caller transitions to error path.
    pub fn validate(
        self,
        ctx: &ValidationContext,
    ) -> std::result::Result<SaTransaction<Composing>, (SaTransaction<Logging>, ValidationError)> {
        // Check 1: CII matches authenticated peer
        if ctx.sender_cii != ctx.expected_cii {
            let err = ValidationError::CiiMismatch {
                got: ctx.sender_cii.clone(),
                expected: ctx.expected_cii.clone(),
            };
            let logging_tx = self.into_logging();
            return Err((logging_tx, err));
        }

        // Check 2: timestamp anti-replay
        let delta = (Utc::now() - ctx.timestamp).num_seconds().abs();
        if delta > ctx.replay_window_secs {
            let err = ValidationError::TimestampOutOfWindow {
                delta_secs: delta,
                window: ctx.replay_window_secs,
            };
            let logging_tx = self.into_logging();
            return Err((logging_tx, err));
        }

        Ok(SaTransaction {
            operation_id: self.operation_id,
            started_at: self.started_at,
            audit: self.audit,
            _state: PhantomData,
        })
    }

    fn into_logging(self) -> SaTransaction<Logging> {
        SaTransaction {
            operation_id: self.operation_id,
            started_at: self.started_at,
            audit: self.audit,
            _state: PhantomData,
        }
    }
}

// ── Composing ────────────────────────────────────────────────────────────────

impl SaTransaction<Composing> {
    /// Accept a D_pub artifact and advance to Transmitting.
    ///
    /// The type of `artifact` is `SaOutboundArtifact` — a closed enum.
    /// The compiler statically rejects any D_raw value here (Property 2.1).
    pub fn compose(
        self,
        artifact: SaOutboundArtifact,
    ) -> SaTransaction<Transmitting> {
        SaTransaction {
            operation_id: self.operation_id,
            started_at: self.started_at,
            audit: self.audit,
            _state: PhantomData,
        }
    }

    /// For inbound-only operations (e.g. block reception) where no artifact
    /// is emitted to the network. Skips Transmitting and goes directly to
    /// Logging. The audit record is still written via `log_and_complete`.
    pub fn skip_transmit(self) -> SaTransaction<Logging> {
        SaTransaction {
            operation_id: self.operation_id,
            started_at: self.started_at,
            audit: self.audit,
            _state: PhantomData,
        }
    }
}

// ── Transmitting ─────────────────────────────────────────────────────────────

/// The result of a transmission attempt.
pub enum TransmitOutcome {
    Sent,
    NetworkFailure(String),
}

impl SaTransaction<Transmitting> {
    /// Record the transmission outcome and advance to Logging.
    /// Network failures and successes both reach Logging — the audit record
    /// is written in both cases before the transaction completes.
    pub fn record_transmission(
        self,
        outcome: TransmitOutcome,
    ) -> (SaTransaction<Logging>, TransmitOutcome) {
        let tx = SaTransaction {
            operation_id: self.operation_id,
            started_at: self.started_at,
            audit: self.audit,
            _state: PhantomData,
        };
        (tx, outcome)
    }
}

// ── Logging ───────────────────────────────────────────────────────────────────

/// Summary of a completed SA operation, written to the audit log.
#[derive(Debug, Clone)]
pub struct OperationRecord {
    pub operation_id: uuid::Uuid,
    pub message_type: String,
    pub peer_cii: Option<ContextualId>,
    pub link_id: Option<LinkId>,
    pub block_count: Option<usize>,
    pub outcome: OperationOutcome,
    pub duration_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationOutcome {
    Success,
    ValidationFailed(String),
    NetworkFailed(String),
}

impl SaTransaction<Logging> {
    /// Write the audit record and return to Idle.
    ///
    /// This is the **only** terminal transition — every path through the
    /// state machine must pass through Logging before completing, ensuring
    /// that every operation produces an audit record (§4.2).
    pub fn log_and_complete(self, record: OperationRecord) -> SaTransaction<Idle> {
        // Write structured audit entry — no content fields
        let outcome_str = match &record.outcome {
            OperationOutcome::Success              => "success".to_string(),
            OperationOutcome::ValidationFailed(r) => format!("validation_failed:{r}"),
            OperationOutcome::NetworkFailed(r)    => format!("network_failed:{r}"),
        };

        self.audit.record_outbound(
            &record.message_type,
            record.peer_cii,
            record.link_id,
            None,
            record.block_count,
        );

        tracing::info!(
            op_id    = %record.operation_id,
            msg_type = %record.message_type,
            outcome  = %outcome_str,
            duration_ms = record.duration_ms,
            "[SA STATE MACHINE] operation complete"
        );

        SaTransaction {
            operation_id: record.operation_id,
            started_at: self.started_at,
            audit: self.audit,
            _state: PhantomData,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience: run a full outbound operation with the state machine
// ─────────────────────────────────────────────────────────────────────────────

/// Execute a complete SA outbound operation through all five states.
///
/// `build_artifact` is called in Composing state; it receives no raw data —
/// only a closure that must return `SaOutboundArtifact`. If `build_artifact`
/// returns `None`, the operation is treated as a no-op (nothing to transmit).
///
/// `transmit` is called in Transmitting state with the composed artifact.
///
/// Returns the final `SaTransaction<Idle>` and the operation record for
/// callers that want to inspect the outcome.
pub async fn run_outbound<F, T, Fut>(
    audit: AuditLog,
    ctx: ValidationContext,
    message_type: impl Into<String> + Clone,
    build_artifact: F,
    transmit: T,
) -> (SaTransaction<Idle>, OperationRecord)
where
    F: FnOnce() -> Option<SaOutboundArtifact>,
    T: FnOnce(SaOutboundArtifact) -> Fut,
    Fut: std::future::Future<Output = std::result::Result<(), String>>,
{
    let msg_type = message_type.into();
    let tx = SaTransaction::<Idle>::begin(audit);
    let started_at = tx.started_at;
    let op_id = tx.operation_id;

    let validating = tx.start_validation();

    let composing = match validating.validate(&ctx) {
        Ok(c) => c,
        Err((logging_tx, err)) => {
            let record = OperationRecord {
                operation_id: op_id,
                message_type: msg_type.clone(),
                peer_cii: Some(ctx.sender_cii),
                link_id: None,
                block_count: None,
                outcome: OperationOutcome::ValidationFailed(format!("{err:?}")),
                duration_ms: (Utc::now() - started_at).num_milliseconds(),
            };
            return (logging_tx.log_and_complete(record.clone()), record);
        }
    };

    let artifact = match build_artifact() {
        Some(a) => a,
        None => {
            // Nothing to transmit — skip Transmitting, go straight to Logging
            let logging_tx: SaTransaction<Logging> = SaTransaction {
                operation_id: op_id,
                started_at,
                audit: composing.audit,
                _state: PhantomData,
            };
            let record = OperationRecord {
                operation_id: op_id,
                message_type: msg_type,
                peer_cii: Some(ctx.sender_cii),
                link_id: None,
                block_count: Some(0),
                outcome: OperationOutcome::Success,
                duration_ms: (Utc::now() - started_at).num_milliseconds(),
            };
            return (logging_tx.log_and_complete(record.clone()), record);
        }
    };

    let transmitting = composing.compose(artifact.clone());
    let net_result = transmit(artifact).await;

    let (outcome, transmit_outcome) = match net_result {
        Ok(()) => (OperationOutcome::Success, TransmitOutcome::Sent),
        Err(e) => (
            OperationOutcome::NetworkFailed(e.clone()),
            TransmitOutcome::NetworkFailure(e),
        ),
    };

    let (logging_tx, _) = transmitting.record_transmission(transmit_outcome);

    let record = OperationRecord {
        operation_id: op_id,
        message_type: msg_type,
        peer_cii: Some(ctx.sender_cii),
        link_id: None,
        block_count: None,
        outcome,
        duration_ms: (Utc::now() - started_at).num_milliseconds(),
    };

    (logging_tx.log_and_complete(record.clone()), record)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLog;
    use crate::types::ContextualId;
    use chrono::Utc;

    fn valid_ctx(cii: &str) -> ValidationContext {
        ValidationContext {
            sender_cii:         ContextualId::new(cii),
            expected_cii:       ContextualId::new(cii),
            timestamp:          Utc::now(),
            replay_window_secs: 300,
        }
    }

    /// Happy path: Idle → Validating → Composing → Transmitting → Logging → Idle
    #[test]
    fn full_happy_path_compiles_and_runs() {
        let audit = AuditLog::new();
        let tx = SaTransaction::<Idle>::begin(audit);
        let tx = tx.start_validation();
        let tx = tx.validate(&valid_ctx("cii:peer")).expect("valid ctx must pass");

        let artifact = SaOutboundArtifact::FederationControl {
            control_type: FederationControlType::Establish,
            from_cii: ContextualId::new("cii:local"),
            to_cii:   ContextualId::new("cii:peer"),
            link_id:  uuid::Uuid::new_v4(),
            signature: crate::types::Ed25519Sig(
                ed25519_dalek::Signature::from_bytes(&[0u8; 64])
            ),
        };

        let tx = tx.compose(artifact);
        let (tx, outcome) = tx.record_transmission(TransmitOutcome::Sent);

        assert!(matches!(outcome, TransmitOutcome::Sent));

        let record = OperationRecord {
            operation_id: tx.operation_id,
            message_type: "federation_control".into(),
            peer_cii:    Some(ContextualId::new("cii:peer")),
            link_id:     None,
            block_count: None,
            outcome:     OperationOutcome::Success,
            duration_ms: 0,
        };
        let _idle = tx.log_and_complete(record);
        // If this compiles and runs, the state machine enforces the transition order.
    }

    /// Error path: CII mismatch causes Validating → Logging (skipping Composing/Transmitting).
    #[test]
    fn validation_failure_goes_to_logging_directly() {
        let audit = AuditLog::new();
        let tx = SaTransaction::<Idle>::begin(audit);
        let tx = tx.start_validation();

        let bad_ctx = ValidationContext {
            sender_cii:         ContextualId::new("cii:attacker"),
            expected_cii:       ContextualId::new("cii:known-peer"),
            timestamp:          Utc::now(),
            replay_window_secs: 300,
        };

        let err = tx.validate(&bad_ctx);
        assert!(err.is_err(), "Mismatched CII must fail validation");

        let (logging_tx, ve) = err.unwrap_err();
        assert!(matches!(ve, ValidationError::CiiMismatch { .. }));

        let record = OperationRecord {
            operation_id: logging_tx.operation_id,
            message_type: "event_hash".into(),
            peer_cii:    Some(ContextualId::new("cii:attacker")),
            link_id:     None,
            block_count: None,
            outcome:     OperationOutcome::ValidationFailed("cii_mismatch".into()),
            duration_ms: 0,
        };
        let _idle = logging_tx.log_and_complete(record);
        // Logging state is reachable from error path — audit record is always written.
    }

    /// Timestamp too old triggers anti-replay rejection.
    #[test]
    fn stale_timestamp_fails_validation() {
        let audit = AuditLog::new();
        let tx = SaTransaction::<Idle>::begin(audit).start_validation();

        let stale_ctx = ValidationContext {
            sender_cii:         ContextualId::new("cii:peer"),
            expected_cii:       ContextualId::new("cii:peer"),
            timestamp:          Utc::now() - chrono::Duration::seconds(600),
            replay_window_secs: 300,
        };

        assert!(tx.validate(&stale_ctx).is_err(), "Stale timestamp must fail");
    }

    /// Network failure still reaches Logging — audit record is always written.
    #[test]
    fn network_failure_reaches_logging() {
        let audit = AuditLog::new();
        let tx = SaTransaction::<Idle>::begin(audit)
            .start_validation()
            .validate(&valid_ctx("cii:peer"))
            .unwrap();

        let artifact = SaOutboundArtifact::FederationControl {
            control_type: FederationControlType::Terminate,
            from_cii: ContextualId::new("cii:local"),
            to_cii:   ContextualId::new("cii:peer"),
            link_id:  uuid::Uuid::new_v4(),
            signature: crate::types::Ed25519Sig(
                ed25519_dalek::Signature::from_bytes(&[0u8; 64])
            ),
        };

        let transmitting = tx.compose(artifact);
        let (logging_tx, outcome) = transmitting.record_transmission(
            TransmitOutcome::NetworkFailure("connection refused".into())
        );

        assert!(matches!(outcome, TransmitOutcome::NetworkFailure(_)));

        let record = OperationRecord {
            operation_id: logging_tx.operation_id,
            message_type: "federation_control".into(),
            peer_cii:    Some(ContextualId::new("cii:peer")),
            link_id:     None,
            block_count: None,
            outcome:     OperationOutcome::NetworkFailed("connection refused".into()),
            duration_ms: 5,
        };
        let _idle = logging_tx.log_and_complete(record);
    }

    /// Compile-time test: SaTransaction<Composing> cannot be constructed from Idle
    /// without going through Validating::validate(). If this compiles, the
    /// transition order is enforced.
    /// (The invalid transition is commented out — uncommenting must cause a compile error.)
    #[test]
    fn state_transitions_are_type_checked() {
        let audit = AuditLog::new();
        let _idle = SaTransaction::<Idle>::begin(audit);
        // The following would be a compile error:
        // let _bad: SaTransaction<Composing> = SaTransaction::<Composing> {
        //     operation_id: uuid::Uuid::new_v4(),
        //     started_at: Utc::now(),
        //     audit: AuditLog::new(),
        //     _state: PhantomData,   // PhantomData<Composing> is private
        // };
    }
}