//! # fstp-core
//!
//! Protocol primitives for the Federated Sovereign Transport Protocol (FSTP).
//!
//! This crate contains exactly the three protocol primitives described in §3:
//!
//! - **Synchronization Agent** ([`sa_machine`], [`message`]): the closed output
//!   enumeration [`message::FstpMessage`] and the state machine that enforces
//!   Property 2.1 (synchronization confinement) at compile time.
//!
//! - **Contextual Identity** ([`identity`]): [`identity::GlobalInstanceId`] and
//!   HKDF-derived [`types::ContextualId`] values that are unlinkable across
//!   federation relationships (Property 3.1).
//!
//! - **Blocklace** ([`blocklace`]): tamper-evident DAG with O(Δ) synchronization
//!   cost and erasure compatibility without integrity loss (Property 3.3).
//!
//! ## Auditing the confinement boundary
//!
//! The closed output enumeration is [`message::FstpMessage`]. Any federation
//! peer can verify the confinement guarantee by inspecting this enum:
//! if `D_raw` types are not members of `FstpMessage` and are not importable
//! in the message module, the compiler statically rejects any attempt to
//! construct a federation message from internal data (§3.1, §6).
//!
//! Extending the output vocabulary requires adding a variant to `FstpMessage`
//! — a change that is visible and auditable in this open-source repository.

pub mod audit;
pub mod blocklace;
pub mod crypto;
pub mod identity;
pub mod registry;
pub mod message;
pub mod sa_machine;
pub mod types;
pub mod utils;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use audit::{AuditLog, AuditRecord, Direction};

pub use blocklace::{
    AggregateAttrs, Block, BlockPayload, BlocklaceStore, DanglingPointer,
    ErasureReason, FrontierExport, InMemoryBlocklace, IntegrityReport,
};

pub use crypto::{verify_request_signature, verify_response_signature, NodeSigner};

pub use identity::{FederationContext, GlobalInstanceId};
pub use registry::IssuerRegistry;

pub use message::{
    CredentialType, CredentialValidity, EventClass,
    FederationEventKind, IdentityEventKind, FstpMessage,
};

pub use sa_machine::{
    FederationControlType, OperationOutcome, OperationRecord, SaOutboundArtifact,
    SaTransaction, TransmitOutcome, ValidationContext, ValidationError,
    Composing, Idle, Logging, Transmitting, Validating,
};

pub use types::{
    ContextualId, Did, Ed25519Sig, FederationEndpoint, FrontierRequest,
    FrontierResponse, FstpError, LinkId, PublicKey, RejectionReason, Result,
    Sha256Hash, SyncOutcome, SyncResult,
};

pub use utils::now_utc;