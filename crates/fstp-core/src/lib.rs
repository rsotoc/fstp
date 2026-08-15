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
pub mod bbs_ietf;
pub mod bbs_plus;
pub mod blocklace;
pub mod crypto;
pub mod governance_notification;
pub mod identity;
pub mod inbound;
pub mod message;
pub mod offline_queue;
pub mod pod_store;
pub mod quorum;
pub mod registry;
pub mod sa_machine;
pub mod sync_crdt;
pub mod sync_policy;
pub mod transparent_log;
pub mod types;
pub mod utils;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use audit::{AuditLog, AuditRecord, Direction};

pub use bbs_plus::{
    canonical_messages_from_subject, derive_proof, generate_key_pair, sign_messages, verify_proof,
    BbsDeriveProofRequest, BbsDerivedProofBundle, BbsKeyPairHex, BbsSignRequest, BbsSignResponse,
    BbsVerifyProofRequest, BbsVerifyProofResponse,
};

pub use bbs_ietf::{
    capability_metadata as bbs_ietf_capability_metadata, derive_proof as ietf_derive_proof,
    generate_key_pair as ietf_generate_key_pair, sign_messages as ietf_sign_messages,
    verify_proof as ietf_verify_proof, BbsIetfDeriveProofRequest, BbsIetfDerivedProofBundle,
    BbsIetfKeyPairHex, BbsIetfSignRequest, BbsIetfSignResponse, BbsIetfVerifyProofRequest,
    BbsIetfVerifyProofResponse, CRYPTO_PROFILE as BBS_IETF_CRYPTO_PROFILE,
    PROOF_TYPE as BBS_IETF_PROOF_TYPE,
};

pub use blocklace::{
    AggregateAttrs, Block, BlockPayload, BlocklaceStore, DanglingPointer, ErasureReason,
    FrontierExport, InMemoryBlocklace, IntegrityReport,
};

pub use governance_notification::{
    GovernanceEventNotification, GovernanceNotifyError, CONTENT_HASH_LEN, ED25519_SIG_LEN,
};

pub use crypto::{
    verify_identity_event_signature, verify_request_signature, verify_response_signature,
    NodeSigner,
};

pub use inbound::{InboundValidationError, InboundValidator, DEFAULT_REPLAY_WINDOW_SECS};

pub use offline_queue::{backoff_delay, OfflineOutboundQueue, OfflineQueueStats, OutboundTask, OutboundTaskKind};

pub use sync_policy::{
    default_sync_policy, SyncPolicy, DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_HEARTBEAT_INTERVAL_MINS,
    DEFAULT_MAX_SEND_RETRIES, DEFAULT_OFFLINE_QUEUE_CAPACITY, DEFAULT_RESPONSE_TIMEOUT_SECS,
    MAX_HEARTBEAT_INTERVAL_MINS, MIN_HEARTBEAT_INTERVAL_MINS,
};

pub use identity::{FederationContext, GlobalInstanceId};
pub use registry::IssuerRegistry;

pub use message::{
    CredentialType, CredentialValidity, EventClass, FederationEventKind, FstpMessage,
    IdentityEventKind,
};

pub use pod_store::{
    EncryptedPodStore, Manifest, ManifestEntry, PodPath, PodStore,
};

pub use quorum::{
    shamir_combine, shamir_split, sign_with_seed, succession_admin_signable, validate_quorum_config,
    verify_admin_signature, QuorumAdmin, QuorumConfig, QuorumShareSubmission, ShamirSplitResult,
    StoredShare, SuccessionReason, SuccessionRecord,
};

pub use sync_crdt::{
    ConflictedValue, ConflictSummary, DecisionRoomSnapshot, InstanceStatus, MemberSnapshot,
    RecordEntry, SignedDeduction, SyncCrdtEngine, SyncStateFile, SyncStatus,
};

pub use transparent_log::{
    LogDirection, LogEntry, LogFilter, LogStats, TransparentIntegrityReport, TransparentLog,
    TransparentRejectionReason,
};

pub use sa_machine::{
    Composing, FederationControlType, Idle, Logging, OperationOutcome, OperationRecord,
    SaOutboundArtifact, SaTransaction, TransmitOutcome, Transmitting, Validating,
    ValidationContext, ValidationError,
};

pub use types::{
    ContextualId, Did, Ed25519Sig, FederationEndpoint, FrontierRequest, FrontierResponse,
    FstpError, LinkId, PublicKey, RejectionReason, Result, Sha256Hash, SyncOutcome, SyncResult,
};

pub use utils::now_utc;
