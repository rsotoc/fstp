// src/server.rs

// 1. Declaramos los submódulos que están dentro de la carpeta server/
mod auth;
pub mod bbs_crypto;
pub mod blocklace_admin;
pub mod federation;
pub mod local_admin;
pub mod outbound_admin;
pub mod bbs_trusted_issuers_admin;
pub mod trusted_issuers_admin;
pub mod quorum_admin;
pub mod sync_admin;
pub mod transparent_admin;
mod mtls_accept;
pub mod grpc;
mod handlers;
mod integration;
mod verify_credential;

// 2. Re-exportaciones Modernas e Idiomáticas
pub use federation::{serve, FederationEntry, ServerState, SharedState, TlsParams};
pub use grpc::serve_grpc;
