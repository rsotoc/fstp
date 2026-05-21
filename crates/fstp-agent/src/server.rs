// src/server.rs

// 1. Declaramos los submódulos que están dentro de la carpeta server/
mod auth;
pub mod blocklace_admin;
pub mod federation;
pub mod grpc;
mod handlers;
mod integration;
mod verify_credential;

// 2. Re-exportaciones Modernas e Idiomáticas
pub use federation::{serve, FederationEntry, ServerState, SharedState, TlsParams};
pub use grpc::serve_grpc;
