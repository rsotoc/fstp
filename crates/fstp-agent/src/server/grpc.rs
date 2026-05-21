use tonic::{Request, Response, Status};

pub mod fstp {
    tonic::include_proto!("fstp");
}

use fstp::fstp_service_server::FstpService;
use fstp::{CredentialRequest, VerificationResponse};

use crate::server::verify_credential::{verify_credential, VerifyCredentialInput};
use crate::server::SharedState;

#[derive(Debug)]
pub struct FstpGrpcServer {
    state: SharedState,
}

impl FstpGrpcServer {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl FstpService for FstpGrpcServer {
    /// Validates a signed credential and appends an `EventHash` block.
    /// Issuer keys are resolved from `IssuerRegistry` (Phase 2).
    async fn verify_credential(
        &self,
        request: Request<CredentialRequest>,
    ) -> Result<Response<VerificationResponse>, Status> {
        let req = request.into_inner();
        let out = verify_credential(
            &self.state,
            VerifyCredentialInput {
                did: req.did,
                credential_json: req.credential_json,
                signature_hex: req.signature_hex,
                pubkey_hex: req.pubkey_hex,
            },
        )
        .await;

        Ok(Response::new(VerificationResponse {
            is_valid: out.is_valid,
            error_message: out.error_message,
        }))
    }
}

/// Starts the local gRPC server (loopback integration with Ágora JVM).
pub async fn serve_grpc(addr: &str, state: SharedState) -> Result<(), Box<dyn std::error::Error>> {
    let socket_addr = addr.parse()?;
    let service = FstpGrpcServer::new(state);

    tracing::info!("FSTP local gRPC gateway listening on {socket_addr}");

    tonic::transport::Server::builder()
        .add_service(fstp::fstp_service_server::FstpServiceServer::new(service))
        .serve(socket_addr)
        .await?;

    Ok(())
}
