//! Injects TLS peer certificates into axum request extensions for federation auth (P5 / IP-02).

use crate::server::auth::TlsClientCert;
use axum::http::Request;
use axum_server::accept::Accept;
use axum_server::tls_rustls::RustlsConfig;
use hyper::body::Incoming;
use pin_project_lite::pin_project;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::{timeout, Timeout};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tower_service::Service;

/// TLS acceptor that attaches the negotiated client certificate to each HTTP request.
#[derive(Clone, Debug)]
pub struct ClientCertInjectAcceptor {
    config: RustlsConfig,
    handshake_timeout: Duration,
}

impl ClientCertInjectAcceptor {
    pub fn new(config: RustlsConfig) -> Self {
        Self {
            config,
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

impl<S> Accept<TcpStream, S> for ClientCertInjectAcceptor
where
    S: Clone + Send + 'static,
{
    type Stream = TlsStream<TcpStream>;
    type Service = CertInjectService<S>;
    type Future = ClientCertInjectAcceptFuture<S>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let server_config = self.config.get_inner();
        let acceptor = TlsAcceptor::from(server_config);
        ClientCertInjectAcceptFuture {
            inner: timeout(self.handshake_timeout, acceptor.accept(stream)),
            service: Some(service),
        }
    }
}

pin_project! {
    pub struct ClientCertInjectAcceptFuture<S> {
        #[pin]
        inner: Timeout<tokio_rustls::Accept<TcpStream>>,
        service: Option<S>,
    }
}

impl<S> Future for ClientCertInjectAcceptFuture<S>
where
    S: Clone,
{
    type Output = io::Result<(TlsStream<TcpStream>, CertInjectService<S>)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        match this.inner.as_mut().poll(cx) {
            Poll::Ready(Ok(Ok(stream))) => {
                let service = this
                    .service
                    .take()
                    .expect("future polled after ready");
                let cert_der = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|certs| certs.first())
                    .map(|c| c.as_ref().to_vec());
                Poll::Ready(Ok((
                    stream,
                    CertInjectService {
                        inner: service,
                        cert_der,
                    },
                )))
            }
            Poll::Ready(Ok(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(Err(timeout)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, timeout)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Per-connection service that attaches the negotiated client cert to each HTTP request.
#[derive(Clone)]
pub struct CertInjectService<S> {
    inner: S,
    cert_der: Option<Vec<u8>>,
}

impl<S> Service<Request<Incoming>> for CertInjectService<S>
where
    S: Service<Request<Incoming>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = CertInjectRequestFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Incoming>) -> Self::Future {
        if let Some(der) = &self.cert_der {
            req.extensions_mut().insert(TlsClientCert(der.clone()));
        }
        CertInjectRequestFuture {
            inner: self.inner.call(req),
        }
    }
}

pin_project! {
    pub struct CertInjectRequestFuture<F> {
        #[pin]
        inner: F,
    }
}

impl<F, R, E> Future for CertInjectRequestFuture<F>
where
    F: Future<Output = Result<R, E>>,
{
    type Output = Result<R, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().inner.poll(cx)
    }
}
