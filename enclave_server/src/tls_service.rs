use crate::certificates::CertificatePair;
use aws_nitro_tls::server::AcceptorBuilder;
use futures::TryFutureExt;
use hyper::body::{Body, Incoming};
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{Request, Response};
use openssl::ssl::Ssl;
use std::error::Error as StdError;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_openssl::SslStream;
use tokio_vsock::VsockListener;
use tracing::{debug, info};

pub struct TlsService<S> {
    certs: Arc<CertificatePair>,
    acceptor_builder: Box<dyn AcceptorBuilder + Send + Sync>,
    service: S,
}

impl<S, Resp> TlsService<S>
where
    Resp: Body + Send + Sync + 'static,
    <Resp as Body>::Error: StdError + Send + Sync,
    <Resp as Body>::Data: Send + Sync,

    S: Service<Request<Incoming>, Response = Response<Resp>> + Send + Sync + Copy + 'static,
    <S as Service<Request<Incoming>>>::Error: Send + Sync + StdError,
    <S as Service<Request<Incoming>>>::Future: Send + Sync,
{
    pub fn new(
        certs: CertificatePair,
        acceptor_builder: Box<dyn AcceptorBuilder + Send + Sync>,
        service: S,
    ) -> Arc<Self> {
        Arc::new(TlsService {
            certs: Arc::new(certs),
            acceptor_builder: acceptor_builder,
            service: service,
        })
    }

    pub async fn tcp_listener(self: Arc<Self>, listener: TcpListener) {
        if let Ok(addr) = listener.local_addr() {
            info!("Starting transport on TCP listener {addr:?}");
        }
        loop {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            tokio::task::spawn(self.clone().process(tcp_stream));
        }
    }

    pub async fn vsock_listener(self: Arc<Self>, mut listener: VsockListener) {
        if let Ok(addr) = listener.local_addr() {
            info!("Starting transport on VSOCK listener {addr:?}");
        }
        loop {
            let (vsock_stream, _) = listener.accept().await.unwrap();
            tokio::task::spawn(self.clone().process(vsock_stream));
        }
    }

    pub async fn process<Stream>(self: Arc<Self>, stream: Stream)
    where
        Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let acceptor = self
            .acceptor_builder
            .ssl_acceptor_builder(self.certs.x509.as_ref(), self.certs.pkey.as_ref())
            .unwrap();
        let ssl = Ssl::new(acceptor.build().context()).unwrap();
        let mut ssl_stream = SslStream::new(ssl, stream).unwrap();

        Pin::new(&mut ssl_stream).accept().await.unwrap();
        let conn = http1::Builder::new().serve_connection(ssl_stream, self.service);
        if let Err(http_err) = conn.await {
            debug!("Error while serving HTTP connection: {}", http_err);
        }
    }
}
