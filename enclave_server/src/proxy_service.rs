use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Body, body::Incoming, Request, Response};
use std::error::Error as StdError;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tracing::{debug, info};

pub struct ProxyService<S> {
    service: S,
}

impl<S, Resp> ProxyService<S>
where
    Resp: Body + Send + Sync + 'static,
    <Resp as Body>::Error: StdError + Send + Sync,
    <Resp as Body>::Data: Send + Sync,

    S: Service<Request<Incoming>, Response = Response<Resp>> + Send + Sync + Copy + 'static,
    <S as Service<Request<Incoming>>>::Error: Send + Sync + StdError,
    <S as Service<Request<Incoming>>>::Future: Send + Sync,
{
    pub fn new(service: S) -> Arc<Self> {
        Arc::new(Self { service: service })
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

    pub async fn process<Stream>(self: Arc<Self>, stream: Stream)
    where
        Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let conn = http1::Builder::new()
            .serve_connection(stream, self.service)
            .with_upgrades();
        if let Err(http_err) = conn.await {
            debug!("Error while serving HTTP connection: {}", http_err);
        }
    }
}
