use crate::aws_nitro_tls_util::{acceptor_builder, connector_builder};
use crate::error::Error;
use crate::to_refactor::{RequestSendingSynchronizer, ThirdWheel};
use bytes::Bytes;
use http::status::StatusCode;
use http_body_util::Full;
use hyper::Uri;
use hyper::{body::Incoming, Method, Request, Response};
use openssl::pkey::PKey;
use openssl::ssl::Ssl;
use openssl::x509::X509;
use std::convert::Infallible;
use std::marker::Unpin;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;
use tracing::{debug, error};

pub async fn proxy_handler(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    debug!("FORWARD PROXY request: {req:?}");
    if req.method() != Method::CONNECT {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Full::new(Bytes::from("Only CONNECT is supported.")))
            .unwrap());
    }

    let uri = req.uri().clone();
    tokio::spawn(async move {
        let upgraded = hyper::upgrade::on(req).await.unwrap();
        let result = mitm_connection(upgraded, uri).await;
        if let Err(e) = result {
            error!("Error proxying connection: {e:?}");
        }
        ()
    });
    Ok(Response::new(Full::new(Bytes::from("some private data"))))
}

async fn mitm_connection<S>(stream: S, uri: Uri) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let host = uri
        .host()
        .ok_or(Error::ProxyError("No host specified".to_string()))?;
    let port = uri
        .port()
        .ok_or(Error::ProxyError("No port specified".to_string()))?;
    debug!("MITM connection for {host:?} {port:?}");

    let (target_stream, target_cert) = connect_to_target(host, port.as_str()).await?;

    // TODO: generate cert dynamically
    let chain = include_bytes!("../../example_server/fullchain.pem");
    let private_key = include_bytes!("../../example_server/privkey.pem");
    let x509 = X509::from_pem(chain).unwrap();
    let pkey = PKey::private_key_from_pem(private_key).unwrap();

    let server_builder = acceptor_builder(/*nsm=*/ true, false);
    let acceptor = server_builder.ssl_acceptor_builder(x509.as_ref(), pkey.as_ref())?;
    let ssl = Ssl::new(acceptor.build().context()).unwrap();
    let mut source_stream = SslStream::new(ssl, stream).unwrap();

    Pin::new(&mut source_stream).accept().await.unwrap();

    let (request_sender, connection) = hyper::client::conn::http1::Builder::new()
        .handshake::<SslStream<TcpStream>, Incoming>(target_stream)
        .await
        .unwrap();
    tokio::spawn(connection);

    // TODO: cleanup proxying to remove ThirdWheel objects
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        RequestSendingSynchronizer::new(request_sender, receiver)
            .run()
            .await
    });
    let third_wheel = ThirdWheel::new(sender);

    hyper::server::conn::http1::Builder::new()
        .serve_connection(source_stream, third_wheel)
        .await?;
    Ok(())
}

async fn connect_to_target(host: &str, port: &str) -> Result<(SslStream<TcpStream>, X509), Error> {
    let target_tcp_stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    // TODO: pass NSM arg
    let ssl = connector_builder(/*nsm=*/ true, true)
        .ssl_connector_builder()?
        .build()
        .configure()?
        .into_ssl(host)?;
    let mut target_stream = SslStream::new(ssl, target_tcp_stream)?;
    Pin::new(&mut target_stream)
        .connect()
        .await
        .or(Err(Error::ProxyError("Unable to connect".to_string())))?;

    let target_cert = match target_stream.ssl().peer_certificate() {
        Some(cert) => cert,
        None => {
            debug!("Target TLS peer didn't provide a certificate: {host:?}:{port:?}");
            return Err(Error::ProxyError(
                "Server did not provide a certificate for TLS connection".to_string(),
            ));
        }
    };
    let x509 = openssl::x509::X509::from_der(&target_cert.to_der()?)?;
    Ok((target_stream, x509))
}
