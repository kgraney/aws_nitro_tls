mod aws_nitro_tls_util;
mod certificates;
mod socket;
mod tls_service;

use crate::aws_nitro_tls_util::acceptor_builder;
use crate::certificates::CertificatePair;
use crate::socket::{ipv4_listen, vsock_listen};
use crate::tls_service::TlsService;
use bytes::Bytes;
use clap::Parser;
use console_subscriber;
use futures::future::TryFutureExt;
use http_body_util::Full;
use hyper::{body::Incoming, service::service_fn, Request, Response};
use std::convert::Infallible;
use std::path::PathBuf;
use thiserror::Error;
use tracing::{info, span, Level};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    //enclave_cid: u16,
    /// Port to listen on for the demo HTTPS handlers with client auth.
    #[arg(long, default_value_t = 8443)]
    tls_port: u16,

    /// Port to listen on for the demo HTTPS handlers with required mutual auth.
    #[arg(long, default_value_t = 9443)]
    mutual_tls_port: u16,

    /// Port to listen on for the FORWARD proxy.  This proxy should be exposed within the enclave
    /// and verifies the attestation of destination hosts.
    #[arg(long, default_value_t = 6443)]
    forward_port: u16,

    /// Port to listen on for the REVERSE proxy.  This proxy should be exposed outside the enclave
    /// and verifies the attestation of hosts making requests to it.  Requests are forwarded to
    /// `reverse_destination`.
    #[arg(long, default_value_t = 7443)]
    reverse_port: u16,

    /// Port to forward requests to `reverse_port` to.
    #[arg(long, default_value_t = 8000)]
    reverse_destination: u16,

    /// If set, don't use Nitro Security Module attestations.  Instead fake attestations will be
    /// used.
    #[arg(long)]
    no_nsm: bool,

    fullchain: PathBuf,
    private_key: PathBuf,

    ca_fullchain: PathBuf,
    ca_private_key: PathBuf,
}

async fn shutdown_signal() {
    // Wait for the CTRL+C signal
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
}

async fn public_test(_: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from("some public data"))))
}

async fn private_test(_: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from("some private data"))))
}

#[derive(Error, Debug)]
pub enum MainError {
    #[error("IoError.")]
    IoError(#[from] std::io::Error),

    #[error("HyperError.")]
    HyperError(#[from] hyper::Error),

    #[error("JoinError.")]
    JoinError(#[from] tokio::task::JoinError),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    console_subscriber::init();
    let args = CliArgs::parse();

    let span = span!(Level::INFO, "startup");
    let startup = span.enter();

    info!("Starting Enclave Transport Server");
    let server_certs = CertificatePair::new_from_pem(&args.fullchain, &args.private_key)?;

    let tls_builder = acceptor_builder(args.no_nsm, false);
    let mutual_tls_builder = acceptor_builder(args.no_nsm, true);

    let public_tls = TlsService::new(server_certs.clone(), tls_builder, service_fn(public_test));
    let public_tcp = tokio::task::spawn(
        public_tls
            .clone()
            .tcp_listener(ipv4_listen(8081).await.unwrap()),
    );

    let private_tls = TlsService::new(
        server_certs.clone(),
        mutual_tls_builder,
        service_fn(private_test),
    );
    let private_tcp = tokio::task::spawn(
        private_tls
            .clone()
            .tcp_listener(ipv4_listen(8082).await.unwrap()),
    );

    //let public_vsock = tokio::task::spawn(tls.clone().vsock_listener(vlistener));

    //let mut vlistener = VsockListener::bind(10, 5000).unwrap();
    //let server_certs2 = CertificatePair::new_from_pem(&args.fullchain, &args.private_key)?;
    //let tls_v = TlsService::new(server_certs2, tls_builder.clone(), service_fn(public_test));
    //let public_vsock = tokio::task::spawn(tls_v.vsock_listener(vlistener));

    //let public = tokio::task::spawn(public_port(listener, tls_builder.clone(), certs.clone()));
    drop(startup);

    futures::try_join!(
        public_tcp.map_err(MainError::from),
        //public_vsock.map_err(MainError::from),
        private_tcp.map_err(MainError::from),
    )?;
    Ok(())
}
