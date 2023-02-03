mod aws_nitro_tls_util;
mod certificates;
mod error;
mod proxy;
mod proxy_service;
mod socket;
mod tls_service;
mod to_refactor;

use crate::aws_nitro_tls_util::acceptor_builder;
use crate::certificates::CertificatePair;
use crate::proxy::proxy_handler;
use crate::proxy_service::ProxyService;
use crate::socket::ipv4_listen;
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
use tokio::task::JoinHandle;
use tokio_vsock::VsockListener;
use tracing::{info, span, Level};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// CID to listen on for VSOCK ports. This should almost always be VMADDR_PORT_ANY (-1U).
    /// See vsock(7) for details.
    #[arg(long, default_value_t = libc::VMADDR_PORT_ANY)]
    listen_cid: u32,

    /// PUBLIC port for TCP connections.
    #[arg(long)]
    public_port_tcp: Option<u16>,

    /// PUBLIC port for VSOCK connections.
    #[arg(long)]
    public_port_vsock: Option<u16>,

    /// PRIVATE port for TCP connections.
    #[arg(long)]
    private_port_tcp: Option<u16>,

    /// PRIVATE port for VSOCK connections.
    #[arg(long)]
    private_port_vsock: Option<u16>,

    /// FORWARD PROXY port for TCP connections.
    #[arg(long)]
    proxy_port: Option<u16>,

    /// If set, don't use Nitro Security Module attestations.  Instead fake attestations will be
    /// used.
    #[arg(long)]
    no_nsm: bool,

    fullchain: PathBuf,
    private_key: PathBuf,
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

    let tls = acceptor_builder(args.no_nsm, false);
    let mutual_tls = acceptor_builder(args.no_nsm, true);

    let public_tls = TlsService::new(server_certs.clone(), tls, service_fn(public_test));
    let private_tls = TlsService::new(server_certs.clone(), mutual_tls, service_fn(private_test));

    let mut servers = Vec::<JoinHandle<()>>::new();
    if let Some(port) = args.public_port_tcp {
        servers.push(tokio::task::spawn(
            public_tls
                .clone()
                .tcp_listener(ipv4_listen(port).await.unwrap()),
        ));
    }

    if let Some(port) = args.public_port_vsock {
        servers.push(tokio::task::spawn(public_tls.clone().vsock_listener(
            VsockListener::bind(args.listen_cid.into(), port.into()).unwrap(),
        )));
    }

    if let Some(port) = &args.private_port_tcp {
        servers.push(tokio::task::spawn(
            private_tls
                .clone()
                .tcp_listener(ipv4_listen(*port).await.unwrap()),
        ));
    }

    let proxy = ProxyService::new(service_fn(proxy_handler));
    if let Some(port) = &args.proxy_port {
        servers.push(tokio::task::spawn(
            proxy
                .clone()
                .tcp_listener(ipv4_listen(*port).await.unwrap()),
        ));
    }

    drop(startup);

    futures::future::join_all(servers).await;
    Ok(())
}
