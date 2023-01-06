use actix_web::{web, App, HttpRequest, HttpServer, Responder};
use aws_nitro_tls::attestation::{AttestationProvider, AttestationVerifier};
use aws_nitro_tls::certgen;
use aws_nitro_tls::nsm::{NsmAttestationProvider, NsmAttestationVerifier};
use aws_nitro_tls::nsm_fake::{FakeAttestationProvider, FakeAttestationVerifier};
use aws_nitro_tls::server::{AcceptorBuilder, AttestedBuilder};
use clap::Parser;
use futures::TryFutureExt;
use hyper::service::Service;
use hyper::Body;
use hyper::Request;
use openssl::pkey::PKey;
use openssl::x509::X509;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use third_wheel::{mitm_layer, CertificateAuthority, MitmProxy, ThirdWheel};
use thiserror::Error;
use tracing::info;

#[derive(Parser, Debug)]
struct CliArgs {
    #[arg(long)]
    no_nsm: bool,

    fullchain: PathBuf,
    private_key: PathBuf,

    ca_fullchain: PathBuf,
    ca_private_key: PathBuf,
}

async fn test(_: HttpRequest) -> impl Responder {
    format!("some test endpoint")
}

async fn secret_test(_: HttpRequest) -> impl Responder {
    format!("secret test endpoint")
}

#[derive(Error, Debug)]
pub enum MainError {
    #[error("IoError.")]
    IoError(#[from] std::io::Error),

    #[error("ThirdWheel.")]
    ThirdWheelError(#[from] third_wheel::Error),
}

fn new_provider(no_nsm: bool) -> Box<dyn AttestationProvider> {
    match no_nsm {
        true => Box::new(FakeAttestationProvider::default()),
        false => Box::new(NsmAttestationProvider::default()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = CliArgs::parse();

    let tls_builder = AttestedBuilder::new(new_provider(args.no_nsm), None);

    let verifier: Box<dyn AttestationVerifier> = match args.no_nsm {
        true => Box::new(FakeAttestationVerifier::default()),
        false => Box::new(NsmAttestationVerifier::default()),
    };
    let mutual_tls_builder = AttestedBuilder::new(new_provider(args.no_nsm), Some(verifier));

    info!("Starting web server...");

    let mut x509_pem = Vec::<u8>::new();
    let mut x509_file = File::open(&args.fullchain)?;
    x509_file.read_to_end(&mut x509_pem)?;

    let mut pkey_pem = Vec::<u8>::new();
    let mut pkey_file = File::open(&args.private_key)?;
    pkey_file.read_to_end(&mut pkey_pem)?;

    let x509 = X509::from_pem(&x509_pem)?;
    let pkey = PKey::private_key_from_pem(&pkey_pem)?;

    // PUBLIC port - for client-to-enclave communication.
    //
    // Use CA-signed certificates for this connection, which may be exposed to the public internet.
    let public = HttpServer::new(move || App::new().route("/test", web::get().to(test)))
        .bind(("localhost", 8080))?
        .bind_openssl(
            "localhost:8443",
            tls_builder.ssl_acceptor_builder(x509.as_ref(), pkey.as_ref())?,
        )?
        .run();

    // SECRET port - for enclave-to-enclave communication.
    //
    // Use self-signed certs for this connection.  The assumption is that this port is only exposed
    // to an internal enclave-to-enclave network.
    let cert = certgen::new_cert()?;
    let secret = HttpServer::new(move || App::new().route("/test", web::get().to(secret_test)))
        .bind(("localhost", 9080))?
        .bind_openssl(
            "localhost:9443",
            mutual_tls_builder.ssl_acceptor_builder(&cert.cert, &cert.pkey)?,
        )?
        .run();

    // FORWARD port - to act as a forward proxy for talking to other enclaves
    //
    // Uses self-signed CA certs to act as an HTTPS CONNECT proxy.  This port should only be
    // exposed internally to the enclave, allowing other processes to send requests to other
    // enclaves, verifying that enclave's attestation document in the process.
    info!("Starting FORWARD proxy...");
    let ca = CertificateAuthority::load_from_pem_files_with_passphrase_on_key(
        &args.ca_fullchain,
        &args.ca_private_key,
        "third-wheel",
    )?;
    let (third_wheel_killer, receiver) = tokio::sync::oneshot::channel();
    let trivial_mitm =
        mitm_layer(|req: Request<Body>, mut third_wheel: ThirdWheel| third_wheel.call(req));
    let mitm_proxy = MitmProxy::builder(trivial_mitm, ca).build();
    let (_, mitm_proxy) = mitm_proxy
        .bind_with_graceful_shutdown("127.0.0.1:7443".parse()?, async {
            receiver.await.ok().unwrap()
        });
    tokio::spawn(mitm_proxy);

    futures::try_join!(
        public.map_err(MainError::from),
        secret.map_err(MainError::from),
    )?;
    info!("Shutting down mitm_proxy");
    third_wheel_killer.send(()).unwrap();
    Ok(())
}
