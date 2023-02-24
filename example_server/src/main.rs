use actix_web::{web, web::Data, App, HttpRequest, HttpResponse, HttpServer, Responder};
use awc::Client;
use aws_nitro_tls::attestation::{AttestationProvider, AttestationVerifier};
use aws_nitro_tls::certgen;
use aws_nitro_tls::nsm::{NsmAttestationProvider, NsmAttestationVerifier};
use aws_nitro_tls::nsm_fake::{FakeAttestationProvider, FakeAttestationVerifier};
use aws_nitro_tls::server::{AcceptorBuilder, AttestedBuilder};
use clap::Parser;
use console_subscriber;
use futures::TryFutureExt;
use hyper::service::Service;
use hyper::{Body, Request};
use openssl::pkey::PKey;
use openssl::x509::X509;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use third_wheel::{mitm_layer, CertificateAuthority, MitmProxy, ThirdWheel};
use thiserror::Error;
use tracing::info;
use url::Url;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
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

async fn test(_: HttpRequest) -> impl Responder {
    format!("some test endpoint")
}

async fn secret_test(_: HttpRequest) -> impl Responder {
    format!("secret test endpoint")
}

async fn forward(
    req: HttpRequest,
    payload: web::Payload,
    client: web::Data<Client>,
) -> Result<HttpResponse, actix_web::Error> {
    // TODO: make the destination configurable.
    let mut new_url = Url::parse(&format!("http://localhost:8080")).unwrap();
    new_url.set_path(req.uri().path());
    new_url.set_query(req.uri().query());

    let forwarded_req = client
        .request_from(new_url.as_str(), req.head())
        .no_decompress();

    let res = forwarded_req
        .send_stream(payload)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let mut client_resp = HttpResponse::build(res.status());

    // Proxies aren't supposed to forward 'Connection' headers.
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection
    for (header_name, header_value) in res.headers().iter().filter(|(h, _)| *h != "connection") {
        client_resp.append_header((header_name.clone(), header_value.clone()));
    }
    Ok(client_resp.streaming(res))
}

#[derive(Error, Debug)]
pub enum MainError {
    #[error("IoError.")]
    IoError(#[from] std::io::Error),

    #[error("ThirdWheel.")]
    ThirdWheelError(#[from] third_wheel::Error),
}

fn builder<P, V>(mutual_tls: bool) -> Box<dyn AcceptorBuilder>
where
    P: AttestationProvider + Default + 'static,
    V: AttestationVerifier + Default + 'static,
{
    match mutual_tls {
        true => Box::new(AttestedBuilder::<P, V>::new(
            P::default(),
            Some(V::default()),
        )),
        false => Box::new(AttestedBuilder::<P, V>::new(P::default(), None)),
    }
}

fn get_builders(no_nsm: bool, mutual_tls: bool) -> Box<dyn AcceptorBuilder> {
    match no_nsm {
        true => builder::<FakeAttestationProvider, FakeAttestationVerifier>(mutual_tls),
        false => builder::<NsmAttestationProvider, NsmAttestationVerifier>(mutual_tls),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    console_subscriber::init();
    //tracing_subscriber::fmt::init();

    let args = CliArgs::parse();

    let tls_builder = get_builders(args.no_nsm, false);
    let mutual_tls_builder = get_builders(args.no_nsm, true);

    info!("Starting web server...");

    let mut x509_pem = Vec::<u8>::new();
    let mut x509_file = File::open(&args.fullchain)?;
    x509_file.read_to_end(&mut x509_pem)?;

    let mut pkey_pem = Vec::<u8>::new();
    let mut pkey_file = File::open(&args.private_key)?;
    pkey_file.read_to_end(&mut pkey_pem)?;

    let x509 = X509::stack_from_pem(&x509_pem)?;
    let pkey = PKey::private_key_from_pem(&pkey_pem)?;

    // PUBLIC port - for client-to-enclave communication.
    //
    // Use CA-signed certificates for this connection, which may be exposed to the public internet.
    let public = HttpServer::new(move || App::new().route("/test", web::get().to(test)))
        .bind(("localhost", 8080))?
        .bind_openssl(
            format!("localhost:{}", args.tls_port),
            tls_builder.ssl_acceptor_builder(x509.as_ref(), pkey.as_ref())?,
        )?
        .run();

    // SECRET port - for enclave-to-enclave communication.
    //
    // Use self-signed certs for this connection.  The assumption is that this port is only exposed
    // to an internal enclave-to-enclave network.
    let cert = certgen::new_cert()?;
    let cert_chain = vec![cert.cert];
    let secret = HttpServer::new(move || App::new().route("/test", web::get().to(secret_test)))
        .bind(("localhost", 9080))?
        .bind_openssl(
            format!("localhost:{}", args.mutual_tls_port),
            mutual_tls_builder.ssl_acceptor_builder(&cert_chain, &cert.pkey)?,
        )?
        .run();

    // REVERSE port - to act as a reverse proxy when other enclaves are talking to this one
    //
    // Forwards traffic from this port to some other process running inside the enclave without
    // that other process needing to understand attestation documents.
    let reverse = HttpServer::new(move || {
        App::new()
            .app_data(Data::new(Client::new()))
            .default_service(web::route().to(forward))
    })
    .bind_openssl(
        format!("localhost:{}", args.reverse_port),
        mutual_tls_builder.ssl_acceptor_builder(&cert_chain, &cert.pkey)?,
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
        .bind_with_graceful_shutdown(format!("127.0.0.1:{}", args.forward_port).parse()?, async {
            receiver.await.ok().unwrap()
        });
    tokio::spawn(mitm_proxy);

    futures::try_join!(
        public.map_err(MainError::from),
        secret.map_err(MainError::from),
        reverse.map_err(MainError::from),
    )?;
    info!("Shutting down mitm_proxy");
    third_wheel_killer.send(()).unwrap();
    Ok(())
}
