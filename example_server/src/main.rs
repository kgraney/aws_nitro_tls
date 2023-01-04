use actix_web::{web, App, HttpRequest, HttpServer, Responder};
use aws_nitro_tls::certgen;
use aws_nitro_tls::server::{AcceptorBuilder, LocalServerBuilder, NsmServerBuilder};
use aws_nitro_tls::verifier::Verifier;
use clap::Parser;
use futures::future;
use openssl::pkey::PKey;
use openssl::x509::X509;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct CliArgs {
    #[arg(long)]
    no_nsm: bool,

    fullchain: PathBuf,
    private_key: PathBuf,
}

async fn test(_: HttpRequest) -> impl Responder {
    format!("some test endpoint")
}

async fn secret_test(_: HttpRequest) -> impl Responder {
    format!("secret test endpoint")
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let args = CliArgs::parse();
    let verifier = match args.no_nsm {
        true => Verifier::new_fake(),
        false => Verifier::new_aws(),
    };

    let tls_builder: Box<dyn AcceptorBuilder> = match args.no_nsm {
        true => Box::new(LocalServerBuilder::default()),
        false => Box::new(NsmServerBuilder::default()),
    };

    log::info!("Starting web server...");

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
            tls_builder
                .ssl_acceptor_builder(x509.as_ref(), pkey.as_ref(), None)
                .unwrap(),
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
            tls_builder
                .ssl_acceptor_builder(&cert.cert, &cert.pkey, Some(verifier))
                .unwrap(),
        )?
        .run();

    future::try_join(public, secret).await?;
    Ok(())
}
