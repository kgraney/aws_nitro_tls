use actix_web::{web, App, HttpRequest, HttpServer, Responder};
use aws_nitro_tls::server::{AcceptorBuilder, LocalServerBuilder, NsmServerBuilder};
use aws_nitro_tls::verifier::Verifier;
use futures::future;
use clap::Parser;
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

    // PUBLIC port - for client-to-enclave communication.
    let public = HttpServer::new(move || App::new().route("/test", web::get().to(test)))
        .bind(("localhost", 8080))?
        .bind_openssl(
            "localhost:8443",
            tls_builder
                .ssl_acceptor_builder(&args.fullchain, &args.private_key, None)
                .unwrap(),
        )?
        .run();

    // SECRET port - for enclave-to-enclave communication.
    let secret = HttpServer::new(move || App::new().route("/test", web::get().to(secret_test)))
        .bind(("localhost", 9080))?
        .bind_openssl(
            "localhost:9443",
            tls_builder
                .ssl_acceptor_builder(&args.fullchain, &args.private_key, Some(verifier))
                .unwrap(),
        )?
        .run();

    future::try_join(public, secret).await?;
    Ok(())
}
