use actix_web::{web, App, HttpRequest, HttpServer, Responder};
use aws_nitro_tls::server::{AcceptorBuilder, LocalServerBuilder, NsmServerBuilder};
use clap::Parser;
use futures::future;
use std::path::PathBuf;

async fn info(_: HttpRequest) -> impl Responder {
    format!("public info")
}

async fn info_internal(_: HttpRequest) -> impl Responder {
    format!("internal info")
}

#[derive(Parser, Debug)]
struct CliArgs {
    #[arg(long)]
    no_nsm: bool,

    fullchain: PathBuf,
    private_key: PathBuf,
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let args = CliArgs::parse();

    let private_api_tls: Box<dyn AcceptorBuilder> = match args.no_nsm {
        true => Box::new(LocalServerBuilder::new(true)),
        false => Box::new(NsmServerBuilder::new(true)),
    };

    let public_api_tls: Box<dyn AcceptorBuilder> = match args.no_nsm {
        true => Box::new(LocalServerBuilder::new(false)),
        false => Box::new(NsmServerBuilder::new(false)),
    };

    // Web service that should be started on a port that has internal access only.  This port must
    // be accessible from other servers in the same cluster.
    let internal = HttpServer::new(move || App::new().route("/info", web::get().to(info_internal)))
        .bind(("localhost", 9080))?
        .bind_openssl(
            "localhost:9443",
            private_api_tls
                .ssl_acceptor_builder(&args.fullchain, &args.private_key)
                .unwrap(),
        )?
        .run();

    // Public web service that should be exposed on the internet.
    let public = HttpServer::new(move || App::new().route("/info", web::get().to(info)))
        .bind(("localhost", 8080))?
        .bind_openssl(
            "localhost:8443",
            public_api_tls
                .ssl_acceptor_builder(&args.fullchain, &args.private_key)
                .unwrap(),
        )?
        .run();

    future::try_join(public, internal).await?;
    Ok(())
}
