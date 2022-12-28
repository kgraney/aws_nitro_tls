use actix_web::{web, App, HttpRequest, HttpServer, Responder};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct CliArgs {
    fullchain: PathBuf,
    private_key: PathBuf,
}

async fn test(_: HttpRequest) -> impl Responder {
    format!("some test endpoint")
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let args = CliArgs::parse();

    let tls_builder = aws_nitro_tls::ServerBuilder::default();

    log::info!("Starting web server...");
    HttpServer::new(move || App::new().route("/test", web::get().to(test)))
        .bind(("localhost", 8080))?
        .bind_openssl(
            "localhost:8443",
            tls_builder
                .ssl_acceptor_builder(&args.fullchain, &args.private_key)
                .unwrap(),
        )?
        .run()
        .await
}
