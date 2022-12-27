use aws_nitro_tls::client::AttestedBuilder;
use aws_nitro_tls::verifier::Verifier;
use clap::Parser;
use hyper::body::HttpBody as _;
use tokio::io::{stdout, AsyncWriteExt as _};

#[derive(Parser, Debug)]
struct CliArgs {
    fetch_url: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();
    openssl_probe::init_ssl_cert_env_vars();

    let args = CliArgs::parse();
    log::info!("Requesting page from: {}", args.fetch_url);

    let root_cert = include_bytes!("./aws_root.der");

    let verifier = Verifier::new(root_cert.to_vec());
    let client_builder = AttestedBuilder::new(verifier);
    let client = client_builder.http_client()?;

    let mut resp = client.get(args.fetch_url.parse()?).await?;
    log::info!("Response: {}", resp.status());
    while let Some(chunk) = resp.body_mut().data().await {
        stdout().write_all(&chunk?).await?;
    }

    Ok(())
}
