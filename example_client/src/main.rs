use aws_nitro_tls::attestation::AttestationVerifier;
use aws_nitro_tls::client::{AttestedBuilder, ConnectorBuilder};
use aws_nitro_tls::nsm::NsmAttestationVerifier;
use aws_nitro_tls::nsm_fake::FakeAttestationVerifier;
use clap::Parser;
use hyper::body::HttpBody as _;
use tokio::io::{stdout, AsyncWriteExt as _};
use tracing::{info, span, Level};

#[derive(Parser, Debug)]
struct CliArgs {
    #[arg(long)]
    no_nsm: bool,

    fetch_url: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();
    openssl_probe::init_ssl_cert_env_vars();

    let args = CliArgs::parse();
    let verifier: Box<dyn AttestationVerifier> = match args.no_nsm {
        true => Box::new(FakeAttestationVerifier::default()),
        false => Box::new(NsmAttestationVerifier::default()),
    };

    let builder = AttestedBuilder::new(verifier, None);
    let client = builder.http_client()?;

    let span = span!(Level::DEBUG, "request_url");
    let enter = span.enter();

    info!("Requesting page from: {}", args.fetch_url);
    let mut resp = client.get(args.fetch_url.parse()?).await?;
    info!("Response: {}", resp.status());
    while let Some(chunk) = resp.body_mut().data().await {
        stdout().write_all(&chunk?).await?;
    }

    drop(enter);

    Ok(())
}
