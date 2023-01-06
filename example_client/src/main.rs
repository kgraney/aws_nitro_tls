use aws_nitro_tls::attestation::{AttestationProvider, AttestationVerifier};
use aws_nitro_tls::client::{AttestedBuilder, ConnectorBuilder};
use aws_nitro_tls::nsm::NsmAttestationVerifier;
use aws_nitro_tls::nsm_fake::FakeAttestationProvider;
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

/// Construct a `ConnectorBuilder` that works with mutual TLS.
fn build_mutual_tls_connector<P, V>() -> Box<dyn ConnectorBuilder>
where
    P: AttestationProvider + Default + 'static,
    V: AttestationVerifier + Default + 'static,
{
    Box::new(AttestedBuilder::<P, V>::new(V::default(), Some(P::default())))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();
    openssl_probe::init_ssl_cert_env_vars();

    let args = CliArgs::parse();

    let builder: Box<dyn ConnectorBuilder> = match args.no_nsm {
        true => build_mutual_tls_connector::<FakeAttestationProvider, FakeAttestationVerifier>(),
        // TODO: Provide a better stand-in for FakeAttestationProvider for clients that don't want
        // mutual TLS.
        false => build_mutual_tls_connector::<FakeAttestationProvider, NsmAttestationVerifier>(),
    };
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
