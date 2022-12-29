use aws_nitro_tls::client::{ConnectorBuilder, LocalBuilder, NsmBuilder};
use aws_nitro_tls::verifier::Verifier;
use clap::Parser;
use hyper::body::HttpBody as _;
use tokio::io::{stdout, AsyncWriteExt as _};

#[derive(Parser, Debug)]
struct CliArgs {
    #[arg(long)]
    no_nsm: bool,

    fetch_url: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();
    openssl_probe::init_ssl_cert_env_vars();

    let args = CliArgs::parse();
    let verifier = match args.no_nsm {
        true => Verifier::new_fake(),
        false => Verifier::new_aws(),
    };

    let builder: Box<dyn ConnectorBuilder> = match args.no_nsm {
        true => Box::new(LocalBuilder::new(verifier)),
        false => Box::new(NsmBuilder::new(verifier)),
    };

    let client = builder.http_client()?;

    log::info!("Requesting page from: {}", args.fetch_url);
    let mut resp = client.get(args.fetch_url.parse()?).await?;
    log::info!("Response: {}", resp.status());
    while let Some(chunk) = resp.body_mut().data().await {
        stdout().write_all(&chunk?).await?;
    }

    Ok(())
}
