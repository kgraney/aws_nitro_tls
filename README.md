# aws\_nitro\_tls

A library for wrapping TLS sessions that verify AWS Nitro Enclave attestation
documents.  Provides an ` openssl::ssl::SslAcceptorBuilder` for the server
and a `hyper::Client` (or `hyper_openssl::HttpsConnector`) for the client.

This library is a work-in-progress.

## Design notes

* Only TLS 1.3 is supported.
* An (unregistered) TLS extension is sent in `CLIENT_HELLO`, where the
  client indicates that is _expects_ an attestation document to be provided
  by the server.
* The server _must_ respond with the attestation document contents in COSE
  format (as provided by the Nitro Security Module).  This document should be
  included in the same extension in the `ENCRYPTED_EXTENSIONS` message to the
  client.  If the server doesn't respond, which is allowed by the TLS spec, the
  client's certificate verification will fail.
* The attestation document is signed with the following fields:
    * `nonce`: the client random for this TLS session.
    * `public_key`: the SHA-256 fingerprint of the server's public certificate.
* The certificate verification step on the client verifies that the certificate
  used for the session matches the fingerprint received in the attestation.  The
  attestation nonce is verified when parsing `ENCRYPTED_EXTENSIONS`.

## Examples

### Client usage

```rust
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

    let verifier = Verifier::new_aws();
    let client_builder = AttestedBuilder::new(verifier);
    let client = client_builder.http_client()?;

    let mut resp = client.get(args.fetch_url.parse()?).await?;
    log::info!("Response: {}", resp.status());
    while let Some(chunk) = resp.body_mut().data().await {
        stdout().write_all(&chunk?).await?;
    }

    Ok(())
}

```

### Server usage

```rust
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
```

