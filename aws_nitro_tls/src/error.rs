use openssl::error::ErrorStack;
use openssl::ssl::SslAlert;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Nitro Security Module error")]
    NsmError(),

    #[error("No certificate available: {0}")]
    NoCertificateKnown(String),

    #[error("OpenSsl ErrorStack: {0}")]
    SslError(#[from] ErrorStack),

    #[error("Failed to parse attestation document")]
    FailedToParseAttestation(),

    #[error("Client nonce error: {0}")]
    ClientNonceError(String),

    #[error("Certificate fingerprint error: {0}")]
    CertificateFingerprintError(String),
}

impl From<Error> for SslAlert {
    fn from(_: Error) -> Self {
        SslAlert::DECODE_ERROR
    }
}
