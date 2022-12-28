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

    #[error("Error serializing CBOR message")]
    CborSerializeError(),

    #[error("Error deserializing CBOR message")]
    CborDeserializeError(),
}

impl From<Error> for SslAlert {
    fn from(e: Error) -> Self {
        log::info!("Converting error into generic SslAlert: {}", e);
        SslAlert::DECODE_ERROR
    }
}
