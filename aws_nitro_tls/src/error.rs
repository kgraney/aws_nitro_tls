use openssl::error::ErrorStack;
use openssl::ssl::SslAlert;
use rcgen::RcgenError;
use thiserror::Error;
use tracing::info;

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

    #[error("Error in rcgen")]
    RcgenError(RcgenError),

    #[error("IoError")]
    IoError(),
}

impl From<Error> for SslAlert {
    fn from(e: Error) -> Self {
        info!("Converting error into generic SslAlert: {}", e);
        SslAlert::DECODE_ERROR
    }
}

impl From<RcgenError> for Error {
    fn from(e: RcgenError) -> Self {
        Error::RcgenError(e)
    }
}

impl From<Error> for std::io::Error {
    fn from(_e: Error) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, "oh no!")
    }
}
