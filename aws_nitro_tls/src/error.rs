use openssl::error::ErrorStack;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("No certificate available: {0}")]
    NoCertificateKnown(String),

    #[error("OpenSsl ErrorStack: {0}")]
    SslError(#[from] ErrorStack),
}
