use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("ProxyError: {0}")]
    ProxyError(String),

    #[error("IoError")]
    IoError(),

    #[error("AwsNitroTlsError: {0}")]
    AwsNitroTlsError(aws_nitro_tls::error::Error),

    #[error("OpenSslError: {0}")]
    OpenSslError(openssl::error::ErrorStack),

    #[error("HyperError {0}")]
    HyperError(hyper::Error),

    #[error("RequestError: {0}")]
    RequestError(String),
}

impl From<aws_nitro_tls::error::Error> for Error {
    fn from(e: aws_nitro_tls::error::Error) -> Self {
        Error::AwsNitroTlsError(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(_e: std::io::Error) -> Self {
        Error::IoError()
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Error::OpenSslError(e)
    }
}

impl From<hyper::Error> for Error {
    fn from(e: hyper::Error) -> Self {
        Error::HyperError(e)
    }
}
