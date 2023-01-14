use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use tracing::info;

/// Stores the TLS certificate pair to use for a connection.
#[derive(Clone)]
pub struct CertificatePair {
    /// X509 Certificate
    pub x509: X509,

    /// Private Key
    pub pkey: PKey<Private>,
}

impl CertificatePair {
    pub fn new_from_pem(fullchain: &PathBuf, private_key: &PathBuf) -> std::io::Result<Self> {
        info!("Loading certificates from files -> chain={fullchain:?} pkey={private_key:?}");
        let mut x509_pem = Vec::<u8>::new();
        let mut x509_file = File::open(&fullchain)?;
        x509_file.read_to_end(&mut x509_pem)?;

        let mut pkey_pem = Vec::<u8>::new();
        let mut pkey_file = File::open(&private_key)?;
        pkey_file.read_to_end(&mut pkey_pem)?;

        Ok(CertificatePair {
            x509: X509::from_pem(&x509_pem)?,
            pkey: PKey::private_key_from_pem(&pkey_pem)?,
        })
    }
}
