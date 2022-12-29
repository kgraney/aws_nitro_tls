use crate::error::Error;
use openssl::hash::{DigestBytes, MessageDigest};

pub trait SslRefHelper {
    fn client_nonce(&self) -> Vec<u8>;
    fn server_nonce(&self) -> Vec<u8>;
    fn cert_fingerprint(&self) -> Result<DigestBytes, Error>;
}

impl SslRefHelper for openssl::ssl::SslRef {
    fn client_nonce(&self) -> Vec<u8> {
        let mut client_random = Vec::<u8>::new();
        client_random.resize(32, 0x0);
        self.client_random(&mut client_random[0..32]);
        client_random
    }

    fn server_nonce(&self) -> Vec<u8> {
        let mut server_random = Vec::<u8>::new();
        server_random.resize(32, 0x0);
        self.server_random(&mut server_random[0..32]);
        server_random
    }

    fn cert_fingerprint(&self) -> Result<DigestBytes, Error> {
        Ok(self
            .certificate()
            .ok_or(Error::NoCertificateKnown("can't compute digest".to_owned()))?
            .digest(MessageDigest::sha256())?)
    }
}
