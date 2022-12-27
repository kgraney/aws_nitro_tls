use openssl::hash::{DigestBytes, MessageDigest};

pub trait SslRefHelper {
    fn client_nonce(&self) -> Vec<u8>;
    fn cert_fingerprint(&self) -> DigestBytes;
}

impl SslRefHelper for openssl::ssl::SslRef {
    fn client_nonce(&self) -> Vec<u8> {
        let mut client_random = Vec::<u8>::new();
        client_random.resize(32, 0x0);
        self.client_random(&mut client_random[0..32]);
        client_random
    }

    fn cert_fingerprint(&self) -> DigestBytes {
        let digest = self
            .certificate()
            .and_then(|x| Some(x.digest(MessageDigest::sha256())))
            .unwrap()
            .unwrap();
        digest
    }
}
