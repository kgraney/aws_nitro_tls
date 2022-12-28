use crate::error::Error;

pub trait AttestationProvider {
    fn attestation_doc(
        &self,
        nonce: Option<Vec<u8>>,
        user_data: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, Error>;

    fn verify_doc(&self, doc: &[u8]) -> Result<SessionValues, Error>;
}

pub struct SessionValues {
    pub client_nonce: Vec<u8>,
    pub cert_fingerprint: Vec<u8>,
}

pub trait AttestationVerifier {
    fn verify_doc(&self, doc: &[u8]) -> Result<SessionValues, Error>;
}
