use crate::error::Error;

pub trait AttestationProvider: Sync + Send {
    // Returns an attestation document signed for the given parameters.
    fn attestation_doc(
        &self,
        nonce: Option<Vec<u8>>,
        user_data: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, Error>;
}

pub trait AttestationVerifier: Sync + Send {
    /// Returns an Error if the document isn't correctly signed by the root-of-trust.  If it is
    /// correctly signed, will return SessionValues that should be compared against the session
    /// state.
    fn verify_doc(&self, doc: &[u8]) -> Result<SessionValues, Error>;

    /// Should return true if the CA of the TLS certificate is verified.
    // TODO: consider moving this config elsewhere since verifying an attestation is distinct from
    // verifying the certificate.
    fn trusted_cert_required(&self) -> bool;
}

#[derive(Debug)]
pub struct SessionValues {
    pub client_nonce: Vec<u8>,
    pub cert_fingerprint: Vec<u8>,
}
