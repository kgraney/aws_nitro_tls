use crate::attestation::{AttestationProvider, AttestationVerifier, SessionValues};
use crate::error::Error;
use serde_derive::{Deserialize, Serialize};

pub struct FakeAttestationProvider {}

impl Default for FakeAttestationProvider {
    fn default() -> Self {
        FakeAttestationProvider {}
    }
}

impl AttestationProvider for FakeAttestationProvider {
    fn attestation_doc(
        &self,
        nonce: Option<Vec<u8>>,
        _user_data: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, Error> {
        let doc = FakeAttestationDoc {
            nonce: nonce.unwrap(),
            public_key: public_key.unwrap(),
        };
        log::debug!("Generating FAKE attestation doc: {doc:?}");
        let bytes = serde_cbor::to_vec(&doc).or(Err(Error::CborSerializeError()))?;
        Ok(bytes)
    }
}

impl AttestationVerifier for FakeAttestationProvider {
    fn verify_doc(&self, bytes: &[u8]) -> Result<SessionValues, Error> {
        let doc: FakeAttestationDoc =
            serde_cbor::from_reader(bytes).or(Err(Error::CborDeserializeError()))?;
        log::debug!("Verifying FAKE attestation doc: {doc:?}");
        Ok(SessionValues {
            client_nonce: doc.nonce,
            cert_fingerprint: doc.public_key,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct FakeAttestationDoc {
    nonce: Vec<u8>,
    public_key: Vec<u8>,
}
