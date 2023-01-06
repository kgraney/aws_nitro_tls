use crate::attestation::{AttestationProvider, AttestationVerifier, SessionValues};
use crate::error::Error;
use serde_derive::{Deserialize, Serialize};
use tracing::warn;

#[derive(Default)]
pub struct FakeAttestationProvider {}

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
        warn!("generating FAKE attestation doc");
        let bytes = serde_cbor::to_vec(&doc).or(Err(Error::CborSerializeError()))?;
        Ok(bytes)
    }
}

#[derive(Default)]
pub struct FakeAttestationVerifier {}

impl AttestationVerifier for FakeAttestationVerifier {
    fn verify_doc(&self, bytes: &[u8]) -> Result<SessionValues, Error> {
        let doc: FakeAttestationDoc =
            serde_cbor::from_reader(bytes).or(Err(Error::CborDeserializeError()))?;
        warn!("verifying FAKE attestation doc");
        Ok(SessionValues {
            client_nonce: doc.nonce,
            cert_fingerprint: doc.public_key,
        })
    }

    fn trusted_cert_required(&self) -> bool {
        return false;
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct FakeAttestationDoc {
    nonce: Vec<u8>,
    public_key: Vec<u8>,
}
