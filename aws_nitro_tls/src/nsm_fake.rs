use crate::attestation::AttestationProvider;
use crate::error::Error;

pub struct FakeAttestationProvider {}

impl Default for FakeAttestationProvider {
    fn default() -> Self {
        FakeAttestationProvider {}
    }
}

impl AttestationProvider for FakeAttestationProvider {
    fn attestation_doc(
        &self,
        _nonce: Option<Vec<u8>>,
        _user_data: Option<Vec<u8>>,
        _public_key: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, Error> {
        // TODO: Do something better here
        let doc = Vec::<u8>::new();
        Ok(doc)
    }
}
