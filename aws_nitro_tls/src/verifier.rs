use crate::attestation::{AttestationProvider, AttestationVerifier, SessionValues};
use crate::error::Error;
use crate::nsm::NsmAttestationProvider;
use crate::nsm_fake::FakeAttestationProvider;
use std::sync::Arc;

pub struct Verifier {
    provider: Arc<dyn AttestationProvider + Send + Sync>,

    // True if the server's certificate should be validated as normal (hostname, CA, etc.)
    validate_cert: bool,
}

impl Verifier {
    pub fn new_fake() -> Verifier {
        Verifier {
            provider: Arc::new(FakeAttestationProvider::default()),
            validate_cert: false,
        }
    }

    pub fn new_aws() -> Verifier {
        Verifier {
            provider: Arc::new(NsmAttestationProvider::default()),
            validate_cert: true,
        }
    }

    pub fn should_validate_cert(&self) -> bool {
        self.validate_cert
    }
}

impl AttestationVerifier for Verifier {
    fn verify_doc(&self, doc: &[u8]) -> Result<SessionValues, Error> {
        self.provider.verify_doc(doc)
    }
}
