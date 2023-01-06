mod aws_nsm {
    pub use aws_nitro_enclaves_nsm_api::*;
}
use crate::attestation::{AttestationProvider, AttestationVerifier, SessionValues};
use crate::error::Error;
use aws_nitro_enclaves_attestation::NitroAdDoc;
use serde_bytes::ByteBuf;
use std::marker::PhantomPinned;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// Provider of attestation documents from an AWS Nitro Security Module.
///
/// This provider can only be used within an AWS Nitro Enclave, where `/dev/nsm` is available.
pub struct NsmAttestationProvider {
    /// File descriptor to the NSM device.
    nsm_fd: i32,

    _not_unpin: PhantomPinned,
}

impl Default for NsmAttestationProvider {
    fn default() -> Self {
        Self {
            nsm_fd: aws_nsm::driver::nsm_init(),
            _not_unpin: PhantomPinned::default(),
        }
    }
}

impl AttestationProvider for NsmAttestationProvider {
    fn attestation_doc(
        &self,
        nonce: Option<Vec<u8>>,
        user_data: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, Error> {
        let nsm_req = aws_nsm::api::Request::Attestation {
            nonce: nonce.and_then(|x| Some(ByteBuf::from(x))),
            user_data: user_data.and_then(|x| Some(ByteBuf::from(x))),
            public_key: public_key.and_then(|x| Some(ByteBuf::from(x))),
        };
        if let aws_nsm::api::Response::Attestation { document } =
            aws_nsm::driver::nsm_process_request(self.nsm_fd, nsm_req)
        {
            return Ok(document);
        }
        Err(Error::NsmError())
    }
}

/// Verifier for attestation documents from AWS Nitro Security Modules.
///
/// By default this verifies, among other things, that the attestation document is signed by the
/// AWS root of trust as described
/// [here](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html).
pub struct NsmAttestationVerifier {
    /// The root certificate that NSM signs attestation documents with.
    root_cert: Arc<Vec<u8>>,

    trusted_cert_required: bool,

    _not_unpin: PhantomPinned,
}

impl Default for NsmAttestationVerifier {
    fn default() -> Self {
        let root_cert = include_bytes!("../certs/aws_root.der");
        Self {
            // TODO: can we avoid copying static data into an Arc?
            root_cert: Arc::new(root_cert.to_vec()),
            trusted_cert_required: true,
            _not_unpin: PhantomPinned::default(),
        }
    }
}

impl NsmAttestationVerifier {
    fn new(trusted_cert_required: bool) -> Self {
        let root_cert = include_bytes!("../certs/aws_root.der");
        Self {
            // TODO: can we avoid copying static data into an Arc?
            root_cert: Arc::new(root_cert.to_vec()),
            trusted_cert_required: trusted_cert_required,
            _not_unpin: PhantomPinned::default(),
        }
    }
}

impl AttestationVerifier for NsmAttestationVerifier {
    fn verify_doc(&self, doc: &[u8]) -> Result<SessionValues, Error> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if let Ok(contents) = NitroAdDoc::from_bytes(&doc, self.root_cert.as_ref(), ts) {
            if let Ok(json) = contents.to_json() {
                debug!("json attestation: {json:?}");
            }

            // TODO: Verify PCRs

            let nonce = contents
                .payload_ref
                .nonce
                .ok_or(Error::ClientNonceError("none set".to_owned()))?;
            let fingerprint = contents
                .payload_ref
                .public_key
                .ok_or(Error::CertificateFingerprintError("none set".to_owned()))?;

            return Ok(SessionValues {
                client_nonce: nonce.into_vec(),
                cert_fingerprint: fingerprint.into_vec(),
            });
        }
        Err(Error::FailedToParseAttestation())
    }

    fn trusted_cert_required(&self) -> bool {
        return self.trusted_cert_required;
    }
}
