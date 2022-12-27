use crate::attestation::{AttestationVerifier, SessionValues};
use aws_nitro_enclaves_attestation::NitroAdDoc;
use openssl::ssl::SslAlert;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Verifier {
    // The AWS root certificate.
    root_cert: Arc<Vec<u8>>,
}

impl Verifier {
    pub fn new(root_cert: Vec<u8>) -> Verifier {
        Verifier {
            root_cert: Arc::new(root_cert),
        }
    }

    pub fn new_aws() -> Verifier {
        let root_cert = include_bytes!("../certs/aws_root.der");
        Verifier {
            // TODO: can we avoid copying static data into an Arc?
            root_cert: Arc::new(root_cert.to_vec()),
        }
    }
}

impl AttestationVerifier for Verifier {
    fn verify_doc(&self, doc: &[u8]) -> Result<SessionValues, SslAlert> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if let Ok(contents) = NitroAdDoc::from_bytes(&doc, self.root_cert.as_ref(), ts) {
            if let Ok(json) = contents.to_json() {
                log::debug!("json attestation: {json:?}");
            }

            // TODO: Verify PCRs

            let nonce = contents.payload_ref.nonce.ok_or(SslAlert::DECODE_ERROR)?;
            let fingerprint = contents
                .payload_ref
                .public_key
                .ok_or(SslAlert::DECODE_ERROR)?;

            return Ok(SessionValues {
                client_nonce: nonce.into_vec(),
                cert_fingerprint: fingerprint.into_vec(),
            });
        }
        Err(SslAlert::DECODE_ERROR)
    }
}
