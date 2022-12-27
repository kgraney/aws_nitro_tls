mod aws_nsm {
    pub use aws_nitro_enclaves_nsm_api::*;
}
use crate::attestation::AttestationProvider;
use serde_bytes::ByteBuf;
use std::marker::PhantomPinned;

pub struct NsmAttestationProvider {
    // File descriptor to the NSM device.
    nsm_fd: i32,
    _not_unpin: PhantomPinned,
}

impl Default for NsmAttestationProvider {
    fn default() -> NsmAttestationProvider {
        NsmAttestationProvider {
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
    ) -> Result<Vec<u8>, &'static str> {
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
        Err("Error in NSM request")
    }
}
