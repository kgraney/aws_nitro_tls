use crate::attestation::AttestationProvider;
use crate::constants;
use crate::error::Error;
use crate::nsm::NsmAttestationProvider;
use crate::nsm_fake::FakeAttestationProvider;
use crate::util::SslRefHelper as _;
use openssl::ssl::{
    ExtensionContext, SslAcceptor, SslAcceptorBuilder, SslAlert, SslFiletype, SslMethod,
    SslOptions, SslRef, SslVerifyMode, SslVersion,
};
use openssl::x509::{X509Ref, X509StoreContextRef};
use std::marker::{PhantomPinned, Send, Sync};
use std::path::PathBuf;
use std::sync::Arc;

pub type NsmServerBuilder = AttestedBuilder<NsmAttestationProvider>;
pub type LocalServerBuilder = AttestedBuilder<FakeAttestationProvider>;

pub trait AcceptorBuilder {
    fn ssl_acceptor_builder(
        &self,
        fullchain: &PathBuf,
        private_key: &PathBuf,
    ) -> Result<SslAcceptorBuilder, Error>;
}

pub struct AttestedBuilder<T>
where
    T: AttestationProvider,
{
    attestation_provider: Arc<T>,

    // If true require that connecting clients present a valid attestation for themself.
    verify_client_attestation: bool,

    _not_unpin: PhantomPinned,
}

impl<T> Default for AttestedBuilder<T>
where
    T: AttestationProvider + Default,
{
    fn default() -> Self {
        AttestedBuilder {
            attestation_provider: Arc::new(T::default()),
            verify_client_attestation: false,
            _not_unpin: PhantomPinned::default(),
        }
    }
}

impl<T> AttestedBuilder<T>
where
    T: AttestationProvider + Default,
{
    // TODO: make construction of this more idiomatic & obvious.
    pub fn new(verify_client_attestation: bool) -> Self {
        AttestedBuilder {
            attestation_provider: Arc::new(T::default()),
            verify_client_attestation: verify_client_attestation,
            _not_unpin: PhantomPinned::default(),
        }
    }
}

impl<T> AcceptorBuilder for AttestedBuilder<T>
where
    T: AttestationProvider,
    T: Send + Sync + 'static,
{
    fn ssl_acceptor_builder(
        &self,
        fullchain: &PathBuf,
        private_key: &PathBuf,
    ) -> Result<SslAcceptorBuilder, Error> {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        acceptor.clear_options(SslOptions::NO_TLSV1_3);
        acceptor.clear_options(SslOptions::NO_TICKET);
        acceptor.set_private_key_file(private_key, SslFiletype::PEM)?;
        acceptor.set_certificate_chain_file(fullchain)?;
        acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;

        let ap_clone = self.attestation_provider.clone();
        let add_cb =
            move |r: &mut SslRef, ctx: ExtensionContext, cert: Option<(usize, &X509Ref)>| {
                add_server_attestation_cb(&ap_clone, r, ctx, cert)
            };
        acceptor.add_custom_ext(
            constants::EXTENSION_TYPE_VAL,
            constants::extension_context(),
            add_cb,
            parse_server_attestation_cb,
        )?;

        if self.verify_client_attestation {
            let cert_cb = |result: bool, _chain: &mut X509StoreContextRef| -> bool {
                // TODO: verify the client's attestation document (and also their cert?)
                log::debug!("verify callback: {}", result);
                true
            };
            acceptor.set_verify_callback(
                SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
                cert_cb,
            );
        }

        Ok(acceptor)
    }
}

fn add_server_attestation_cb<T: AttestationProvider>(
    provider: &Arc<T>,
    r: &mut SslRef,
    ctx: ExtensionContext,
    _cert: Option<(usize, &X509Ref)>,
) -> Result<Option<Vec<u8>>, SslAlert> {
    log::debug!("add server attestation callback: {ctx:?}");
    if ctx == ExtensionContext::TLS1_3_ENCRYPTED_EXTENSIONS {
        let client_random = r.client_nonce();
        // TODO: avoid copy?
        let cert_fingerprint = r
            .cert_fingerprint()
            .or(Err(SslAlert::DECODE_ERROR))?
            .to_vec();
        let doc = provider.attestation_doc(Some(client_random), None, Some(cert_fingerprint))?;
        return Ok(Some(doc));
    }

    // When we send certificate requests to clients we include the extension requesting,
    // additionally, an attestation document.
    if ctx == ExtensionContext::TLS1_3_CERTIFICATE_REQUEST {
        // TODO: add a nonce here? option to include other data?
        return Ok(Some(vec![0xff]));
    }

    Ok(None)
}

fn parse_server_attestation_cb(
    _r: &mut SslRef,
    ctx: ExtensionContext,
    _data: &[u8],
    _cert: Option<(usize, &X509Ref)>,
) -> Result<(), SslAlert> {
    log::debug!("parse server attestation callback: {ctx:?}");
    Ok(())
}
