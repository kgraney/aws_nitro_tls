use crate::attestation::{AttestationProvider, AttestationVerifier};
use crate::constants;
use crate::error::Error;
use crate::nsm::NsmAttestationProvider;
use crate::nsm_fake::FakeAttestationProvider;
use crate::util::SslRefHelper as _;
use crate::verifier::Verifier;
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
        verifier: Option<Verifier>,
    ) -> Result<SslAcceptorBuilder, Error>;
}

pub struct AttestedBuilder<T>
where
    T: AttestationProvider,
{
    attestation_provider: Arc<T>,

    _not_unpin: PhantomPinned,
}

impl<T> Default for AttestedBuilder<T>
where
    T: AttestationProvider + Default,
{
    fn default() -> Self {
        AttestedBuilder {
            attestation_provider: Arc::new(T::default()),
            _not_unpin: PhantomPinned::default(),
        }
    }
}

impl<T> AttestedBuilder<T>
where
    T: AttestationProvider + Default,
{
    // TODO: make construction of this more idiomatic & obvious.
    pub fn new() -> Self {
        AttestedBuilder {
            attestation_provider: Arc::new(T::default()),
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
        verifier: Option<Verifier>,
    ) -> Result<SslAcceptorBuilder, Error> {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        acceptor.clear_options(SslOptions::NO_TLSV1_3);
        acceptor.clear_options(SslOptions::NO_TICKET);
        acceptor.set_private_key_file(private_key, SslFiletype::PEM)?;
        acceptor.set_certificate_chain_file(fullchain)?;
        acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;

        if let Some(_) = &verifier {
            let cert_cb = |_result: bool, _chain: &mut X509StoreContextRef| -> bool {
                // We don't actually care about certificate verification at all, so any certificate
                // will do.  We do care about verifying the attestation extension, which is
                // implemented in the parse callback.
                true
                // TODO: verify the client certificate?
            };
            acceptor.set_verify_callback(
                SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
                cert_cb,
            );
        }

        let ap_clone = self.attestation_provider.clone();
        let add_cb =
            move |r: &mut SslRef, ctx: ExtensionContext, cert: Option<(usize, &X509Ref)>| {
                add_server_attestation_cb(&ap_clone, r, ctx, cert)
            };

        let vp_clone = Arc::new(verifier).clone();
        let parse_cb = move |r: &mut SslRef,
                             ctx: ExtensionContext,
                             data: &[u8],
                             cert: Option<(usize, &X509Ref)>| {
            parse_server_attestation_cb(vp_clone.clone(), r, ctx, data, cert)
        };

        acceptor.add_custom_ext(
            constants::EXTENSION_TYPE_VAL,
            constants::extension_context(),
            add_cb,
            parse_cb,
        )?;

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
    verifier: Arc<Option<Verifier>>,
    r: &mut SslRef,
    ctx: ExtensionContext,
    data: &[u8],
    _cert: Option<(usize, &X509Ref)>,
) -> Result<(), SslAlert> {
    log::debug!("parse server attestation callback: {ctx:?}");
    if ctx == ExtensionContext::TLS1_3_CERTIFICATE {
        let v = Option::as_ref(&verifier).ok_or(SslAlert::DECODE_ERROR)?;
        let values = v.verify_doc(data)?;
        log::debug!("client attestation: {values:?}");
        if r.server_nonce() != values.client_nonce {
            return Err(SslAlert::ILLEGAL_PARAMETER);
        }
    }
    Ok(())
}
