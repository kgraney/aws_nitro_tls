use crate::attestation::{AttestationProvider, AttestationVerifier};
use crate::constants;
use crate::error::Error;
use crate::util::SslRefHelper as _;
use openssl::ex_data::Index;
use openssl::pkey::{PKeyRef, Private};
use openssl::ssl::{
    ExtensionContext, Ssl, SslAcceptor, SslAcceptorBuilder, SslAlert, SslMethod, SslOptions,
    SslRef, SslVerifyMode, SslVersion,
};
use openssl::x509::{X509, X509Ref, X509StoreContext, X509StoreContextRef};
use std::marker::PhantomPinned;
use std::sync::Arc;
use tracing::debug;

pub trait AcceptorBuilder {
    fn ssl_acceptor_builder(
        &self,
        fullchain: &Vec<X509>,
        private_key: &PKeyRef<Private>,
    ) -> Result<SslAcceptorBuilder, Error>;
}

pub struct AttestedBuilder<P, V>
where
    P: AttestationProvider,
    V: AttestationVerifier,
{
    provider: Arc<P>,
    verifier: Option<Arc<V>>,
    _not_unpin: PhantomPinned,
}

impl<P, V> AttestedBuilder<P, V>
where
    P: AttestationProvider,
    V: AttestationVerifier,
{
    pub fn new(provider: P, verifier: Option<V>) -> Self {
        let verifier = match verifier {
            None => None,
            Some(b) => Some(Arc::from(b)),
        };
        Self {
            provider: Arc::from(provider),
            verifier: verifier,
            _not_unpin: PhantomPinned::default(),
        }
    }
}

impl<P, V> AcceptorBuilder for AttestedBuilder<P, V>
where
    P: AttestationProvider + 'static,
    V: AttestationVerifier + 'static,
{
    fn ssl_acceptor_builder(
        &self,
        fullchain: &Vec<X509>,
        private_key: &PKeyRef<Private>,
    ) -> Result<SslAcceptorBuilder, Error> {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        acceptor.clear_options(SslOptions::NO_TLSV1_3);
        acceptor.clear_options(SslOptions::NO_TICKET);
        acceptor.set_private_key(&private_key)?;

        let slice = fullchain.as_slice();
        let (leaf, chain) = slice.split_first().ok_or(Error::NoCertificateKnown("No leaf certificate in chain".to_string()))?;
        acceptor.set_certificate(leaf)?;
        for cert in chain {
            // TODO: Investigate why add_extra_chain_cert needs an X509 instead of an X509Ref.
            let copy = X509::from_der(&cert.to_der()?)?;
            acceptor.add_extra_chain_cert(copy)?;
        }
        acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;

        let client_verified_idx = Ssl::new_ex_index::<bool>()?;
        if let Some(_) = &self.verifier {
            let cert_cb = move |_result: bool, chain: &mut X509StoreContextRef| -> bool {
                // We don't actually care about certificate verification at all, so any certificate
                // will do.  We do care about verifying the attestation extension, which is
                // verified in the parse callback.  A boolean is transferred here and used as
                // the certificate verify result regardless of what certificate is actually used.
                let ssl_idx = X509StoreContext::ssl_idx().expect("ssl_idx invalid");
                let ssl_ctx = chain.ex_data(ssl_idx).expect("error getting ssl_ctx");
                match ssl_ctx.ex_data(client_verified_idx.clone()) {
                    Some(r) => *r, // Previous result of verifying attestation extension
                    None => false, // No attestation extension
                }
            };
            acceptor.set_verify_callback(
                SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
                cert_cb,
            );
        }

        let ap_clone = self.provider.clone();
        let add_cb =
            move |r: &mut SslRef, ctx: ExtensionContext, cert: Option<(usize, &X509Ref)>| {
                add_server_attestation_cb(&ap_clone, r, ctx, cert)
            };

        let vp_clone = match self.verifier.clone() {
            None => None,
            Some(v) => Some(v.clone()),
        };
        let parse_cb = move |r: &mut SslRef,
                             ctx: ExtensionContext,
                             data: &[u8],
                             cert: Option<(usize, &X509Ref)>| {
            parse_server_attestation_cb(
                vp_clone.as_ref(),
                client_verified_idx.clone(),
                r,
                ctx,
                data,
                cert,
            )
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

fn add_server_attestation_cb<P: AttestationProvider>(
    provider: &Arc<P>,
    r: &mut SslRef,
    ctx: ExtensionContext,
    _cert: Option<(usize, &X509Ref)>,
) -> Result<Option<Vec<u8>>, SslAlert> {
    if ctx == ExtensionContext::TLS1_3_ENCRYPTED_EXTENSIONS {
        let client_random = r.client_nonce();
        // TODO: avoid copy?
        let cert_fingerprint = r
            .cert_fingerprint()
            .or(Err(SslAlert::DECODE_ERROR))?
            .to_vec();
        let doc = provider.attestation_doc(Some(client_random), None, Some(cert_fingerprint))?;
        debug!("including attestation doc in response: {} bytes", doc.len());
        return Ok(Some(doc));
    }

    // When we send certificate requests to clients we include the extension requesting,
    // additionally, an attestation document.
    if ctx == ExtensionContext::TLS1_3_CERTIFICATE_REQUEST {
        debug!("requesting client certificate with attestation");
        // TODO: add a nonce here? option to include other data?
        return Ok(Some(vec![]));
    }

    Ok(None)
}

fn parse_server_attestation_cb<V: AttestationVerifier>(
    verifier: Option<&Arc<V>>,
    client_verified_idx: Index<Ssl, bool>,
    r: &mut SslRef,
    ctx: ExtensionContext,
    data: &[u8],
    _cert: Option<(usize, &X509Ref)>,
) -> Result<(), SslAlert> {
    if ctx == ExtensionContext::TLS1_3_CERTIFICATE {
        debug!("parsing client certificate msg that should include attestation");
        r.set_ex_data(client_verified_idx, false);
        let v = Option::as_ref(&verifier).ok_or(SslAlert::DECODE_ERROR)?;
        let values = v.verify_doc(data)?;
        if r.server_nonce() != values.client_nonce {
            debug!("client nonce failed");
            return Err(SslAlert::ILLEGAL_PARAMETER);
        }
        // TODO: verify the cert fingerprint (this isn't set correctly at the moment)
        r.set_ex_data(client_verified_idx, true);
    }
    Ok(())
}
