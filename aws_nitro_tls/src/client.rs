use crate::attestation::{AttestationProvider, AttestationVerifier};
use crate::certgen;
use crate::constants;
use crate::error::Error;
use crate::util::SslRefHelper as _;
use hyper::client::HttpConnector;
use hyper::Client;
use hyper_openssl::HttpsConnector;
use openssl::ex_data::Index;
use openssl::hash::MessageDigest;
use openssl::ssl::{
    ExtensionContext, Ssl, SslAlert, SslConnector, SslConnectorBuilder, SslMethod, SslRef,
    SslVerifyMode,
};
use openssl::x509::{X509Ref, X509StoreContext, X509StoreContextRef};
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;
use tracing::{debug, error, warn};

pub trait ConnectorBuilder {
    fn ssl_connector_builder(&self) -> Result<SslConnectorBuilder, Error>;
    fn http_client(
        &self,
    ) -> Result<hyper::Client<HttpsConnector<HttpConnector>, hyper::body::Body>, Error>;
}

pub struct AttestedBuilder<P, V>
where
    P: AttestationProvider,
    V: AttestationVerifier,
{
    provider: Option<Arc<P>>,
    verifier: Arc<V>,
}

impl<P, V> AttestedBuilder<P, V>
where
    P: AttestationProvider,
    V: AttestationVerifier,
{
    pub fn new(verifier: V, provider: Option<P>) -> Self {
        let provider = match provider {
            None => None,
            Some(b) => Some(Arc::from(b)),
        };
        Self {
            provider: provider,
            verifier: Arc::from(verifier),
        }
    }
}

impl<P, V> ConnectorBuilder for AttestedBuilder<P, V>
where
    P: AttestationProvider + 'static,
    V: AttestationVerifier + 'static,
{
    fn http_client(
        &self,
    ) -> Result<hyper::Client<HttpsConnector<HttpConnector>, hyper::body::Body>, Error> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        let https = HttpsConnector::with_connector(http, self.ssl_connector_builder()?)?;
        Ok(Client::builder().build::<_, hyper::Body>(https))
    }

    fn ssl_connector_builder(&self) -> Result<SslConnectorBuilder, Error> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())?;
        builder.set_verify(openssl::ssl::SslVerifyMode::PEER);

        let fingerprint_idx = Ssl::new_ex_index::<Vec<u8>>()?;

        let parse_cb_verifier = self.verifier.clone();
        let parse_cb = move |r: &mut SslRef,
                             ctx: ExtensionContext,
                             data: &[u8],
                             cert: Option<(usize, &X509Ref)>| {
            parse_client_attestation_cb(
                &parse_cb_verifier,
                fingerprint_idx.clone(),
                r,
                ctx,
                data,
                cert,
            )
        };

        let add_cb_provider = self.provider.clone();
        let add_cb =
            move |r: &mut SslRef, ctx: ExtensionContext, cert: Option<(usize, &X509Ref)>| {
                add_client_attestation_cb(&add_cb_provider, r, ctx, cert)
            };

        builder.add_custom_ext(
            constants::EXTENSION_TYPE_VAL,
            constants::extension_context(),
            add_cb,
            parse_cb,
        )?;

        let cert_cb_verifier = self.verifier.clone();
        let cert_cb = move |result: bool, chain: &mut X509StoreContextRef| -> bool {
            verify_cert_fingerprint(&cert_cb_verifier, fingerprint_idx.clone(), result, chain)
        };
        builder.set_verify_callback(SslVerifyMode::PEER, cert_cb);

        // Self-signed cert to use for mutual TLS.
        let cert = certgen::new_cert()?;
        builder.set_certificate(&cert.cert)?;
        builder.set_private_key(&cert.pkey)?;

        if let Ok(keylog_file) = env::var("SSLKEYLOGFILE") {
            log_secrets(&mut builder, keylog_file);
        }

        Ok(builder)
    }
}

// Log TLS premaster/master secrets for decrypting sessions with Wireshark.
fn log_secrets(builder: &mut SslConnectorBuilder, keylog_file: String) {
    warn!("TLS secrets are being logged to: {}", keylog_file);
    builder.set_keylog_callback(move |_: &SslRef, s: &str| {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&keylog_file)
            .unwrap();
        file.write_all(s.as_bytes()).unwrap();
        file.write_all("\n".as_bytes()).unwrap();
    });
}

fn add_client_attestation_cb<P: AttestationProvider>(
    provider: &Option<Arc<P>>,
    r: &mut SslRef,
    ctx: ExtensionContext,
    _cert: Option<(usize, &X509Ref)>,
) -> Result<Option<Vec<u8>>, SslAlert> {
    if ctx == ExtensionContext::CLIENT_HELLO {
        debug!("requesting attestation from server in CLIENT_HELLO");
        return Ok(Some(vec![]));
    }
    if ctx == ExtensionContext::TLS1_3_CERTIFICATE {
        let provider = provider.as_ref().ok_or(SslAlert::DECODE_ERROR)?;

        debug!("providing attestation to server in client CERTIFICATE");
        let client_random = r.server_nonce();
        let cert_fingerprint = r
            .cert_fingerprint()
            .or(Err(SslAlert::DECODE_ERROR))?
            .to_vec();
        let doc = provider.attestation_doc(Some(client_random), None, Some(cert_fingerprint))?;
        return Ok(Some(doc));
    }
    Ok(None)
}

fn parse_client_attestation_cb<V: AttestationVerifier>(
    verifier: &Arc<V>,
    fingerprint_idx: Index<Ssl, Vec<u8>>,
    r: &mut SslRef,
    ctx: ExtensionContext,
    data: &[u8],
    _cert: Option<(usize, &X509Ref)>,
) -> Result<(), SslAlert> {
    if ctx == ExtensionContext::TLS1_3_ENCRYPTED_EXTENSIONS {
        debug!("parsing server attestation doc");
        let values = verifier.verify_doc(data)?;
        if r.client_nonce() != values.client_nonce {
            error!("attestation doc nonce does not match!");
            return Err(SslAlert::ILLEGAL_PARAMETER);
        }
        // The cert isn't available yet in this callback, so we store the cert fingerprint provided
        // in the attestation document and retrieve it for comparison once we have the server's
        // certificate available.
        r.set_ex_data(fingerprint_idx, values.cert_fingerprint);
    }
    Ok(())
}

fn verify_cert_fingerprint<V: AttestationVerifier>(
    verifier: &Arc<V>,
    fingerprint_idx: Index<Ssl, Vec<u8>>,
    result: bool,
    chain: &mut X509StoreContextRef,
) -> bool {
    let depth = chain.error_depth();
    if depth != 0 {
        // TODO: Make this verification configurable.  We might want to override the return value
        // here, not using the result from OpenSSL.
        return result;
    }

    debug!("verifying fingerprint in session certificate");
    // For only the first certificate in the chain verify that the certificate fingerprint matches
    // what we saw earlier in the attestation doc.
    let ssl_idx = X509StoreContext::ssl_idx().expect("ssl_idx invalid");
    let ssl_ctx = chain.ex_data(ssl_idx).expect("error getting ssl_idx");

    let doc_fingerprint = match ssl_ctx.ex_data(fingerprint_idx) {
        Some(bytes) => bytes,
        None => return false,
    };

    let cert_fingerprint = chain
        .current_cert()
        .and_then(|x| Some(x.digest(MessageDigest::sha256())));
    let cert_fingerprint = match cert_fingerprint {
        Some(Ok(bytes)) => bytes,
        Some(Err(_)) => return false,
        None => return false,
    };

    if *cert_fingerprint == *doc_fingerprint {
        debug!("fingerprint verification successful!");
        if verifier.trusted_cert_required() {
            return result;
        } else {
            return true;
        }
    }
    debug!("Fingerprint mismatch! doc:{doc_fingerprint:?} cert:{cert_fingerprint:?}");
    false
}
