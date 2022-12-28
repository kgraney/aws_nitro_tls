use crate::attestation::AttestationVerifier;
use crate::constants;
use crate::error::Error;
use crate::util::SslRefHelper as _;
use crate::verifier::Verifier;
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

pub struct AttestedBuilder {
    verifier: Arc<Verifier>,
}

impl AttestedBuilder {
    pub fn new(verifier: Verifier) -> AttestedBuilder {
        AttestedBuilder {
            verifier: Arc::new(verifier),
        }
    }

    pub fn http_client(
        &self,
    ) -> Result<hyper::Client<HttpsConnector<HttpConnector>, hyper::body::Body>, Error> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        let https = HttpsConnector::with_connector(http, self.ssl_connector_builder()?)?;
        Ok(Client::builder().build::<_, hyper::Body>(https))
    }

    pub fn ssl_connector_builder(&self) -> Result<SslConnectorBuilder, Error> {
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

        builder.add_custom_ext(
            constants::EXTENSION_TYPE_VAL,
            constants::extension_context(),
            add_client_attestation_cb,
            parse_cb,
        )?;

        let cert_cb_verifier = self.verifier.clone();
        let cert_cb = move |result: bool, chain: &mut X509StoreContextRef| -> bool {
            verify_cert_fingerprint(&cert_cb_verifier, fingerprint_idx.clone(), result, chain)
        };
        builder.set_verify_callback(SslVerifyMode::PEER, cert_cb);

        if let Ok(keylog_file) = env::var("SSLKEYLOGFILE") {
            log_secrets(&mut builder, keylog_file);
        }

        Ok(builder)
    }
}

// Log TLS premaster/master secrets for decrypting sessions with Wireshark.
fn log_secrets(builder: &mut SslConnectorBuilder, keylog_file: String) {
    log::warn!("TLS secrets are being logged to: {}", keylog_file);
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

fn add_client_attestation_cb(
    _r: &mut SslRef,
    ctx: ExtensionContext,
    _cert: Option<(usize, &X509Ref)>,
) -> Result<Option<Vec<u8>>, SslAlert> {
    log::debug!("add attestation extension callback: {ctx:?}");
    match ctx {
        // TODO: don't send an extra 0xff
        ExtensionContext::CLIENT_HELLO => Ok(Some(vec![0xff])),
        _ => Ok(None),
    }
}

fn parse_client_attestation_cb(
    verifier: &Arc<Verifier>,
    fingerprint_idx: Index<Ssl, Vec<u8>>,
    r: &mut SslRef,
    ctx: ExtensionContext,
    data: &[u8],
    _cert: Option<(usize, &X509Ref)>,
) -> Result<(), SslAlert> {
    log::debug!("parse client attestation callback: {ctx:?}");
    if ctx == ExtensionContext::TLS1_3_ENCRYPTED_EXTENSIONS {
        let values = verifier.verify_doc(data)?;
        if r.client_nonce() != values.client_nonce {
            return Err(SslAlert::ILLEGAL_PARAMETER);
        }
        // The cert isn't availabe yet in this callback, so we store the cert fingerprint provided
        // in the attestation document and retrieve it for comparison once we have the server's
        // certificate available.
        r.set_ex_data(fingerprint_idx, values.cert_fingerprint);
    }
    Ok(())
}

fn verify_cert_fingerprint(
    verifier: &Arc<Verifier>,
    fingerprint_idx: Index<Ssl, Vec<u8>>,
    result: bool,
    chain: &mut X509StoreContextRef,
) -> bool {
    let depth = chain.error_depth();
    if depth != 0 {
        return result;
    }

    // For only the first certificate in the chain verify that the certificate fingerprint matches
    // what we saw earlier in the attestation doc.
    log::debug!("verifying fingerprint in session certificate");
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
        if verifier.should_validate_cert() {
            return result;
        } else {
            return true;
        }
    }
    log::debug!("Fingerprint mismatch! doc:{doc_fingerprint:?} cert:{cert_fingerprint:?}");
    false
}
