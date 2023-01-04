use crate::error::Error;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use rcgen::generate_simple_self_signed;

pub struct GeneratedCert {
    pub cert: X509,
    pub pkey: PKey<Private>,
}

pub fn new_cert() -> Result<GeneratedCert, Error> {
    let subject_alt_names = vec!["localhost".to_string()];

    let cert = generate_simple_self_signed(subject_alt_names)?;
    let x509 = X509::from_der(&cert.serialize_der()?)?;
    let pkey = PKey::private_key_from_der(&cert.serialize_private_key_der())?;

    Ok(GeneratedCert {
        cert: x509,
        pkey: pkey,
    })
}

#[cfg(test)]
mod tests {
    use crate::certgen::new_cert;

    #[test]
    fn test_new_cert() {
        new_cert();
    }
}
