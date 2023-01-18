use aws_nitro_tls::attestation::{AttestationProvider, AttestationVerifier};
use aws_nitro_tls::client::{AttestedBuilder as ClientAttestedBuilder, ConnectorBuilder};
use aws_nitro_tls::nsm::{NsmAttestationProvider, NsmAttestationVerifier};
use aws_nitro_tls::nsm_fake::{FakeAttestationProvider, FakeAttestationVerifier};
use aws_nitro_tls::server::{AcceptorBuilder, AttestedBuilder};

fn builder<P, V>(mutual_tls: bool) -> Box<dyn AcceptorBuilder + Send + Sync>
where
    P: AttestationProvider + Default + 'static,
    V: AttestationVerifier + Default + 'static,
{
    match mutual_tls {
        true => Box::new(AttestedBuilder::<P, V>::new(
            P::default(),
            Some(V::default()),
        )),
        false => Box::new(AttestedBuilder::<P, V>::new(P::default(), None)),
    }
}

pub fn acceptor_builder(no_nsm: bool, mutual_tls: bool) -> Box<dyn AcceptorBuilder + Send + Sync> {
    match no_nsm {
        true => builder::<FakeAttestationProvider, FakeAttestationVerifier>(mutual_tls),
        false => builder::<NsmAttestationProvider, NsmAttestationVerifier>(mutual_tls),
    }
}

fn client_builder<P, V>(mutual_tls: bool) -> Box<dyn ConnectorBuilder + Send + Sync>
where
    P: AttestationProvider + Default + 'static,
    V: AttestationVerifier + Default + 'static,
{
    match mutual_tls {
        true => Box::new(ClientAttestedBuilder::<P, V>::new(
            V::default(),
            Some(P::default()),
        )),
        false => Box::new(ClientAttestedBuilder::<P, V>::new(V::default(), None)),
    }
}

pub fn connector_builder(no_nsm: bool, mutual_tls: bool) -> Box<dyn ConnectorBuilder> {
    match no_nsm {
        true => client_builder::<FakeAttestationProvider, FakeAttestationVerifier>(mutual_tls),
        false => client_builder::<NsmAttestationProvider, NsmAttestationVerifier>(mutual_tls),
    }
}
