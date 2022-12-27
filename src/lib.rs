use openssl::ssl::SslAcceptorBuilder;
use std::path::PathBuf;

mod attestation;
pub mod client;
mod constants;
mod nsm;
mod server;
mod util;

pub struct ServerBuilder(server::AttestedBuilder<nsm::NsmAttestationProvider>);

impl Default for ServerBuilder {
    fn default() -> ServerBuilder {
        ServerBuilder(server::AttestedBuilder::<nsm::NsmAttestationProvider>::default())
    }
}

impl ServerBuilder {
    pub fn ssl_acceptor_builder(
        &self,
        fullchain: &PathBuf,
        private_key: &PathBuf,
    ) -> std::io::Result<SslAcceptorBuilder> {
        self.0.ssl_acceptor_builder(fullchain, private_key)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
