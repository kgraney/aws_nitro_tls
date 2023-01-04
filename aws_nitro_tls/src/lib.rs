pub mod certgen;
pub mod client;
pub mod server;
pub mod verifier;

mod attestation;
mod constants;
mod error;
mod nsm;
mod nsm_fake;
mod util;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
