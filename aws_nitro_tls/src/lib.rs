pub mod attestation;
pub mod certgen;
pub mod client;
pub mod nsm;
pub mod nsm_fake;
pub mod server;

mod constants;
mod error;
mod util;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
