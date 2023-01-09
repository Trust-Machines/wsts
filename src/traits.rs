use rand_core::{CryptoRng, RngCore};

use crate::common::{PublicNonce, SignatureShare};

pub trait Signer {
    fn gen_nonces<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG) -> Vec<PublicNonce>;

    fn sign(&self, msg: &[u8], signers: &[usize], nonces: &[PublicNonce]) -> Vec<SignatureShare>;
}
