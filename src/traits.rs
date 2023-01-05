use rand_core::{CryptoRng, RngCore};

use crate::common::{PublicNonce, SignatureShare};

pub trait Signer {
    fn new<RNG: RngCore + CryptoRng>(ids: &[usize], n: usize, t: usize, rng: &mut RNG) -> Self;

    fn gen_nonces<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG) -> Vec<(usize, PublicNonce)>;

    fn sign(&self, msg: &[u8], signers: &[usize], nonces: &[PublicNonce]) -> Vec<SignatureShare>;
}
