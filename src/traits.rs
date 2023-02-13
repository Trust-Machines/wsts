use rand_core::{CryptoRng, RngCore};

use crate::common::{PublicNonce, SignatureShare};

/// A trait which provides a common interface for `v1` and `v2`
pub trait Signer<T> {
    /// Generate nonces for all the signer's parties
    fn gen_nonces<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG) -> Vec<PublicNonce>;

    /// Sign `msg` for all the signer's parties
    fn sign(&self, msg: &[u8], signers: &[usize], nonces: &[PublicNonce])
        -> Vec<SignatureShare<T>>;
}
