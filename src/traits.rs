use rand_core::{CryptoRng, RngCore};

pub trait Signer {
    fn new<RNG: RngCore + CryptoRng>(ids: &[usize], n: usize, t: usize, rng: &mut RNG) -> Self;
    fn load(path: &str) -> Self;

    fn save(&self, path: &str);
}
