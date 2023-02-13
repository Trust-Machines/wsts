use p256k1::scalar::Scalar;
use polynomial::Polynomial;
use rand_core::{CryptoRng, RngCore};

/// A verifiable secret share algorithm
pub struct VSS {}

impl VSS {
    /// Construct a random polynomial of the passed degree `n`
    pub fn random_poly<RNG: RngCore + CryptoRng>(n: usize, rng: &mut RNG) -> Polynomial<Scalar> {
        let params: Vec<Scalar> = (0..n + 1).map(|_| Scalar::random(rng)).collect();
        Polynomial::new(params)
    }
}
