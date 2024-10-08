use rand_core::{CryptoRng, RngCore};

use crate::curve::scalar::Scalar;

/// A verifiable secret share algorithm
pub struct VSS {}

impl VSS {
    /// Construct a random polynomial of the passed degree `n`
    pub fn random_poly<RNG: RngCore + CryptoRng>(n: u32, rng: &mut RNG) -> Vec<Scalar> {
        (0..n + 1).map(|_| Scalar::random(rng)).collect()
    }

    /// Construct a random polynomial of the passed degree `n` using the passed constant term
    pub fn random_poly_with_constant<RNG: RngCore + CryptoRng>(
        n: u32,
        constant: Scalar,
        rng: &mut RNG,
    ) -> Vec<Scalar> {
        let mut params: Vec<Scalar> = (0..n + 1).map(|_| Scalar::random(rng)).collect();
        params[0] = constant;

        params
    }
}
