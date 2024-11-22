use rand_core::{CryptoRng, RngCore};

use crate::common::Polynomial;
use crate::curve::scalar::Scalar;

/// A verifiable secret share algorithm
pub struct VSS {}

impl VSS {
    /// Construct a random polynomial of the passed degree `n`
    pub fn random_poly<RNG: RngCore + CryptoRng>(
        n: u32,
        rng: &mut RNG,
    ) -> Polynomial<Scalar, Scalar> {
        Polynomial::random(n, rng)
    }

    /// Construct a random polynomial of the passed degree `n` using the passed constant term
    pub fn random_poly_with_constant<RNG: RngCore + CryptoRng>(
        n: u32,
        constant: Scalar,
        rng: &mut RNG,
    ) -> Polynomial<Scalar, Scalar> {
        let mut poly = Polynomial::random(n, rng);
        poly.params[0] = constant;

        poly
    }
}
