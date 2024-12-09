use is_prime;
use rand_core::{CryptoRng, RngCore};

use crate::curve::scalar::Scalar;

/// A publicly verifiable secret share algorithm
pub struct PVSS {
    R: Vec<Scalar>,
    c: Scalar,
}

impl PVSS {
    /// Construct a random polynomial of the passed degree `n`
    pub fn new<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> PVSS {
        let R = Vec::new();
        let c = Scalar::random(rng);
        PVSS { R, c }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::curve::{point::Point, scalar::Scalar};

    use num_bigint::BigUint;

    #[test]
    fn is_p_minus_1_over_2_prime() {
        let p = BigUint::from_bytes_be(crate::curve::point::N.as_slice());

        assert!(is_prime::is_biguint_prime(p.clone()));

        let p12 = (p - 1u32) / 2u32;

        assert!(is_prime::is_biguint_prime(p12.clone()));
    }
}
