use rand_core::{CryptoRng, RngCore};

use crate::curve::scalar::Scalar;

/// A publicly verifiable secret share algorithm from Sta96
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
    //use super::*;
    //use crate::curve::{point::Point, scalar::Scalar};

    use is_prime;
    use num_bigint::BigUint;
    use num_integer::Integer;

    #[test]
    fn is_p_minus_1_over_2_prime() {
        let p = BigUint::from_bytes_be(crate::curve::point::N.as_slice());

        assert!(is_prime::is_biguint_prime(p.clone()));

        let p12 = (&p - 1u32) / 2u32;
        let p21 = &p12 * 2u32;

	println!("p         = {}", &p);
	println!("p12       = {}", &p12);
	println!("p21       = {}", &p21);
	println!("p21^1 % p = {}", p21.modpow(&BigUint::from(1u32), &p));
	
        assert_eq!(p12, p21);
        assert!(p12.is_odd());
        assert!(is_prime::is_biguint_prime(p12.clone()));
    }
}
