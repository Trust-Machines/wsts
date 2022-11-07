use secp256k1_math::{
    scalar::Scalar,
};
use polynomial::Polynomial;
use rand_core::{
    RngCore, CryptoRng,
};

pub struct VSS {
    
}

impl VSS {
    pub fn random_poly<RNG: RngCore+CryptoRng>(n: usize, rng: &mut RNG) -> Polynomial<Scalar> {
	let params: Vec<Scalar> = (0..n+1).map(|_| Scalar::random(rng)).collect();
	Polynomial::new(params)
    }
}
