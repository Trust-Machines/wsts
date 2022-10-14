use curve25519_dalek::{
    scalar::Scalar, ristretto::RistrettoPoint as Point,
};
use rand_core::{
    RngCore, CryptoRng,
};
use sha3::{
    Digest, Sha3_256,
};

use crate::util::{
    G, hash_to_scalar,
};

#[allow(non_snake_case)]
pub struct ID {
    pub kG: Point,
    pub kca: Scalar,
}

impl ID {
    pub fn new<RNG: RngCore+CryptoRng>(id: &String, a: &Scalar, rng: &mut RNG) -> Self {
	let k = Scalar::random(rng);
	let mut hasher = Sha3_256::new();

	hasher.update(id.as_bytes());
	hasher.update((k * G).compress().as_bytes());
	hasher.update((a * G).compress().as_bytes());

	let c = hash_to_scalar(&mut hasher);
	
	Self{
	    kG: k * G,
	    kca: k + c * a,
	}
    }
}
