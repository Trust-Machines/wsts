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
#[derive(Clone)]
pub struct ID {
    pub id: String,
    pub kG: Point,
    pub kca: Scalar,
}

#[allow(non_snake_case)]
impl ID {
    pub fn new<RNG: RngCore+CryptoRng>(id: &String, a: &Scalar, rng: &mut RNG) -> Self {
	let k = Scalar::random(rng);
	let c = Self::challenge(id, &(k * G), &(a * G));

	Self{
	    id: id.to_string(),
	    kG: k * G,
	    kca: k + c * a,
	}
    }

    pub fn challenge(id: &String, K: &Point, A: &Point) -> Scalar {
	let mut hasher = Sha3_256::new();

	hasher.update(id.as_bytes());
	hasher.update(K.compress().as_bytes());
	hasher.update(A.compress().as_bytes());

	hash_to_scalar(&mut hasher)
    }
    
    pub fn verify(&self, A: &Point) -> bool {
	let c = Self::challenge(&self.id, &self.kG, A);
	self.kca * G == self.kG + c * A
    }
}
