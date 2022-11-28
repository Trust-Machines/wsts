use rand_core::{CryptoRng, RngCore};
use secp256k1_math::{
    point::{Point, G},
    scalar::Scalar,
};
use sha3::{Digest, Sha3_256};

use crate::util::hash_to_scalar;

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct ID {
    pub id: Scalar,
    pub kG: Point,
    pub kca: Scalar,
}

#[allow(non_snake_case)]
impl ID {
    pub fn new<RNG: RngCore + CryptoRng>(id: &Scalar, a: &Scalar, rng: &mut RNG) -> Self {
        let k = Scalar::random(rng);
        let c = Self::challenge(id, &(&k * &G), &(a * &G));

        Self {
            id: id.clone(),
            kG: &k * G,
            kca: &k + c * a,
        }
    }

    pub fn challenge(id: &Scalar, K: &Point, A: &Point) -> Scalar {
        let mut hasher = Sha3_256::new();

        hasher.update(id.as_bytes());
        hasher.update(K.compress().as_bytes());
        hasher.update(A.compress().as_bytes());

        hash_to_scalar(&mut hasher)
    }

    pub fn verify(&self, A: &Point) -> bool {
        let c = Self::challenge(&self.id, &self.kG, A);
        &self.kca * &G == &self.kG + c * A
    }
}
