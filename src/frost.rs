use curve25519_dalek::{
    ristretto::RistrettoPoint as Point, scalar::Scalar,
};
use polynomial::Polynomial;
use rand_core::{
    RngCore, CryptoRng,
};

use crate::schnorr::ID;
use crate::util::G;
use crate::vss::VSS;

#[allow(non_snake_case)]
pub struct Share {
    pub id: ID,
    pub A: Vec<Point>,
}

impl Share {
    pub fn verify(&self) -> bool {
	self.id.verify(&self.A[0])
    }
}

pub struct Party {
    pub id: String,
    pub poly: Polynomial<Scalar>,
}

impl Party {
    pub fn new<RNG: RngCore+CryptoRng>(id: &String, t: usize, rng: &mut RNG) -> Self {
	Self {
	    id: id.clone(),
	    poly: VSS::random_poly(t - 1, rng),
	}
    }

    pub fn share<RNG: RngCore+CryptoRng>(&self, rng: &mut RNG) -> Share {
	Share {
	    id: ID::new(&self.id, &self.poly.data()[0], rng),
	    A: (0..self.poly.data().len()).map(|i| self.poly.data()[i] * G).collect(),
	}
    }
}
