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

#[derive(Clone)]
pub struct Share2 {
    pub i: Scalar,
    pub f_i: Scalar,
}

#[derive(Clone)]
pub struct Party {
    pub id: Scalar,
    pub f: Polynomial<Scalar>,
    pub shares: Vec<Share2>,
    pub secret: Scalar,
}

impl Party {
    pub fn new<RNG: RngCore+CryptoRng>(id: &Scalar, t: usize, rng: &mut RNG) -> Self {
	Self {
	    id: id.clone(),
	    f: VSS::random_poly(t - 1, rng),
	    shares: Vec::new(),
	    secret: Scalar::zero(),
	}
    }

    pub fn share<RNG: RngCore+CryptoRng>(&self, rng: &mut RNG) -> Share {
	Share {
	    id: ID::new(&self.id, &self.f.data()[0], rng),
	    A: (0..self.f.data().len()).map(|i| self.f.data()[i] * G).collect(),
	}
    }

    pub fn send(&mut self, share: Share2) {
	self.shares.push(share);
    }

    pub fn compute_secret(&mut self) {
	for share in &self.shares {
	    self.secret += share.f_i;
	}
    }
}
