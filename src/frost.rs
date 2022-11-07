use secp256k1_math::{
    point::Point, scalar::Scalar,
};
use num_traits::{Zero, One};
use polynomial::Polynomial;
use rand_core::{
    RngCore, CryptoRng,
};
use sha3::{
    Digest, Sha3_256, 
};

use crate::schnorr::ID;
use crate::util::{
    hash_to_scalar,
};
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
pub struct Nonce {
    d: Scalar,
    e: Scalar,
}

#[derive(Clone)]
#[allow(non_snake_case)]
pub struct PublicNonce {
    pub D: Point,
    pub E: Point,
}

impl PublicNonce {
    pub fn from(n: &Nonce) -> Self {
	Self {
	    D: n.d * Point::G(),
	    E: n.e * Point::G(),
	}
    }
}

#[derive(Clone)]
pub struct Party {
    pub id: Scalar,
    pub f: Polynomial<Scalar>,
    pub shares: Vec<Share2>,
    pub secret: Scalar,
    pub nonces: Vec<Nonce>,
}

impl Party {
    pub fn new<RNG: RngCore+CryptoRng>(id: &Scalar, t: usize, rng: &mut RNG) -> Self {
	Self {
	    id: id.clone(),
	    f: VSS::random_poly(t - 1, rng),
	    shares: Vec::new(),
	    secret: Scalar::zero(),
	    nonces: Vec::new(),
	}
    }

    pub fn share<RNG: RngCore+CryptoRng>(&self, rng: &mut RNG) -> Share {
	Share {
	    id: ID::new(&self.id, &self.f.data()[0], rng),
	    A: (0..self.f.data().len()).map(|i| self.f.data()[i] * Point::G()).collect(),
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

    pub fn gen_nonces<RNG: RngCore+CryptoRng>(&mut self, rng: &mut RNG) {
	const N: usize = 16;
	self.nonces = (0..N).map(|_| Nonce {
	    d: Scalar::random(rng),
	    e: Scalar::random(rng),
	}).collect();
    }

    #[allow(dead_code)]
    pub fn pub_nonces(&self) -> Vec<PublicNonce> {
	self.nonces.iter().map(|n| PublicNonce::from(n)).collect()
    }

    #[allow(dead_code)]
    pub fn pub_nonce(&self) -> PublicNonce {
	PublicNonce::from(self.nonces.last().unwrap())
    }

    pub fn get_nonce<RNG: RngCore+CryptoRng>(&mut self, rng: &mut RNG) -> PublicNonce {
	if self.nonces.is_empty() {
	    self.gen_nonces(rng);
	}
	PublicNonce::from(&self.nonces.last().unwrap())
    }

    #[allow(dead_code)]
    pub fn pop_nonce<RNG: RngCore+CryptoRng>(&mut self, rng: &mut RNG) -> PublicNonce {
	if self.nonces.is_empty() {
	    self.gen_nonces(rng);
	}
	PublicNonce::from(&self.nonces.pop().unwrap())
    }

    #[allow(non_snake_case)]
    pub fn get_binding(&self, B: &Vec<PublicNonce>, msg: &String) -> Scalar {
	let mut hasher = Sha3_256::new();

	hasher.update(self.id.as_bytes());
	for b in B {
	    hasher.update(b.D.compress().as_bytes());
	    hasher.update(b.E.compress().as_bytes());
	}
	hasher.update(msg.as_bytes());

	hash_to_scalar(&mut hasher)
    }

    #[allow(non_snake_case)]
    pub fn sign(&self, X: &Point, rho: &Scalar, R: &Point, msg: &String, l: &Scalar) -> Scalar {
	let nonce = self.nonces.last().unwrap();
	let mut z = nonce.d + rho * nonce.e;
	
	let mut hasher = Sha3_256::new();

	hasher.update(X.compress().as_bytes());
	hasher.update(R.compress().as_bytes());
	hasher.update(msg.as_bytes());

	z += hash_to_scalar(&mut hasher) * self.secret * l;

	z
    }

    pub fn lambda(i: Scalar, n: usize) -> Scalar {
	let mut l = Scalar::one();
	
	for jj in 1..n+1 {
	    let j = Scalar::from(jj as u32);
	    if i == j {
		continue;
	    }
	    l *= j / (j - i);
	}
	
	l
    }
}

#[allow(non_snake_case)]
pub struct Signature {
    pub R: Point,
    pub z: Scalar,
}

impl Signature {
    #[allow(non_snake_case)]
    pub fn new<RNG: RngCore+CryptoRng>(X: &Point, msg: &String, parties: &mut Vec<Party>, N: usize, rng: &mut RNG) -> Self {
	let mut B = Vec::new();
	for party in parties.iter_mut() {
	    B.push(party.get_nonce(rng));
	}

	let rho: Vec<Scalar> = parties.iter().map(|p| p.get_binding(&B, &msg)).collect();

	let mut R = Point::zero();
	for i in 0..B.len() {
	    R += B[i].D + rho[i]*B[i].E;
	}

	let mut z = Scalar::zero();
	for (i,party) in parties.iter().enumerate() {
	    let l = Party::lambda(party.id, N);
	    z += party.sign(&X, &rho[i], &R, &msg, &l);
	}

	Self {
	    R: R,
	    z: z,
	}
    }

    // verify: R' = z * G + -c * X, pass if R' == R
    #[allow(non_snake_case)]
    pub fn verify(&self, X: &Point, msg: &String) -> bool {
	let mut hasher = Sha3_256::new();

	hasher.update(X.compress().as_bytes());
	hasher.update(self.R.compress().as_bytes());
	hasher.update(msg.as_bytes());

	let c = hash_to_scalar(&mut hasher);
	let R = self.z * Point::G() + (-c) * X;

	println!("Verification R = {}", R);
	
	R == self.R
    }
}
