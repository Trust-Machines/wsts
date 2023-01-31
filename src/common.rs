use core::ops::Add;
use num_traits::Zero;
use p256k1::{
    point::{Point, G},
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::compute::challenge;
use crate::schnorr::ID;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct PolyCommitment {
    pub id: ID,
    pub A: Vec<Point>,
}

impl PolyCommitment {
    pub fn verify(&self) -> bool {
        self.id.verify(&self.A[0])
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Nonce {
    pub d: Scalar,
    pub e: Scalar,
}

impl Nonce {
    pub fn random<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Self {
        Self {
            d: Scalar::random(rng),
            e: Scalar::random(rng),
        }
    }
}

impl Zero for Nonce {
    fn zero() -> Self {
        Self {
            d: Scalar::zero(),
            e: Scalar::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        self.d == Scalar::zero() && self.e == Scalar::zero()
    }
}

impl Add for Nonce {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            d: self.d + other.d,
            e: self.e + other.e,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct PublicNonce {
    pub D: Point,
    pub E: Point,
}

impl PublicNonce {
    pub fn from(n: &Nonce) -> Self {
        Self {
            D: &n.d * G,
            E: &n.e * G,
        }
    }
}

// TODO: Remove public key from here
// The SA should get that as usual
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignatureShare<T> {
    pub id: usize,
    pub z_i: Scalar,
    pub public_key: T,
}

#[allow(non_snake_case)]
pub struct Signature {
    pub R: Point,
    pub z: Scalar,
}

impl Signature {
    // verify: R' = z * G + -c * publicKey, pass if R' == R
    #[allow(non_snake_case)]
    pub fn verify(&self, public_key: &Point, msg: &[u8]) -> bool {
        let c = challenge(public_key, &self.R, msg);
        let R = &self.z * G + (-c) * public_key;

        R == self.R
    }
}
