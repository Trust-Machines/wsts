use secp256k1_math::{
    point::{Point, G},
    scalar::Scalar,
};
use serde::{Deserialize, Serialize};

use crate::compute::challenge;
use crate::schnorr::ID;

#[derive(Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Nonce {
    pub d: Scalar,
    pub e: Scalar,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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
#[derive(Deserialize, Serialize)]
pub struct SignatureShare {
    pub id: usize,
    pub z_i: Scalar,
    pub public_key: Point,
}

#[allow(non_snake_case)]
pub struct Signature {
    pub R: Point,
    pub z: Scalar,
}

impl Signature {
    // verify: R' = z * G + -c * publicKey, pass if R' == R
    #[allow(non_snake_case)]
    pub fn verify(&self, public_key: &Point, msg: &String) -> bool {
        let c = challenge(&public_key, &self.R, &msg);
        let R = &self.z * G + (-c) * public_key;

        println!("Verification R = {}", R);

        R == self.R
    }
}
