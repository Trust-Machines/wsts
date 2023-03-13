use core::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    ops::Add,
};
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
/// A commitment to a polynonial, with a Schnorr proof of ownership bound to the ID
pub struct PolyCommitment {
    /// The party ID with a schnorr proof
    pub id: ID,
    /// The public polynomial which commits to the secret polynomial
    pub A: Vec<Point>,
}

impl PolyCommitment {
    /// Verify the wrapped schnorr ID
    pub fn verify(&self) -> bool {
        self.id.verify(&self.A[0])
    }
}

impl Display for PolyCommitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.id.id)?;
        for p in &self.A {
            write!(f, " {}", p)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
/// A composite private nonce used as a random commitment in the protocol
pub struct Nonce {
    /// The first committed value
    pub d: Scalar,
    /// The second committed value
    pub e: Scalar,
}

impl Nonce {
    /// Construct a random nonce
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
/// A commitment to the private nonce
pub struct PublicNonce {
    /// A commitment to the private nonce's first value
    pub D: Point,
    /// A commitment to the private nonce's second value
    pub E: Point,
}

impl PublicNonce {
    /// Construct a public nonce from a private nonce
    pub fn from(n: &Nonce) -> Self {
        Self {
            D: &n.d * G,
            E: &n.e * G,
        }
    }
}

impl Display for PublicNonce {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{} {}", &self.D, &self.E)
    }
}

// TODO: Remove public key from here
// The SA should get that as usual
#[derive(Clone, Debug, Deserialize, Serialize)]
/// A share of the party signature with related values
pub struct SignatureShare<T> {
    /// The ID of the party
    pub id: usize,
    /// The party signature
    pub z_i: Scalar,
    /// The party's public key
    pub public_key: T,
}

#[allow(non_snake_case)]
/// An aggregated group signature
pub struct Signature {
    /// The sum of the public nonces with commitments to the signed message
    pub R: Point,
    /// The sum of the party signatures
    pub z: Scalar,
}

impl Signature {
    #[allow(non_snake_case)]
    /// Verify the aggregated group signature
    pub fn verify(&self, public_key: &Point, msg: &[u8]) -> bool {
        let c = challenge(public_key, &self.R, msg);
        let R = &self.z * G + (-c) * public_key;

        R == self.R
    }
}

/// Helper functions for tests
pub mod test_helpers {
    /// Generate a set of `k` vectors which divide `n` IDs evenly
    pub fn gen_signer_ids(n: usize, k: usize) -> Vec<Vec<usize>> {
        let mut ids = Vec::new();
        let m = n / k;

        for i in 0..k {
            let mut pids = Vec::new();
            for j in 0..m {
                pids.push(i * m + j);
            }
            ids.push(pids);
        }

        ids
    }
}
