use core::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    ops::Add,
};
use hashbrown::HashMap;
use num_traits::{One, Zero};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    compute::challenge,
    curve::{
        point::{Point, G},
        scalar::Scalar,
        traits::MultiMult,
    },
    schnorr::ID,
};

/// A merkle root is a 256 bit hash
pub type MerkleRoot = [u8; 32];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
/// A commitment to a polynonial, with a Schnorr proof of ownership bound to the ID
pub struct PolyCommitment {
    /// The party ID with a schnorr proof
    pub id: ID,
    /// The public polynomial which commits to the secret polynomial
    pub poly: Vec<Point>,
}

impl PolyCommitment {
    /// Verify the wrapped schnorr ID
    pub fn verify(&self) -> bool {
        self.id.verify(&self.poly[0])
    }
}

impl Display for PolyCommitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.id.id)?;
        for p in &self.poly {
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
/// A share of the party signature with related values
pub struct SignatureShare {
    /// The ID of the party
    pub id: u32,
    /// The party signature
    pub z_i: Scalar,
    /// The key IDs of the party
    pub key_ids: Vec<u32>,
}

#[allow(non_snake_case)]
/// An aggregated group signature
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
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
    pub fn gen_signer_ids(n: u32, k: u32) -> Vec<Vec<u32>> {
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

/// An implementation of p256k1's MultiMult trait that allows fast checking of DKG private shares
/// We convert a set of checked polynomial evaluations into a single giant multimult
/// These evaluations take the form of s * G == \Sum{k=0}{T+1}(a_k * x^k) where the a vals are the coeffs of the polys
/// There is 1 share per poly, N polys, and each poly is degree T-1 (so T coeffs)
/// First we evaluate each poly, then we subtract each s * G
pub struct CheckPrivateShares {
    /// number of keys
    n: u32,
    /// threshold, where the degree of each poly is (t-1)
    t: u32,
    /// Powers of x, where x is the receiving key ID
    powers: Vec<Scalar>,
    /// Negated DKG private shares for the receiving key ID, indexed by sending key ID
    pub neg_shares: HashMap<u32, Scalar>,
    /// Polynomial commitments for each key ID
    polys: HashMap<u32, PolyCommitment>,
}

impl CheckPrivateShares {
    /// Construct a new CheckPrivateShares object
    pub fn new(
        id: Scalar,
        shares: &HashMap<u32, Scalar>,
        polys: HashMap<u32, PolyCommitment>,
    ) -> Self {
        let mut l: usize = 0;
        for (_id, comm) in &polys {
            l = comm.poly.len();
            break;
        }
        let n: u32 = shares.len().try_into().unwrap();
        let t: u32 = l.try_into().unwrap();
        let x = id;
        let mut powers = Vec::with_capacity(l);
        let mut pow = Scalar::one();

        for _ in 0..t {
            powers.push(pow);
            pow *= &x;
        }

        let mut neg_shares = HashMap::with_capacity(polys.len());
        for (i, s) in shares.iter() {
            neg_shares.insert(*i, -s);
        }

        Self {
            n,
            t,
            powers,
            neg_shares,
            polys,
        }
    }
}

impl MultiMult for CheckPrivateShares {
    /// The first n*t scalars will be powers, the last n will be the negation of shares
    fn get_scalar(&self, i: usize) -> &Scalar {
        println!("get_scalar({})", i);
        let h: u32 = i.try_into().unwrap();
        let u: usize = self.t.try_into().unwrap();
        if h < self.n * self.t {
            &self.powers[i % u]
        } else {
            &self.neg_shares[&(h - (self.t * self.n) + 1)]
        }
    }

    /// The first n*t points will be poly coeffs, the last n will be G
    fn get_point(&self, i: usize) -> &Point {
        println!("get_point({})", i);
        let h: u32 = i.try_into().unwrap();
        let u: usize = self.t.try_into().unwrap();
        if h < self.n * self.t {
            let j = i / u;
            let k = i % u;

            &self.polys[&((j + 1) as u32)].poly[k]
        } else {
            &G
        }
    }

    fn get_size(&self) -> usize {
        ((self.t + 1) * self.n).try_into().unwrap()
    }
}
