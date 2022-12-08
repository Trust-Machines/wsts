use num_traits::{One, Zero};
use polynomial::Polynomial;
use rand_core::{CryptoRng, RngCore};
use secp256k1_math::{
    point::{Point, G},
    scalar::Scalar,
};
use sha3::{Digest, Sha3_256};

use crate::schnorr::ID;
use crate::util::hash_to_scalar;
use crate::vss::VSS;

use hashbrown::HashMap;

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
            D: &n.d * G,
            E: &n.e * G,
        }
    }
}

// TODO: Remove public key from here
// The SA should get that as usual
pub struct SignatureShare {
    pub id: usize,
    pub z_i: Scalar,
    pub public_key: Point,
}

#[allow(non_snake_case)]
fn compute_binding(id: &Scalar, B: &Vec<PublicNonce>, msg: &String) -> Scalar {
    let mut hasher = Sha3_256::new();

    hasher.update(id.as_bytes());
    for b in B {
        hasher.update(b.D.compress().as_bytes());
        hasher.update(b.E.compress().as_bytes());
    }
    hasher.update(msg.as_bytes());

    hash_to_scalar(&mut hasher)
}

#[allow(non_snake_case)]
fn compute_challenge(publicKey: &Point, R: &Point, msg: &String) -> Scalar {
    let mut hasher = Sha3_256::new();

    hasher.update(publicKey.compress().as_bytes());
    hasher.update(R.compress().as_bytes());
    hasher.update(msg.as_bytes());

    hash_to_scalar(&mut hasher)
}

fn lambda(i: &usize, indices: &Vec<usize>) -> Scalar {
    let mut lambda = Scalar::one();
    let i_scalar = Scalar::from((i + 1) as u32);
    for j in indices {
        if i != j {
            let j_scalar = Scalar::from((j + 1) as u32);
            lambda *= j_scalar / (j_scalar - i_scalar);
        }
    }
    lambda
}

// Is this the best way to return these values?
// TODO: this fn needs a better name
#[allow(non_snake_case)]
fn get_B_rho_R_vec(
    signers: &Vec<usize>,
    B: &Vec<Vec<PublicNonce>>,
    index: usize,
    msg: &String,
) -> (Vec<PublicNonce>, Vec<Point>, Point) {
    let B = signers.iter().map(|&i| B[i][index].clone()).collect();
    let rho: Vec<Scalar> = signers
        .iter()
        .map(|&i| compute_binding(&Scalar::from((i + 1) as u32), &B, &msg))
        .collect();
    let R_vec: Vec<Point> = (0..B.len()).map(|i| &B[i].D + &rho[i] * &B[i].E).collect();
    let R = R_vec.iter().fold(Point::zero(), |R, &R_i| R + R_i);
    (B, R_vec, R)
}

#[derive(Clone)]
#[allow(non_snake_case)]
pub struct Party {
    pub id: usize,
    pub public_key: Point,
    n: usize,
    _t: usize,
    f: Polynomial<Scalar>,
    //shares: HashMap<usize, Scalar>, // received from other parties
    private_key: Scalar,
    group_key: Point,
    nonces: Vec<Nonce>,
    B: Vec<Vec<PublicNonce>>, // received from other parties
}

impl Party {
    #[allow(non_snake_case)]
    pub fn new<RNG: RngCore + CryptoRng>(id: usize, n: usize, t: usize, rng: &mut RNG) -> Self {
        Self {
            id: id,
            n: n,
            _t: t,
            f: VSS::random_poly(t - 1, rng),
            private_key: Scalar::zero(),
            public_key: Point::zero(),
            group_key: Point::zero(),
            nonces: Vec::new(),
            B: Vec::new(),
        }
    }

    pub fn gen_nonces<RNG: RngCore + CryptoRng>(
        &mut self,
        num_nonces: u32,
        rng: &mut RNG,
    ) -> Vec<PublicNonce> {
        self.nonces = (0..num_nonces)
            .map(|_| Nonce {
                d: Scalar::random(rng),
                e: Scalar::random(rng),
            })
            .collect();
        self.nonces.iter().map(|n| PublicNonce::from(n)).collect()
    }

    #[allow(non_snake_case)]
    pub fn set_group_nonces(&mut self, B: Vec<Vec<PublicNonce>>) {
        self.B = B;
    }

    #[allow(non_snake_case)]
    pub fn get_poly_commitment<RNG: RngCore + CryptoRng>(&self, rng: &mut RNG) -> PolyCommitment {
        PolyCommitment {
            id: ID::new(&self.id(), &self.f.data()[0], rng),
            A: (0..self.f.data().len())
                .map(|i| &self.f.data()[i] * G)
                .collect(),
        }
    }

    pub fn get_shares(&self) -> HashMap<usize, Scalar> {
        let mut shares = HashMap::new();
        for i in 0..self.n as usize {
            shares.insert(i, self.f.eval(Scalar::from((i + 1) as u32)));
        }
        shares
    }

    // TODO: Maybe this should be private? If receive_share is keeping track
    // of which it receives, then this could be called when it has N shares from unique ids
    #[allow(non_snake_case)]
    pub fn compute_secret(&mut self, shares: HashMap<usize, Scalar>, A: &Vec<PolyCommitment>) {
        // TODO: return error with a list of missing shares
        assert!(shares.len() == self.n);
        self.private_key = Scalar::zero();
        for (i, s) in shares.iter() {
            let Ai = &A[*i];
            assert!(Ai.verify()); // checks a0 proof
            assert!(
                s * G
                    == (0..Ai.A.len()).fold(Point::zero(), |s, j| s
                        + (Scalar::from((self.id + 1) as u32) ^ j) * Ai.A[j])
            );
            self.private_key += s;
            self.group_key += Ai.A[0].clone();
        }
        self.public_key = self.private_key * G;
        println!("Party {} secret {}", self.id, self.private_key);
    }

    fn id(&self) -> Scalar {
        Scalar::from((self.id + 1) as u32)
    }

    #[allow(non_snake_case)]
    pub fn sign(&self, msg: &String, signers: &Vec<usize>, nonce_index: usize) -> Scalar {
        let (B, _R_vec, R) = get_B_rho_R_vec(&signers, &self.B, nonce_index, &msg);
        let nonce = &self.nonces[nonce_index]; // TODO: needs to check that index exists
        let mut z = &nonce.d + &nonce.e * compute_binding(&self.id(), &B, &msg);
        z += compute_challenge(&self.group_key, &R, &msg)
            * &self.private_key
            * lambda(&self.id, signers);
        z
    }
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
        let c = compute_challenge(&public_key, &self.R, &msg);
        let R = &self.z * G + (-c) * public_key;

        println!("Verification R = {}", R);

        R == self.R
    }
}

#[allow(non_snake_case)]
pub struct SignatureAggregator {
    pub N: usize,
    pub T: usize,
    pub A: Vec<PolyCommitment>, // outer vector is N-long, inner vector is T-long
    pub B: Vec<Vec<PublicNonce>>, // outer vector is N-long, inner vector is T-long
    pub key: Point,
    nonce_ctr: usize,
    num_nonces: usize,
}

impl SignatureAggregator {
    #[allow(non_snake_case)]
    pub fn new(N: usize, T: usize, A: Vec<PolyCommitment>, B: Vec<Vec<PublicNonce>>) -> Self {
        // TODO: How should we handle bad As?
        assert!(A.len() == N);
        for A_i in &A {
            assert!(A_i.verify());
        }

        let mut key = Point::new(); // TODO: Compute pub key from A
        for A_i in &A {
            key += &A_i.A[0];
        }
        println!("SA groupKey {}", key);

        assert!(B.len() == N);
        let num_nonces = B[0].len();
        for b in &B {
            assert!(num_nonces == b.len());
        }
        // TODO: Check that each B_i is len num_nonces?

        Self {
            N: N,
            T: T,
            A: A,
            B: B,
            key: key,
            nonce_ctr: 0,
            num_nonces: num_nonces,
        }
    }

    #[allow(non_snake_case)]
    pub fn sign(
        &mut self,
        msg: &String,
        sig_shares: &Vec<SignatureShare>,
        signers: &Vec<usize>,
    ) -> Signature {
        let (_B, R_vec, R) = get_B_rho_R_vec(&signers, &self.B, self.nonce_ctr, &msg);

        let mut z = Scalar::zero();
        let c = compute_challenge(&self.key, &R, &msg); // only needed for checking z_i
        for i in 0..signers.len() {
            let z_i = sig_shares[i].z_i;
            assert!(
                z_i * G
                    == R_vec[i]
                        + (lambda(&sig_shares[i].id, signers) * c * sig_shares[i].public_key)
            ); // TODO: This should return a list of bad parties.
            z += z_i;
        }
        self.update_nonce();

        Signature { R: R, z: z }
    }

    pub fn get_nonce_ctr(&self) -> usize {
        self.nonce_ctr
    }

    fn update_nonce(&mut self) {
        self.nonce_ctr += 1;
        if self.nonce_ctr == self.num_nonces {
            println!("Out of nonces! Need to generate new ones!");
            // TODO: Trigger another round of nonces generation & sharing B
            self.nonce_ctr = 0;
        }
    }
}
