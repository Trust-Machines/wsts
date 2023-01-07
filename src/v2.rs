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

use hashbrown::{HashMap, HashSet};

pub type PubKeyMap = HashMap<usize, Point>;
pub type PrivKeyMap = HashMap<usize, Scalar>;
pub type SelectedSigners = HashMap<usize, HashSet<usize>>;

#[allow(non_snake_case)]
pub struct PolyCommitment {
    pub party_id: ID,
    pub A: Vec<Point>,
}

impl PolyCommitment {
    pub fn verify(&self) -> bool {
        self.party_id.verify(&self.A[0])
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

// The SA should get that as usual
pub struct SignatureShare {
    pub party_id: usize,
    pub z_i: Scalar,
}

#[allow(non_snake_case)]
fn compute_binding(party_id: &Scalar, B: &Vec<PublicNonce>, msg: &[u8]) -> Scalar {
    let mut hasher = Sha3_256::new();

    hasher.update(party_id.as_bytes());
    for b in B {
        hasher.update(b.D.compress().as_bytes());
        hasher.update(b.E.compress().as_bytes());
    }
    hasher.update(msg);

    hash_to_scalar(&mut hasher)
}

#[allow(non_snake_case)]
fn compute_challenge(publicKey: &Point, R: &Point, msg: &[u8]) -> Scalar {
    let mut hasher = Sha3_256::new();

    hasher.update(publicKey.compress().as_bytes());
    hasher.update(R.compress().as_bytes());
    hasher.update(msg);

    hash_to_scalar(&mut hasher)
}

fn lambda(i: &usize, signers: &SelectedSigners) -> Scalar {
    let mut lambda = Scalar::one();
    let i_scalar = id_to_scalar(i);
    for (_, h) in signers {
        for j in h {
            if i != j {
                let j_scalar = id_to_scalar(j);
                lambda *= j_scalar / (j_scalar - i_scalar);
            }
        }
    }
    lambda
}

// Is this the best way to return these values?
// TODO: this fn needs a better name
#[allow(non_snake_case)]
fn compute_intermediate_values(
    signers: &SelectedSigners, // only the keys are needed
    B: &Vec<Vec<PublicNonce>>,
    index: usize,
    msg: &[u8],
) -> (Vec<PublicNonce>, HashMap<usize, Point>, Point) {
    let mut signer_vec = Vec::from_iter(signers.keys());
    signer_vec.sort();
    let B = signer_vec
        .iter()
        .map(|&party_id| B[*party_id][index].clone())
        .collect();
    let rho: Vec<Scalar> = signer_vec
        .iter()
        .map(|&party_id| compute_binding(&id_to_scalar(&party_id), &B, &msg))
        .collect();

    let mut Ris = HashMap::new();
    for i in 0..signer_vec.len() {
        Ris.insert(*signer_vec[i], &B[i].D + &rho[i] * &B[i].E);
    }
    let R = Ris.values().fold(Point::zero(), |R, R_i| R + R_i);
    (B, Ris, R)
}

fn id_to_scalar(id: &usize) -> Scalar {
    Scalar::from((id + 1) as u32)
}

#[derive(Clone)]
#[allow(non_snake_case)]
pub struct Party {
    pub party_id: usize,
    pub key_ids: HashSet<usize>,
    pub public_keys: PubKeyMap, // key is key_id
    num_keys: usize,
    num_parties: usize,
    f: Polynomial<Scalar>, // one poly per party to simulate the sum of all their polys
    private_keys: PrivKeyMap, // key is key_id
    group_key: Point,
    nonces: Vec<Nonce>,
    B: Vec<Vec<PublicNonce>>, // received from other parties
}

impl Party {
    #[allow(non_snake_case)]
    pub fn new<RNG: RngCore + CryptoRng>(
        party_id: usize,
        key_ids: HashSet<usize>,
        num_keys: usize,
        num_parties: usize,
        threshold: usize,
        rng: &mut RNG,
    ) -> Self {
        Self {
            party_id: party_id,
            key_ids: key_ids,
            num_keys: num_keys,
            num_parties: num_parties,
            f: VSS::random_poly(threshold - 1, rng),
            private_keys: PrivKeyMap::new(),
            public_keys: PubKeyMap::new(),
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

    // Warning: This function assumes that B already exists - it's just for resetting
    #[allow(non_snake_case)]
    pub fn set_party_nonces(&mut self, party_id: usize, B: Vec<PublicNonce>) {
        self.B[party_id] = B;
    }

    #[allow(non_snake_case)]
    pub fn get_poly_commitment<RNG: RngCore + CryptoRng>(&self, rng: &mut RNG) -> PolyCommitment {
        PolyCommitment {
            party_id: ID::new(&id_to_scalar(&self.party_id), &self.f.data()[0], rng),
            A: (0..self.f.data().len())
                .map(|i| &self.f.data()[i] * G)
                .collect(),
        }
    }

    pub fn get_shares(&self) -> Vec<(usize, Scalar)> {
        let mut shares = Vec::new();
        for i in 0..self.num_keys as usize {
            shares.push((i, self.f.eval(id_to_scalar(&i))));
        }
        shares
    }

    // TODO: Maybe this should be private? If receive_share is keeping track
    // of which it receives, then this could be called when it has N shares from unique ids
    #[allow(non_snake_case)]
    pub fn compute_secret(
        &mut self,
        shares: HashMap<usize, Vec<(usize, Scalar)>>,
        A: &[PolyCommitment],
    ) -> &PubKeyMap {
        // TODO: return error with a list of missing shares
        assert!(shares.len() == self.key_ids.len());

        for Ai in A {
            assert!(Ai.verify()); // checks a0 proof
            self.group_key += Ai.A[0].clone();
        }

        for key_id in &self.key_ids {
            assert!(shares[key_id].len() == self.num_parties);
            self.private_keys.insert(*key_id, Scalar::zero());

            for (sender, s) in &shares[key_id] {
                let Ai = &A[*sender];
                assert!(
                    s * G
                        == (0..Ai.A.len()).fold(Point::zero(), |s, j| s
                            + (id_to_scalar(key_id) ^ j) * Ai.A[j])
                );
                self.private_keys
                    .insert(*key_id, self.private_keys[key_id] + s);
            }
            self.public_keys
                .insert(*key_id, self.private_keys[key_id] * G);
            println!(
                "Party {} key_id {} secret {}",
                self.party_id, key_id, self.private_keys[&key_id]
            );
        }

        &self.public_keys
    }

    #[allow(non_snake_case)]
    pub fn sign(&self, msg: &[u8], signers: &SelectedSigners, nonce_index: usize) -> Scalar {
        let (B, _R_vec, R) = compute_intermediate_values(&signers, &self.B, nonce_index, &msg);
        let c = compute_challenge(&self.group_key, &R, &msg);
        let nonce = &self.nonces[nonce_index]; // TODO: needs to check that index exists

        let mut z = &nonce.d + &nonce.e * compute_binding(&id_to_scalar(&self.party_id), &B, &msg);
        for key_id in signers[&self.party_id].iter() {
            z += c * &self.private_keys[&key_id] * lambda(&key_id, signers);
        }
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
    pub fn verify(&self, public_key: &Point, msg: &[u8]) -> bool {
        let c = compute_challenge(&public_key, &self.R, &msg);
        let R = &self.z * G + (-c) * public_key;

        println!("Verification R = {}", R);

        R == self.R
    }
}

#[allow(non_snake_case)]
pub struct SignatureAggregator {
    pub num_keys: usize,
    pub num_parties: usize,
    pub threshold: usize,
    pub A: Vec<PolyCommitment>, // outer vector is N-long, inner vector is T-long
    pub B: Vec<Vec<PublicNonce>>, // outer vector is N-long, inner vector is T-long
    pub group_key: Point,       // the group's combined public key
    pub public_keys: PubKeyMap, // the public key for each point
    nonce_ctr: usize,
    num_nonces: usize,
}

impl SignatureAggregator {
    #[allow(non_snake_case)]
    pub fn new(
        num_keys: usize,
        num_parties: usize,
        threshold: usize,
        A: Vec<PolyCommitment>,
        B: Vec<Vec<PublicNonce>>,
        public_keys: PubKeyMap,
    ) -> Self {
        assert!(A.len() == num_parties);
        for A_i in &A {
            assert!(A_i.verify());
        }

        let mut key = Point::new(); // TODO: Compute pub key from A
        for A_i in &A {
            key += &A_i.A[0];
        }
        println!("SA groupKey {}", key);

        assert!(B.len() == num_parties);
        let num_nonces = B[0].len();
        for b in &B {
            assert!(num_nonces == b.len());
        }

        Self {
            num_keys: num_keys,
            num_parties: num_parties,
            threshold: threshold,
            A: A,
            B: B,
            group_key: key,
            public_keys: public_keys,
            nonce_ctr: 0,
            num_nonces: num_nonces,
        }
    }

    #[allow(non_snake_case)]
    pub fn sign(
        &mut self,
        msg: &[u8],
        sig_shares: &[SignatureShare], // one per party and each contains vectors for all their pts
        signers: &SelectedSigners,     // the list of party_ids
    ) -> Signature {
        let (_B, Ris, R) = compute_intermediate_values(&signers, &self.B, self.nonce_ctr, &msg);

        let mut z = Scalar::zero();
        let c = compute_challenge(&self.group_key, &R, &msg); // only needed for checking z_i
        for sig in sig_shares {
            assert!(
                sig.z_i * G
                    == Ris[&sig.party_id]
                        + signers[&sig.party_id]
                            .iter()
                            .fold(Point::zero(), |p, k| p + lambda(&k, signers)
                                * c
                                * self.public_keys[&k])
            );
            z += sig.z_i;
        }
        self.update_nonce();

        let sig = Signature { R: R, z: z };
        assert!(sig.verify(&self.group_key, msg));
        sig
    }

    pub fn get_nonce_ctr(&self) -> usize {
        self.nonce_ctr
    }

    fn update_nonce(&mut self) {
        self.nonce_ctr += 1;
        if self.nonce_ctr == self.num_nonces {
            // TODO: Should this kick off the re-generation process?
            println!("This is the last available nonce! Need to generate more!");
        }
    }

    #[allow(non_snake_case)]
    pub fn set_party_nonces(&mut self, i: usize, B: Vec<PublicNonce>) {
        self.B[i] = B;
    }

    #[allow(non_snake_case)]
    pub fn set_group_nonces(&mut self, B: Vec<Vec<PublicNonce>>) {
        self.B = B;
        self.nonce_ctr = 0;
        self.num_nonces = self.B.len();
    }
}
