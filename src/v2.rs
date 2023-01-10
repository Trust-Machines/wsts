use num_traits::Zero;
use polynomial::Polynomial;
use rand_core::{CryptoRng, RngCore};
use secp256k1_math::{
    point::{Point, G},
    scalar::Scalar,
};

use crate::common::{Nonce, PolyCommitment, PublicNonce, Signature, SignatureShare};
use crate::compute;
use crate::schnorr::ID;
use crate::vss::VSS;

use hashbrown::{HashMap, HashSet};

pub type PubKeyMap = HashMap<usize, Point>;
pub type PrivKeyMap = HashMap<usize, Scalar>;
pub type SelectedSigners = HashMap<usize, HashSet<usize>>;

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
    nonce: Nonce,
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
            nonce: Nonce::zero(),
        }
    }

    pub fn gen_nonce<RNG: RngCore + CryptoRng>(
        &mut self,
        rng: &mut RNG,
    ) -> PublicNonce {
        self.nonce = Nonce::random(rng);

        PublicNonce::from(&self.nonce)
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
        for i in 0..self.num_keys as usize {
            shares.insert(i, self.f.eval(compute::id(i)));
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
                            + (compute::id(*key_id) ^ j) * Ai.A[j])
                );
                self.private_keys
                    .insert(*key_id, self.private_keys[key_id] + s);
            }
            self.public_keys
                .insert(*key_id, self.private_keys[key_id] * G);
            println!(
                "Party {} key_id {} secret {}",
                self.party_id, key_id, self.private_keys[key_id]
            );
        }

        &self.public_keys
    }

    pub fn id(&self) -> Scalar {
        compute::id(self.party_id)
    }


    #[allow(non_snake_case)]
    pub fn sign(&self, msg: &[u8], signers: &[usize], nonces: &[PublicNonce]) -> Scalar {
        let (_R_vec, R) = compute::intermediate(msg, signers, nonces);
        let c = compute::challenge(&self.group_key, &R, &msg);

        let mut z = &nonce.d + &nonce.e * compute_binding(&id_to_scalar(&self.party_id), &B, &msg);
        for key_id in signers[&self.party_id].iter() {
            z += c * &self.private_keys[key_id] * lambda(&key_id, signers);
        }
        z
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
        nonces: &[PublicNonce], // for now duplicate for each key a party has
        sig_shares: &[SignatureShare],
    ) -> Signature {
        let signers: Vec<usize> = sig_shares.iter().map(|ss| ss.id).collect();
        let (Ris, R) = compute::intermediate(msg, &signers, nonces);

        let mut z = Scalar::zero();
        let c = compute::challenge(&self.group_key, &R, &msg); // only needed for checking z_i
        for i in sig_shares.len() {
            assert!(
                let z_i = sig_shares[i].z_i;
                z_i * G
                    == Ris[&sig.party_id]
                        + signers[&sig.party_id]
                            .iter()
                            .fold(Point::zero(), |p, k| p + compute::lambda(&k, signers)
                                * c
                                * self.public_keys[k])
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
