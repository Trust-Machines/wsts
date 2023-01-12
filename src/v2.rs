use num_traits::Zero;
use polynomial::Polynomial;
use rand_core::{CryptoRng, RngCore};
use secp256k1_math::{
    point::{Point, G},
    scalar::Scalar,
};
use serde::{Deserialize, Serialize};

use crate::common::{Nonce, PolyCommitment, PublicNonce, Signature};
use crate::compute;
use crate::schnorr::ID;
use crate::vss::VSS;

use hashbrown::{HashMap, HashSet};

pub type PubKeyMap = HashMap<usize, Point>;
pub type PrivKeyMap = HashMap<usize, Scalar>;
pub type SelectedSigners = HashMap<usize, HashSet<usize>>;

// TODO: Remove public key from here
// The SA should get that as usual
#[derive(Debug, Deserialize, Serialize)]
pub struct SignatureShare {
    pub party_id: usize,
    pub z_i: Scalar,
    pub public_keys: HashMap<usize, Point>,
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
    nonce: Nonce,
}

impl Party {
    #[allow(non_snake_case)]
    pub fn new<RNG: RngCore + CryptoRng>(
        party_id: usize,
        key_ids: HashSet<usize>,
        num_parties: usize,
        num_keys: usize,
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

    pub fn gen_nonce<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG) -> PublicNonce {
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
    // signers are party_ids, not key_ids
    pub fn sign(&self, msg: &[u8], signers: &[usize], nonces: &[PublicNonce]) -> SignatureShare {
        let (_R_vec, R) = compute::intermediate(msg, signers, nonces);
        let c = compute::challenge(&self.group_key, &R, &msg);

        let mut z = &self.nonce.d + &self.nonce.e * compute::binding(&self.id(), nonces, msg);
        for key_id in self.key_ids.iter() {
            z += c * &self.private_keys[key_id] * compute::lambda(*key_id, signers);
        }

        SignatureShare {
            party_id: self.party_id,
            z_i: z,
            public_keys: self.public_keys.clone(),
        }
    }
}

#[allow(non_snake_case)]
pub struct SignatureAggregator {
    pub num_keys: usize,
    pub threshold: usize,
    pub group_key: Point, // the group's combined public key
}

impl SignatureAggregator {
    #[allow(non_snake_case)]
    pub fn new(
        num_keys: usize,
        num_parties: usize,
        threshold: usize,
        A: Vec<PolyCommitment>,  // one per party_id
        _public_keys: PubKeyMap, // one per key_id
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

        Self {
            num_keys: num_keys,
            threshold: threshold,
            group_key: key,
        }
    }

    #[allow(non_snake_case)]
    pub fn sign(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
    ) -> Signature {
        let signers: Vec<usize> = sig_shares.iter().map(|ss| ss.party_id).collect();
        let (Ris, R) = compute::intermediate(msg, &signers, nonces);
        let mut z = Scalar::zero();
        let c = compute::challenge(&self.group_key, &R, &msg); // only needed for checking z_i

        for i in 0..sig_shares.len() {
            let z_i = sig_shares[i].z_i;
            assert!(
                z_i * G
                    == Ris[i]
                        + sig_shares
                            .iter()
                            .enumerate()
                            .fold(Point::zero(), |p, (k, share)| p + compute::lambda(
                                share.party_id,
                                &signers
                            ) * c
                                * share.public_keys[&k])
            );
            z += z_i;
        }

        let sig = Signature { R: R, z: z };
        assert!(sig.verify(&self.group_key, msg));
        sig
    }
}

#[cfg(test)]
mod tests {
    use crate::common::{PolyCommitment, PublicNonce};
    use crate::traits::Signer;
    use crate::v2;
    use crate::v2::SignatureShare;

    use hashbrown::HashMap;
    use rand_core::{CryptoRng, OsRng, RngCore};

    #[allow(non_snake_case)]
    fn dkg<RNG: RngCore + CryptoRng>(
        signers: &mut Vec<v2::Party>,
        rng: &mut RNG,
    ) -> Vec<PolyCommitment> {
        let A: Vec<PolyCommitment> = signers.iter().map(|s| s.get_poly_commitment(rng)).collect();

        // each party broadcasts their commitments
        // these hashmaps will need to be serialized in tuples w/ the value encrypted
        // Vec<(party_id, HashMap<key_id, Share>)>
        let mut broadcast_shares = Vec::new();
        for party in signers.iter() {
            broadcast_shares.push((party.party_id, party.get_shares()));
        }

        // each party collects its shares from the broadcasts
        // maybe this should collect into a hashmap first?
        for party in signers.iter_mut() {
            let mut h = HashMap::new();
            for key_id in party.key_ids.clone() {
                let mut g = Vec::new();

                for (id, shares) in &broadcast_shares {
                    g.push((*id, shares[&key_id]));
                }

                h.insert(key_id, g);
            }

            party.compute_secret(h, &A);
        }

        A
    }

    // There might be a slick one-liner for this?
    fn sign<RNG: RngCore + CryptoRng>(
        msg: &[u8],
        signers: &mut [v2::Party],
        rng: &mut RNG,
    ) -> (Vec<PublicNonce>, Vec<SignatureShare>) {
        let party_ids: Vec<usize> = signers.iter().map(|s| s.party_id).collect();
        let nonces: Vec<PublicNonce> = signers.iter_mut().map(|s| s.gen_nonce(rng)).collect();
        let shares = signers
            .iter()
            .map(|s| s.sign(msg, &party_ids, &nonces))
            .collect();

        (nonces, shares)
    }

    #[allow(non_snake_case)]
    #[test]
    fn aggregator_sign() {
        let mut rng = OsRng::default();
        let msg = "It was many and many a year ago".as_bytes();
        let N: usize = 10;
        let T: usize = 7;
        let party_key_ids: Vec<Vec<usize>> = [
            [0, 1, 2].to_vec(),
            [3, 4].to_vec(),
            [5, 6, 7].to_vec(),
            [8, 9].to_vec(),
        ]
        .to_vec();
        let mut signers = party_key_ids
            .iter()
            .enumerate()
            .map(|(pid, pkids)| v2::Party::new(pid, pkids, party_key_ids.len(), N, T, &mut rng))
            .collect();

        let A = dkg(&mut signers, &mut rng);

        // signers [0,1,3] who have T keys
        {
            let mut signers = [signers[0].clone(), signers[1].clone(), signers[3].clone()].to_vec();
            let mut sig_agg = v2::SignatureAggregator::new(N, T, A.clone());

            let (nonces, sig_shares) = sign(&msg, &mut signers, &mut rng);
            let sig = sig_agg.sign(&msg, &nonces, &sig_shares);

            println!("Signature (R,z) = \n({},{})", sig.R, sig.z);
            assert!(sig.verify(&sig_agg.key, &msg));
        }
    }
}
