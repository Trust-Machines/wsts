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
use crate::errors::{AggregatorError, DkgError};
use crate::schnorr::ID;
use crate::vss::VSS;

use hashbrown::{HashMap, HashSet};

pub type PubKeyMap = HashMap<usize, Point>;
pub type PrivKeyMap = HashMap<usize, Scalar>;
pub type SelectedSigners = HashMap<usize, HashSet<usize>>;
pub type SignatureShare = crate::common::SignatureShare<PubKeyMap>;

#[derive(Serialize, Deserialize)]
pub struct PartyState {
    pub party_id: usize,
    pub key_ids: Vec<usize>,
    pub public_keys: PubKeyMap,
    pub num_keys: usize,
    pub num_parties: usize,
    pub polynomial: Polynomial<Scalar>,
    pub private_keys: PrivKeyMap,
    pub group_key: Point,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(non_snake_case)]
pub struct Party {
    pub party_id: usize,
    pub key_ids: Vec<usize>,
    pub public_keys: PubKeyMap, // key is key_id
    num_keys: usize,
    num_parties: usize,
    f: Polynomial<Scalar>,    // one poly per party
    private_keys: PrivKeyMap, // key is key_id
    group_key: Point,
    nonce: Nonce,
}

impl Party {
    #[allow(non_snake_case)]
    pub fn new<RNG: RngCore + CryptoRng>(
        party_id: usize,
        key_ids: &[usize],
        num_parties: usize,
        num_keys: usize,
        threshold: usize,
        rng: &mut RNG,
    ) -> Self {
        Self {
            party_id,
            key_ids: key_ids.to_vec(),
            num_keys,
            num_parties,
            f: VSS::random_poly(threshold - 1, rng),
            private_keys: PrivKeyMap::new(),
            public_keys: PubKeyMap::new(),
            group_key: Point::zero(),
            nonce: Nonce::zero(),
        }
    }

    pub fn load(state: &PartyState) -> Self {
        Self {
            party_id: state.party_id,
            key_ids: state.key_ids.clone(),
            num_keys: state.num_keys,
            num_parties: state.num_parties,
            f: state.polynomial.clone(),
            private_keys: state.private_keys.clone(),
            public_keys: state.public_keys.clone(),
            group_key: state.group_key,
            nonce: Nonce::zero(),
        }
    }

    pub fn save(&self) -> PartyState {
        PartyState {
            party_id: self.party_id,
            key_ids: self.key_ids.clone(),
            num_keys: self.num_keys,
            num_parties: self.num_parties,
            polynomial: self.f.clone(),
            private_keys: self.private_keys.clone(),
            public_keys: self.public_keys.clone(),
            group_key: self.group_key,
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
        for i in 0..self.num_keys {
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
    ) -> Result<&PubKeyMap, DkgError> {
        let mut missing_shares = Vec::new();
        for key_id in &self.key_ids {
            if shares.get(key_id).is_none() {
                missing_shares.push(*key_id);
            }
        }
        if !missing_shares.is_empty() {
            return Err(DkgError::MissingShares(missing_shares));
        }

        let mut bad_ids = Vec::new();
        for (i, Ai) in A.iter().enumerate() {
            if !Ai.verify() {
                bad_ids.push(i);
            }
            self.group_key += Ai.A[0];
        }
        if !bad_ids.is_empty() {
            return Err(DkgError::BadIds(bad_ids));
        }

        let mut not_enough_shares = Vec::new();
        for key_id in &self.key_ids {
            if shares[key_id].len() != self.num_parties {
                not_enough_shares.push(*key_id);
            }
        }
        if !not_enough_shares.is_empty() {
            return Err(DkgError::NotEnoughShares(not_enough_shares));
        }

        let mut bad_shares = Vec::new();
        for key_id in &self.key_ids {
            for (sender, s) in &shares[key_id] {
                let Ai = &A[*sender];
                if s * G
                    != (0..Ai.A.len()).fold(Point::zero(), |s, j| {
                        s + (compute::id(*key_id) ^ j) * Ai.A[j]
                    })
                {
                    bad_shares.push(*sender);
                }
            }
        }
        if !bad_shares.is_empty() {
            return Err(DkgError::BadShares(bad_shares));
        }

        for key_id in &self.key_ids {
            self.private_keys.insert(*key_id, Scalar::zero());

            for (_sender, s) in &shares[key_id] {
                self.private_keys
                    .insert(*key_id, self.private_keys[key_id] + s);
            }
            self.public_keys
                .insert(*key_id, self.private_keys[key_id] * G);
        }

        Ok(&self.public_keys)
    }

    pub fn id(&self) -> Scalar {
        compute::id(self.party_id)
    }

    #[allow(non_snake_case)]
    pub fn sign(
        &self,
        msg: &[u8],
        party_ids: &[usize],
        key_ids: &[usize],
        nonces: &[PublicNonce],
    ) -> SignatureShare {
        let (_R_vec, R) = compute::intermediate(msg, party_ids, nonces);
        let c = compute::challenge(&self.group_key, &R, msg);

        let mut z = &self.nonce.d + &self.nonce.e * compute::binding(&self.id(), nonces, msg);
        for key_id in self.key_ids.iter() {
            z += c * &self.private_keys[key_id] * compute::lambda(*key_id, key_ids);
        }

        SignatureShare {
            id: self.party_id,
            z_i: z,
            public_key: self.public_keys.clone(),
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
        threshold: usize,
        A: Vec<PolyCommitment>, // one per party_id
    ) -> Result<Self, AggregatorError> {
        let mut bad_poly_commitments = Vec::new();
        for A_i in &A {
            if !A_i.verify() {
                bad_poly_commitments.push(A_i.id.id);
            }
        }
        if !bad_poly_commitments.is_empty() {
            return Err(AggregatorError::BadPolyCommitments(bad_poly_commitments));
        }

        let mut group_key = Point::zero(); // TODO: Compute pub key from A
        for A_i in &A {
            group_key += &A_i.A[0];
        }
        //println!("SA groupKey {}", group_key);

        Ok(Self {
            num_keys,
            threshold,
            group_key,
        })
    }

    #[allow(non_snake_case)]
    pub fn sign(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[usize],
    ) -> Result<Signature, AggregatorError> {
        if nonces.len() != sig_shares.len() {
            return Err(AggregatorError::BadNonceLen(nonces.len(), sig_shares.len()));
        }

        let party_ids: Vec<usize> = sig_shares.iter().map(|ss| ss.id).collect();
        let (Ris, R) = compute::intermediate(msg, &party_ids, nonces);
        let mut z = Scalar::zero();
        let c = compute::challenge(&self.group_key, &R, msg);
        let mut bad_party_sigs = Vec::new();

        for i in 0..sig_shares.len() {
            let z_i = sig_shares[i].z_i;
            if z_i * G
                != (Ris[i]
                    + sig_shares[i].public_key.iter().fold(
                        Point::zero(),
                        |p, (key_id, public_key)| {
                            p + compute::lambda(*key_id, key_ids) * c * public_key
                        },
                    ))
            {
                bad_party_sigs.push(sig_shares[i].id);
            }
            z += z_i;
        }

        if bad_party_sigs.is_empty() {
            let sig = Signature { R, z };
            if sig.verify(&self.group_key, msg) {
                Ok(sig)
            } else {
                Err(AggregatorError::BadGroupSig)
            }
        } else {
            Err(AggregatorError::BadPartySigs(bad_party_sigs))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::common::{PolyCommitment, PublicNonce};
    use crate::v2;
    use crate::v2::SignatureShare;

    use hashbrown::HashMap;
    use rand_core::{CryptoRng, OsRng, RngCore};

    #[test]
    fn party_save_load() {
        let mut rng = OsRng::default();
        let ids = [1, 2, 3];
        let n: usize = 10;
        let t: usize = 7;

        let signer = v2::Party::new(0, &ids, 1, n, t, &mut rng);

        let state = signer.save();
        let loaded = v2::Party::load(&state);

        assert_eq!(signer, loaded);
    }

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

            party.compute_secret(h, &A).expect("compute_secret failed");
        }

        A
    }

    // There might be a slick one-liner for this?
    fn sign<RNG: RngCore + CryptoRng>(
        msg: &[u8],
        signers: &mut [v2::Party],
        rng: &mut RNG,
    ) -> (Vec<PublicNonce>, Vec<SignatureShare>, Vec<usize>) {
        let party_ids: Vec<usize> = signers.iter().map(|s| s.party_id).collect();
        let key_ids: Vec<usize> = signers.iter().flat_map(|s| s.key_ids.clone()).collect();
        let nonces: Vec<PublicNonce> = signers.iter_mut().map(|s| s.gen_nonce(rng)).collect();
        let shares = signers
            .iter()
            .map(|s| s.sign(msg, &party_ids, &key_ids, &nonces))
            .collect();

        (nonces, shares, key_ids)
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
            let mut sig_agg =
                v2::SignatureAggregator::new(N, T, A.clone()).expect("aggregator ctor failed");

            let (nonces, sig_shares, key_ids) = sign(&msg, &mut signers, &mut rng);
            if let Err(e) = sig_agg.sign(&msg, &nonces, &sig_shares, &key_ids) {
                panic!("Aggregator sign failed: {:?}", e);
            }
        }
    }
}
