use num_traits::Zero;
use p256k1::{
    point::{Point, G},
    scalar::Scalar,
};
use polynomial::Polynomial;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::common::{Nonce, PolyCommitment, PublicNonce, Signature};
use crate::compute;
use crate::errors::{AggregatorError, DkgError};
use crate::schnorr::ID;
use crate::vss::VSS;

use hashbrown::HashMap;

pub type SignatureShare = crate::common::SignatureShare<Point>;

#[derive(Debug, Deserialize, Serialize)]
pub struct PartyState {
    pub private_key: Scalar,
    pub polynomial: Polynomial<Scalar>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(non_snake_case)]
pub struct Party {
    pub id: usize,
    pub public_key: Point,
    n: usize,
    f: Polynomial<Scalar>,
    private_key: Scalar,
    group_key: Point,
    nonce: Nonce,
}

impl Party {
    #[allow(non_snake_case)]
    pub fn new<RNG: RngCore + CryptoRng>(id: usize, n: usize, t: usize, rng: &mut RNG) -> Self {
        Self {
            id,
            n,
            f: VSS::random_poly(t - 1, rng),
            private_key: Scalar::zero(),
            public_key: Point::zero(),
            group_key: Point::zero(),
            nonce: Nonce::zero(),
        }
    }

    pub fn load(id: usize, n: usize, group_key: &Point, state: &PartyState) -> Self {
        Self {
            id,
            n,
            f: state.polynomial.clone(),
            private_key: state.private_key,
            public_key: &state.private_key * G,
            group_key: *group_key,
            nonce: Nonce::zero(),
        }
    }

    pub fn save(&self) -> PartyState {
        PartyState {
            private_key: self.private_key,
            polynomial: self.f.clone(),
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
        for i in 0..self.n {
            shares.insert(i, self.f.eval(Scalar::from((i + 1) as u32)));
        }
        shares
    }

    // TODO: Maybe this should be private? If receive_share is keeping track
    // of which it receives, then this could be called when it has N shares from unique ids
    #[allow(non_snake_case)]
    pub fn compute_secret(
        &mut self,
        shares: HashMap<usize, Scalar>,
        A: &[PolyCommitment],
    ) -> Result<(), DkgError> {
        let mut missing_shares = Vec::new();
        for i in 0..self.n {
            if shares.get(&i).is_none() {
                missing_shares.push(i);
            }
        }
        if !missing_shares.is_empty() {
            return Err(DkgError::MissingShares(missing_shares));
        }

        self.private_key = Scalar::zero();

        let bad_ids: Vec<usize> = shares.keys().cloned().filter(|i| !A[*i].verify()).collect();
        if !bad_ids.is_empty() {
            return Err(DkgError::BadIds(bad_ids));
        }

        let mut bad_shares = Vec::new();
        for (i, s) in shares.iter() {
            let Ai = &A[*i];
            if s * G != (0..Ai.A.len()).fold(Point::zero(), |s, j| s + (self.id() ^ j) * Ai.A[j]) {
                bad_shares.push(*i);
            }
        }
        if !bad_shares.is_empty() {
            return Err(DkgError::BadShares(bad_shares));
        }

        for (i, s) in shares.iter() {
            let Ai = &A[*i];

            self.private_key += s;
            self.group_key += Ai.A[0];
        }
        self.public_key = self.private_key * G;

        Ok(())
    }

    fn id(&self) -> Scalar {
        compute::id(self.id)
    }

    #[allow(non_snake_case)]
    pub fn sign(&self, msg: &[u8], signers: &[usize], nonces: &[PublicNonce]) -> SignatureShare {
        let (_R_vec, R) = compute::intermediate(msg, signers, nonces);
        let mut z = &self.nonce.d + &self.nonce.e * compute::binding(&self.id(), nonces, msg);
        z += compute::challenge(&self.group_key, &R, msg)
            * &self.private_key
            * compute::lambda(self.id, signers);

        SignatureShare {
            id: self.id,
            z_i: z,
            public_key: self.public_key,
        }
    }
}

#[allow(non_snake_case)]
pub struct SignatureAggregator {
    pub N: usize,
    pub T: usize,
    pub key: Point,
}

impl SignatureAggregator {
    #[allow(non_snake_case)]
    pub fn new(N: usize, T: usize, A: Vec<PolyCommitment>) -> Result<Self, AggregatorError> {
        if A.len() != N {
            return Err(AggregatorError::BadPolyCommitmentLen(A.len(), N));
        }

        let mut bad_poly_commitments = Vec::new();
        for A_i in &A {
            if !A_i.verify() {
                bad_poly_commitments.push(A_i.id.id);
            }
        }
        if !bad_poly_commitments.is_empty() {
            return Err(AggregatorError::BadPolyCommitments(bad_poly_commitments));
        }

        let mut key = Point::zero(); // TODO: Compute pub key from A
        for A_i in &A {
            key += &A_i.A[0];
        }
        //println!("SA groupKey {}", key);

        Ok(Self { N, T, key })
    }

    #[allow(non_snake_case)]
    pub fn sign(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
    ) -> Result<Signature, AggregatorError> {
        if nonces.len() != sig_shares.len() {
            return Err(AggregatorError::BadNonceLen(nonces.len(), sig_shares.len()));
        }

        let signers: Vec<usize> = sig_shares.iter().map(|ss| ss.id).collect();
        let (R_vec, R) = compute::intermediate(msg, &signers, nonces);
        let mut z = Scalar::zero();
        let c = compute::challenge(&self.key, &R, msg);
        let mut bad_party_sigs = Vec::new();

        for i in 0..sig_shares.len() {
            let z_i = sig_shares[i].z_i;
            if z_i * G
                != R_vec[i]
                    + (compute::lambda(sig_shares[i].id, &signers) * c * sig_shares[i].public_key)
            {
                bad_party_sigs.push(sig_shares[i].id);
            }

            z += z_i;
        }
        if bad_party_sigs.is_empty() {
            let sig = Signature { R, z };
            if sig.verify(&self.key, msg) {
                Ok(sig)
            } else {
                Err(AggregatorError::BadGroupSig)
            }
        } else {
            Err(AggregatorError::BadPartySigs(bad_party_sigs))
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SignerState {
    n: usize,
    group_key: Point,
    parties: HashMap<usize, PartyState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signer {
    pub n: usize,
    pub group_key: Point,
    pub parties: Vec<Party>,
}

impl Signer {
    pub fn new<RNG: RngCore + CryptoRng>(ids: &[usize], n: usize, t: usize, rng: &mut RNG) -> Self {
        let parties = ids.iter().map(|id| Party::new(*id, n, t, rng)).collect();
        Signer {
            n,
            group_key: Point::zero(),
            parties,
        }
    }

    pub fn load(state: &SignerState) -> Self {
        let parties = state
            .parties
            .iter()
            .map(|(id, ps)| Party::load(*id, state.n, &state.group_key, ps))
            .collect();

        Self {
            n: state.n,
            group_key: state.group_key,
            parties,
        }
    }

    pub fn save(&self) -> SignerState {
        let mut parties = HashMap::new();

        for party in &self.parties {
            parties.insert(party.id, party.save());
        }

        SignerState {
            n: self.n,
            group_key: self.group_key,
            parties,
        }
    }

    pub fn get_poly_commitments<RNG: RngCore + CryptoRng>(
        &self,
        rng: &mut RNG,
    ) -> Vec<PolyCommitment> {
        self.parties
            .iter()
            .map(|p| p.get_poly_commitment(rng))
            .collect()
    }

    pub fn get_ids(&self) -> Vec<usize> {
        self.parties.iter().map(|p| p.id).collect()
    }
}

impl crate::traits::Signer<Point> for Signer {
    fn gen_nonces<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG) -> Vec<PublicNonce> {
        self.parties.iter_mut().map(|p| p.gen_nonce(rng)).collect()
    }

    fn sign(&self, msg: &[u8], signers: &[usize], nonces: &[PublicNonce]) -> Vec<SignatureShare> {
        self.parties
            .iter()
            .map(|p| p.sign(msg, signers, nonces))
            .collect()
    }
}

pub mod test_helpers {
    use crate::common::{PolyCommitment, PublicNonce};
    use crate::errors::DkgError;
    use crate::traits::Signer;
    use crate::v1;

    use hashbrown::HashMap;
    use rand_core::{CryptoRng, RngCore};

    #[allow(non_snake_case)]
    pub fn dkg<RNG: RngCore + CryptoRng>(
        signers: &mut [v1::Signer],
        rng: &mut RNG,
    ) -> Result<Vec<PolyCommitment>, HashMap<usize, DkgError>> {
        let A: Vec<PolyCommitment> = signers
            .iter()
            .flat_map(|s| s.get_poly_commitments(rng))
            .collect();

        // each party broadcasts their commitments
        // these hashmaps will need to be serialized in tuples w/ the value encrypted
        let mut broadcast_shares = Vec::new();
        for signer in signers.iter() {
            for party in &signer.parties {
                broadcast_shares.push((party.id, party.get_shares()));
            }
        }

        // each party collects its shares from the broadcasts
        // maybe this should collect into a hashmap first?
        let mut secret_errors = HashMap::new();
        for signer in signers.iter_mut() {
            for party in signer.parties.iter_mut() {
                let mut h = HashMap::new();

                for (id, share) in &broadcast_shares {
                    h.insert(*id, share[&party.id]);
                }

                if let Err(secret_error) = party.compute_secret(h, &A) {
                    secret_errors.insert(party.id, secret_error);
                }
            }
        }

        if secret_errors.is_empty() {
            Ok(A)
        } else {
            Err(secret_errors)
        }
    }

    // There might be a slick one-liner for this?
    pub fn sign<RNG: RngCore + CryptoRng>(
        msg: &[u8],
        signers: &mut [v1::Signer],
        rng: &mut RNG,
    ) -> (Vec<PublicNonce>, Vec<v1::SignatureShare>) {
        let ids: Vec<usize> = signers.iter().flat_map(|s| s.get_ids()).collect();
        let nonces: Vec<PublicNonce> = signers.iter_mut().flat_map(|s| s.gen_nonces(rng)).collect();
        let shares = signers
            .iter()
            .flat_map(|s| s.sign(msg, &ids, &nonces))
            .collect();

        (nonces, shares)
    }
}

#[cfg(test)]
mod tests {
    use crate::traits::Signer;
    use crate::v1;

    use num_traits::Zero;
    use rand_core::OsRng;

    #[test]
    fn signer_new() {
        let mut rng = OsRng::default();
        let ids = [1, 2, 3];
        let n: usize = 10;
        let t: usize = 7;

        let signer = v1::Signer::new(&ids, n, t, &mut rng);

        assert_eq!(signer.parties.len(), ids.len());
    }

    #[test]
    fn signer_gen_nonces() {
        let mut rng = OsRng::default();
        let ids = [1, 2, 3];
        let n: usize = 10;
        let t: usize = 7;

        let mut signer = v1::Signer::new(&ids, n, t, &mut rng);

        for party in &signer.parties {
            assert!(party.nonce.is_zero());
        }

        let nonces = signer.gen_nonces(&mut rng);

        assert_eq!(nonces.len(), ids.len());

        for party in &signer.parties {
            assert!(!party.nonce.is_zero());
        }
    }

    #[test]
    fn signer_save_load() {
        let mut rng = OsRng::default();
        let ids = [1, 2, 3];
        let n: usize = 10;
        let t: usize = 7;

        let signer = v1::Signer::new(&ids, n, t, &mut rng);

        let state = signer.save();
        let loaded = v1::Signer::load(&state);

        assert_eq!(signer, loaded);
    }

    #[allow(non_snake_case)]
    #[test]
    fn aggregator_sign() {
        let mut rng = OsRng::default();
        let msg = "It was many and many a year ago".as_bytes();
        let N: usize = 10;
        let T: usize = 7;
        let signer_ids: Vec<Vec<usize>> = [
            [0, 1, 2].to_vec(),
            [3, 4].to_vec(),
            [5, 6, 7].to_vec(),
            [8, 9].to_vec(),
        ]
        .to_vec();
        let mut signers: Vec<v1::Signer> = signer_ids
            .iter()
            .map(|ids| v1::Signer::new(ids, N, T, &mut rng))
            .collect();

        let A = match v1::test_helpers::dkg(&mut signers, &mut rng) {
            Ok(A) => A,
            Err(secret_errors) => {
                panic!("Got secret errors from DKG: {:?}", secret_errors);
            }
        };

        // signers [0,1,3] who have T keys
        {
            let mut signers = [signers[0].clone(), signers[1].clone(), signers[3].clone()].to_vec();
            let mut sig_agg =
                v1::SignatureAggregator::new(N, T, A.clone()).expect("aggregator ctor failed");

            let (nonces, sig_shares) = v1::test_helpers::sign(&msg, &mut signers, &mut rng);
            if let Err(e) = sig_agg.sign(&msg, &nonces, &sig_shares) {
                panic!("Aggregator sign failed: {:?}", e);
            }
        }
    }
}
