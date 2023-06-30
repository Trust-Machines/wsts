use hashbrown::HashMap;
use num_traits::Zero;
use p256k1::{
    point::{Point, G},
    scalar::Scalar,
};
use polynomial::Polynomial;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::common::{
    CheckPrivateShares, Nonce, PolyCommitment, PublicNonce, Signature, SignatureShare,
};
use crate::compute;
use crate::errors::{AggregatorError, DkgError};
use crate::schnorr::ID;
use crate::vss::VSS;

#[derive(Debug, Deserialize, Serialize)]
/// The saved state required to construct a party
pub struct PartyState {
    /// The party's private key
    pub private_key: Scalar,
    /// The party's private polynomial
    pub polynomial: Polynomial<Scalar>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(non_snake_case)]
/// A FROST party, which encapsulates a single polynomial, nonce, and key
pub struct Party {
    /// The ID
    pub id: u32,
    /// The public key
    pub public_key: Point,
    /// The polynomial used for Lagrange interpolation
    pub f: Polynomial<Scalar>,
    n: u32,
    private_key: Scalar,
    /// The aggregate group public key
    pub group_key: Point,
    nonce: Nonce,
}

impl Party {
    #[allow(non_snake_case)]
    /// Construct a random Party with the passed ID and parameters
    pub fn new<RNG: RngCore + CryptoRng>(id: u32, n: u32, t: u32, rng: &mut RNG) -> Self {
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

    /// Load a party from `state`
    pub fn load(id: u32, n: u32, group_key: &Point, state: &PartyState) -> Self {
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

    /// Save the state required to reconstruct the party
    pub fn save(&self) -> PartyState {
        PartyState {
            private_key: self.private_key,
            polynomial: self.f.clone(),
        }
    }

    /// Generate and store a private nonce for a signing round
    pub fn gen_nonce<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG) -> PublicNonce {
        self.nonce = Nonce::random(rng);

        PublicNonce::from(&self.nonce)
    }

    #[allow(non_snake_case)]
    /// Get a public commitment to the private polynomial
    pub fn get_poly_commitment<RNG: RngCore + CryptoRng>(&self, rng: &mut RNG) -> PolyCommitment {
        PolyCommitment {
            id: ID::new(&self.id(), &self.f.data()[0], rng),
            A: (0..self.f.data().len())
                .map(|i| &self.f.data()[i] * G)
                .collect(),
        }
    }

    /// Make a new polynomial
    pub fn reset_poly<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG) {
        let t = self.f.data().len() - 1;
        self.f = VSS::random_poly(t.try_into().unwrap(), rng);
    }

    /// Get the shares of this party's private polynomial for all parties
    pub fn get_shares(&self) -> HashMap<u32, Scalar> {
        let mut shares = HashMap::new();
        for i in 0..self.n {
            shares.insert(i, self.f.eval(compute::id(i)));
        }
        shares
    }

    #[allow(non_snake_case)]
    /// Compute this party's share of the group secret key
    pub fn compute_secret(
        &mut self,
        shares: HashMap<u32, Scalar>,
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
        self.group_key = Point::zero();

        let bad_ids: Vec<u32> = shares
            .keys()
            .cloned()
            .filter(|i| !A[usize::try_from(*i).unwrap()].verify())
            .collect();
        if !bad_ids.is_empty() {
            return Err(DkgError::BadIds(bad_ids));
        }
        // let's optimize for the case where all shares are good, and test them as a batch

        // building a vector of scalars and points from public poly evaluations and expected values takes too much memory
        // instead make an object which implements p256k1 MultiMult trait, using the existing powers of x and shares
        let mut check_shares = CheckPrivateShares::new(self.id(), &shares, A);

        // if the batch verify fails then check them one by one and find the bad ones
        if Point::multimult_trait(&mut check_shares)? != Point::zero() {
            let mut bad_shares = Vec::new();
            for (i, s) in shares.iter() {
                let Ai = &A[usize::try_from(*i).unwrap()];
                if s * G != compute::poly(&self.id(), &Ai.A)? {
                    bad_shares.push(*i);
                }
            }
            return Err(DkgError::BadShares(bad_shares));
        }

        for (i, s) in shares.iter() {
            let Ai = &A[usize::try_from(*i).unwrap()];

            self.private_key += s;
            self.group_key += Ai.A[0];
        }
        self.public_key = self.private_key * G;

        Ok(())
    }

    /// Compute a Scalar from this party's ID
    fn id(&self) -> Scalar {
        compute::id(self.id)
    }

    #[allow(non_snake_case)]
    /// Sign `msg` with this party's share of the group private key, using the set of `sigers` and corresponding `nonces`
    pub fn sign(&self, msg: &[u8], signers: &[u32], nonces: &[PublicNonce]) -> SignatureShare {
        let (_R_vec, R) = compute::intermediate(msg, signers, nonces);
        let mut z = &self.nonce.d + &self.nonce.e * compute::binding(&self.id(), nonces, msg);
        z += compute::challenge(&self.group_key, &R, msg)
            * &self.private_key
            * compute::lambda(self.id, signers);

        SignatureShare {
            id: self.id,
            z_i: z,
            key_ids: vec![self.id],
        }
    }

    /// Sign `msg` with this party's share of the group private key, using the set of `sigers` and corresponding `nonces` with a precomputed `aggregate_nonce`
    pub fn sign_precomputed(
        &self,
        msg: &[u8],
        signers: &[u32],
        nonces: &[PublicNonce],
        aggregate_nonce: &Point,
    ) -> SignatureShare {
        let mut z = &self.nonce.d + &self.nonce.e * compute::binding(&self.id(), nonces, msg);
        z += compute::challenge(&self.group_key, aggregate_nonce, msg)
            * &self.private_key
            * compute::lambda(self.id, signers);

        SignatureShare {
            id: self.id,
            z_i: z,
            key_ids: vec![self.id],
        }
    }
}

#[allow(non_snake_case)]
/// The group signature aggregator
pub struct SignatureAggregator {
    /// The total number of keys/parties
    pub N: u32,
    /// The threshold of signers needed to construct a valid signature
    pub T: u32,
    /// The aggregate group polynomial; poly[0] is the group public key
    pub poly: Vec<Point>,
}

impl SignatureAggregator {
    #[allow(non_snake_case)]
    /// Construct a SignatureAggregator with the passed parameters and polynomial commitments
    pub fn new(N: u32, T: u32, A: Vec<PolyCommitment>) -> Result<Self, AggregatorError> {
        let len = N.try_into().unwrap();
        if A.len() != len {
            return Err(AggregatorError::BadPolyCommitmentLen(len, A.len()));
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

        let mut poly = Vec::with_capacity(T.try_into().unwrap());

        for i in 0..poly.capacity() {
            poly.push(Point::zero());
            for p in &A {
                poly[i] += &p.A[i];
            }
        }

        Ok(Self { N, T, poly })
    }

    #[allow(non_snake_case)]
    /// Check and aggregate the party signatures
    pub fn sign(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
    ) -> Result<Signature, AggregatorError> {
        if nonces.len() != sig_shares.len() {
            return Err(AggregatorError::BadNonceLen(nonces.len(), sig_shares.len()));
        }

        let signers: Vec<u32> = sig_shares.iter().map(|ss| ss.id).collect();
        let (R_vec, R) = compute::intermediate(msg, &signers, nonces);
        let mut z = Scalar::zero();
        let c = compute::challenge(&self.poly[0], &R, msg);
        let mut bad_party_keys = Vec::new();
        let mut bad_party_sigs = Vec::new();

        for i in 0..sig_shares.len() {
            let id = compute::id(sig_shares[i].id);
            let public_key = match compute::poly(&id, &self.poly) {
                Ok(p) => p,
                Err(_) => {
                    bad_party_keys.push(sig_shares[i].id);
                    Point::zero()
                }
            };

            let z_i = sig_shares[i].z_i;

            if z_i * G != R_vec[i] + (compute::lambda(sig_shares[i].id, &signers) * c * public_key)
            {
                bad_party_sigs.push(sig_shares[i].id);
            }

            z += z_i;
        }
        if bad_party_sigs.is_empty() {
            let sig = Signature { R, z };
            if sig.verify(&self.poly[0], msg) {
                Ok(sig)
            } else {
                Err(AggregatorError::BadGroupSig)
            }
        } else if !bad_party_keys.is_empty() {
            Err(AggregatorError::BadPartyKeys(bad_party_keys))
        } else {
            Err(AggregatorError::BadPartySigs(bad_party_sigs))
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
/// The saved state required to construct a Signer
pub struct SignerState {
    /// The associated ID
    id: u32,
    /// The total number of keys
    n: u32,
    /// The aggregate group public key
    group_key: Point,
    /// The set of states for the parties which this object encapsulates, indexed by their party/key IDs
    parties: HashMap<u32, PartyState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A set of encapsulated FROST parties
pub struct Signer {
    /// The associated signer ID
    id: u32,
    /// The total number of keys
    n: u32,
    /// The aggregate group public key
    group_key: Point,
    /// The parties which this object encapsulates
    parties: Vec<Party>,
}

impl Signer {
    /// Construct a random Signer with the passed IDs and parameters
    pub fn new<RNG: RngCore + CryptoRng>(
        id: u32,
        key_ids: &[u32],
        n: u32,
        t: u32,
        rng: &mut RNG,
    ) -> Self {
        let parties = key_ids
            .iter()
            .map(|id| Party::new(*id, n, t, rng))
            .collect();
        Signer {
            id,
            n,
            group_key: Point::zero(),
            parties,
        }
    }

    /// Load a Signer from the saved state
    pub fn load(state: &SignerState) -> Self {
        let parties = state
            .parties
            .iter()
            .map(|(id, ps)| Party::load(*id, state.n, &state.group_key, ps))
            .collect();

        Self {
            id: state.id,
            n: state.n,
            group_key: state.group_key,
            parties,
        }
    }

    /// Save the state required to reconstruct the signer
    pub fn save(&self) -> SignerState {
        let mut parties = HashMap::new();

        for party in &self.parties {
            parties.insert(party.id, party.save());
        }

        SignerState {
            id: self.id,
            n: self.n,
            group_key: self.group_key,
            parties,
        }
    }
}

impl crate::traits::Signer for Signer {
    fn get_id(&self) -> u32 {
        self.id
    }

    fn get_key_ids(&self) -> Vec<u32> {
        self.parties.iter().map(|p| p.id).collect()
    }

    fn get_poly_commitments<RNG: RngCore + CryptoRng>(&self, rng: &mut RNG) -> Vec<PolyCommitment> {
        self.parties
            .iter()
            .map(|p| p.get_poly_commitment(rng))
            .collect()
    }

    fn reset_polys<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG) {
        for party in self.parties.iter_mut() {
            party.reset_poly(rng);
        }
    }

    fn get_shares(&self) -> HashMap<u32, HashMap<u32, Scalar>> {
        let mut shares = HashMap::new();
        for party in &self.parties {
            shares.insert(party.id, party.get_shares());
        }
        shares
    }

    fn compute_secrets(
        &mut self,
        private_shares: &HashMap<u32, HashMap<u32, Scalar>>,
        polys: &[PolyCommitment],
    ) -> Result<(), HashMap<u32, DkgError>> {
        let mut dkg_errors = HashMap::new();
        for party in &mut self.parties {
            // go through the shares, looking for this party's
            let mut key_shares = HashMap::with_capacity(polys.len());
            for (signer_id, signer_shares) in private_shares.iter() {
                key_shares.insert(*signer_id, signer_shares[&party.id]);
            }
            if let Err(e) = party.compute_secret(key_shares, polys) {
                dkg_errors.insert(party.id, e);
            }
        }

        if dkg_errors.is_empty() {
            Ok(())
        } else {
            Err(dkg_errors)
        }
    }

    fn gen_nonces<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG) -> Vec<PublicNonce> {
        self.parties.iter_mut().map(|p| p.gen_nonce(rng)).collect()
    }

    fn compute_intermediate(
        msg: &[u8],
        _signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> (Vec<Point>, Point) {
        compute::intermediate(msg, key_ids, nonces)
    }

    fn sign(
        &self,
        msg: &[u8],
        _signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> Vec<SignatureShare> {
        let aggregate_nonce = compute::aggregate_nonce(msg, key_ids, nonces).unwrap();
        self.parties
            .iter()
            .map(|p| p.sign_precomputed(msg, key_ids, nonces, &aggregate_nonce))
            .collect()
    }
}

/// Helper functions for tests
pub mod test_helpers {
    use crate::common::{PolyCommitment, PublicNonce};
    use crate::errors::DkgError;
    use crate::traits::Signer;
    use crate::v1;

    use hashbrown::HashMap;
    use rand_core::{CryptoRng, RngCore};

    #[allow(non_snake_case)]
    /// Run a distributed key generation round
    pub fn dkg<RNG: RngCore + CryptoRng>(
        signers: &mut [v1::Signer],
        rng: &mut RNG,
    ) -> Result<Vec<PolyCommitment>, HashMap<u32, DkgError>> {
        let A: Vec<PolyCommitment> = signers
            .iter()
            .flat_map(|s| s.get_poly_commitments(rng))
            .collect();

        let mut private_shares = HashMap::new();
        for signer in signers.iter() {
            for (signer_id, signer_shares) in signer.get_shares() {
                private_shares.insert(signer_id, signer_shares);
            }
        }

        let mut secret_errors = HashMap::new();
        for signer in signers.iter_mut() {
            if let Err(signer_secret_errors) = signer.compute_secrets(&private_shares, &A) {
                secret_errors.extend(signer_secret_errors.into_iter());
            }
        }

        if secret_errors.is_empty() {
            Ok(A)
        } else {
            Err(secret_errors)
        }
    }

    /// Run a signing round for the passed `msg`
    pub fn sign<RNG: RngCore + CryptoRng>(
        msg: &[u8],
        signers: &mut [v1::Signer],
        rng: &mut RNG,
    ) -> (Vec<PublicNonce>, Vec<v1::SignatureShare>) {
        let ids: Vec<u32> = signers.iter().flat_map(|s| s.get_key_ids()).collect();
        let nonces: Vec<PublicNonce> = signers.iter_mut().flat_map(|s| s.gen_nonces(rng)).collect();
        let shares = signers
            .iter()
            .flat_map(|s| s.sign(msg, &ids, &ids, &nonces))
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
        let id = 1;
        let key_ids = [1, 2, 3];
        let n: u32 = 10;
        let t: u32 = 7;

        let signer = v1::Signer::new(id, &key_ids, n, t, &mut rng);

        assert_eq!(signer.parties.len(), key_ids.len());
    }

    #[test]
    fn signer_gen_nonces() {
        let mut rng = OsRng::default();
        let id = 1;
        let key_ids = [1, 2, 3];
        let n: u32 = 10;
        let t: u32 = 7;

        let mut signer = v1::Signer::new(id, &key_ids, n, t, &mut rng);

        for party in &signer.parties {
            assert!(party.nonce.is_zero());
        }

        let nonces = signer.gen_nonces(&mut rng);

        assert_eq!(nonces.len(), key_ids.len());

        for party in &signer.parties {
            assert!(!party.nonce.is_zero());
        }
    }

    #[test]
    fn signer_save_load() {
        let mut rng = OsRng::default();
        let id = 1;
        let key_ids = [1, 2, 3];
        let n: u32 = 10;
        let t: u32 = 7;

        let signer = v1::Signer::new(id, &key_ids, n, t, &mut rng);

        let state = signer.save();
        let loaded = v1::Signer::load(&state);

        assert_eq!(signer, loaded);
    }

    #[allow(non_snake_case)]
    #[test]
    fn aggregator_sign() {
        let mut rng = OsRng::default();
        let msg = "It was many and many a year ago".as_bytes();
        let N: u32 = 10;
        let T: u32 = 7;
        let signer_ids: Vec<Vec<u32>> = [
            [0, 1, 2].to_vec(),
            [3, 4].to_vec(),
            [5, 6, 7].to_vec(),
            [8, 9].to_vec(),
        ]
        .to_vec();
        let mut signers: Vec<v1::Signer> = signer_ids
            .iter()
            .enumerate()
            .map(|(id, ids)| v1::Signer::new(id.try_into().unwrap(), ids, N, T, &mut rng))
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
