use hashbrown::{HashMap, HashSet};
use num_traits::Zero;
use p256k1::{
    point::{Point, G},
    scalar::Scalar,
};
use polynomial::Polynomial;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::common::{Nonce, PolyCommitment, PublicNonce, Signature, SignatureShare};
use crate::compute;
use crate::errors::{AggregatorError, DkgError};
use crate::schnorr::ID;
use crate::vss::VSS;

/// A map of private keys indexed by key ID
pub type PrivKeyMap = HashMap<u32, Scalar>;
/// A signing set of key IDs indexed by party ID
pub type SelectedSigners = HashMap<u32, HashSet<u32>>;

#[derive(Serialize, Deserialize)]
/// The saved state required to construct a party
pub struct PartyState {
    /// The party ID
    pub party_id: u32,
    /// The key IDs for this party
    pub key_ids: Vec<u32>,
    /// The total number of keys
    pub num_keys: u32,
    /// The total number of parties
    pub num_parties: u32,
    /// The threshold for signing
    pub threshold: u32,
    /// The party's private polynomial
    pub polynomial: Polynomial<Scalar>,
    /// The private keys for this party, indexed by ID
    pub private_keys: PrivKeyMap,
    /// The aggregate group public key
    pub group_key: Point,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(non_snake_case)]
/// A WSTS party, which encapsulates a single polynomial, nonce, and one private key per key ID
pub struct Party {
    /// The party ID
    pub party_id: u32,
    /// The key IDs for this party
    pub key_ids: Vec<u32>,
    /// The public keys for this party, indexed by ID
    num_keys: u32,
    num_parties: u32,
    threshold: u32,
    f: Polynomial<Scalar>,
    private_keys: PrivKeyMap,
    group_key: Point,
    nonce: Nonce,
}

impl Party {
    #[allow(non_snake_case)]
    /// Construct a random Party with the passed party ID, key IDs, and parameters
    pub fn new<RNG: RngCore + CryptoRng>(
        party_id: u32,
        key_ids: &[u32],
        num_parties: u32,
        num_keys: u32,
        threshold: u32,
        rng: &mut RNG,
    ) -> Self {
        Self {
            party_id,
            key_ids: key_ids.to_vec(),
            num_keys,
            num_parties,
            threshold,
            f: VSS::random_poly(threshold - 1, rng),
            private_keys: PrivKeyMap::new(),
            group_key: Point::zero(),
            nonce: Nonce::zero(),
        }
    }

    /// Load a party from `state`
    pub fn load(state: &PartyState) -> Self {
        Self {
            party_id: state.party_id,
            key_ids: state.key_ids.clone(),
            num_keys: state.num_keys,
            num_parties: state.num_parties,
            threshold: state.threshold,
            f: state.polynomial.clone(),
            private_keys: state.private_keys.clone(),
            group_key: state.group_key,
            nonce: Nonce::zero(),
        }
    }

    /// Save the state required to reconstruct the party
    pub fn save(&self) -> PartyState {
        PartyState {
            party_id: self.party_id,
            key_ids: self.key_ids.clone(),
            num_keys: self.num_keys,
            num_parties: self.num_parties,
            threshold: self.threshold,
            polynomial: self.f.clone(),
            private_keys: self.private_keys.clone(),
            group_key: self.group_key,
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

    /// Get the shares of this party's private polynomial for all keys
    pub fn get_shares(&self) -> HashMap<u32, Scalar> {
        let mut shares = HashMap::new();
        for i in 0..self.num_keys {
            shares.insert(i, self.f.eval(compute::id(i)));
        }
        shares
    }

    #[allow(non_snake_case)]
    /// Compute this party's share of the group secret key
    pub fn compute_secret(
        &mut self,
        shares: &HashMap<u32, HashMap<u32, Scalar>>,
        A: &[PolyCommitment],
    ) -> Result<(), DkgError> {
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
                bad_ids.push(i.try_into().unwrap());
            }
            self.group_key += Ai.A[0];
        }
        if !bad_ids.is_empty() {
            return Err(DkgError::BadIds(bad_ids));
        }

        let mut not_enough_shares = Vec::new();
        for key_id in &self.key_ids {
            if shares[key_id].len() != self.num_parties.try_into().unwrap() {
                not_enough_shares.push(*key_id);
            }
        }
        if !not_enough_shares.is_empty() {
            return Err(DkgError::NotEnoughShares(not_enough_shares));
        }

        let mut bad_shares = Vec::new();
        for key_id in &self.key_ids {
            for (sender, s) in &shares[key_id] {
                let Ai = &A[usize::try_from(*sender).unwrap()];
                if s * G != compute::poly(&compute::id(*key_id), &Ai.A)? {
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
        }

        Ok(())
    }

    /// Compute a Scalar from this party's ID
    pub fn id(&self) -> Scalar {
        compute::id(self.party_id)
    }

    /// Sign `msg` with this party's shares of the group private key, using the set of `party_ids`, `key_ids` and corresponding `nonces`
    #[allow(non_snake_case)]
    pub fn sign(
        &self,
        msg: &[u8],
        party_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> SignatureShare {
        let (_R_vec, R) = compute::intermediate(msg, party_ids, nonces);
        let c = compute::challenge(&self.group_key, &R, msg);

        self.sign_challenge(msg, key_ids, nonces, &c)
    }

    /// Sign `msg` with this party's shares of the group private key, using the set of `party_ids`, `key_ids` and corresponding `nonces` with a tweaked public key
    #[allow(non_snake_case)]
    pub fn sign_tweaked(
        &self,
        msg: &[u8],
        party_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
        tweaked_public_key: &Point,
    ) -> SignatureShare {
        let (_R_vec, R) = compute::intermediate(msg, party_ids, nonces);
        let c = compute::challenge(tweaked_public_key, &R, msg);

        self.sign_challenge(msg, key_ids, nonces, &c)
    }

    #[allow(non_snake_case)]
    fn sign_challenge(
        &self,
        msg: &[u8],
        key_ids: &[u32],
        nonces: &[PublicNonce],
        c: &Scalar,
    ) -> SignatureShare {
        let mut z = &self.nonce.d + &self.nonce.e * compute::binding(&self.id(), nonces, msg);
        for key_id in self.key_ids.iter() {
            z += c * &self.private_keys[key_id] * compute::lambda(*key_id, key_ids);
        }

        SignatureShare {
            id: self.party_id,
            z_i: z,
            key_ids: self.key_ids.clone(),
        }
    }
}

#[allow(non_snake_case)]
/// The group signature aggregator
pub struct SignatureAggregator {
    /// The total number of keys
    pub num_keys: u32,
    /// The threshold of signing keys needed to construct a valid signature
    pub threshold: u32,
    /// The aggregate group polynomial; poly[0] is the group public key
    pub poly: Vec<Point>,
}

impl SignatureAggregator {
    #[allow(non_snake_case)]
    /// Construct a SignatureAggregator with the passed parameters and polynomial commitments
    pub fn new(
        num_keys: u32,
        threshold: u32,
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

        let mut poly = Vec::with_capacity(threshold.try_into().unwrap());

        for i in 0..poly.capacity() {
            poly.push(Point::zero());
            for p in &A {
                poly[i] += &p.A[i];
            }
        }

        Ok(Self {
            num_keys,
            threshold,
            poly,
        })
    }

    #[allow(non_snake_case)]
    /// Check and aggregate the party signatures
    pub fn sign(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[u32],
    ) -> Result<Signature, AggregatorError> {
        if nonces.len() != sig_shares.len() {
            return Err(AggregatorError::BadNonceLen(nonces.len(), sig_shares.len()));
        }

        let party_ids: Vec<u32> = sig_shares.iter().map(|ss| ss.id).collect();
        let (Ris, R) = compute::intermediate(msg, &party_ids, nonces);
        let mut z = Scalar::zero();
        let c = compute::challenge(&self.poly[0], &R, msg);
        let mut bad_party_keys = Vec::new();
        let mut bad_party_sigs = Vec::new();

        for i in 0..sig_shares.len() {
            let z_i = sig_shares[i].z_i;
            let mut cx = Point::zero();

            for key_id in &sig_shares[i].key_ids {
                let kid = compute::id(*key_id);
                let public_key = match compute::poly(&kid, &self.poly) {
                    Ok(p) => p,
                    Err(_) => {
                        bad_party_keys.push(sig_shares[i].id);
                        Point::zero()
                    }
                };

                cx += compute::lambda(*key_id, key_ids) * c * public_key;
            }

            if z_i * G != (Ris[i] + cx) {
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

/// Typedef so we can use the same tokens for v1 and v2
pub type SignerState = PartyState;
/// Typedef so we can use the same tokens for v1 and v2
pub type Signer = Party;

impl crate::traits::Signer for Party {
    fn get_id(&self) -> u32 {
        self.party_id
    }

    fn get_key_ids(&self) -> Vec<u32> {
        self.key_ids.clone()
    }

    fn get_poly_commitments<RNG: RngCore + CryptoRng>(&self, rng: &mut RNG) -> Vec<PolyCommitment> {
        vec![self.get_poly_commitment(rng)]
    }

    fn reset_polys<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG) {
        self.f = VSS::random_poly(self.threshold - 1, rng);
    }

    fn get_shares(&self) -> HashMap<u32, HashMap<u32, Scalar>> {
        let mut shares = HashMap::new();

        shares.insert(self.party_id, self.get_shares());

        shares
    }

    fn compute_secrets(
        &mut self,
        private_shares: &HashMap<u32, HashMap<u32, Scalar>>,
        polys: &[PolyCommitment],
    ) -> Result<(), HashMap<u32, DkgError>> {
        // go through the shares, looking for this party's
        let mut key_shares = HashMap::new();
        for key_id in self.get_key_ids() {
            let mut shares = HashMap::new();
            for (signer_id, signer_shares) in private_shares.iter() {
                shares.insert(*signer_id, signer_shares[&key_id]);
            }
            key_shares.insert(key_id, shares);
        }

        match self.compute_secret(&key_shares, polys) {
            Ok(()) => Ok(()),
            Err(dkg_error) => {
                let mut dkg_errors = HashMap::new();
                dkg_errors.insert(self.party_id, dkg_error);
                Err(dkg_errors)
            }
        }
    }

    fn gen_nonces<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG) -> Vec<PublicNonce> {
        vec![self.gen_nonce(rng)]
    }

    fn compute_intermediate(
        msg: &[u8],
        signer_ids: &[u32],
        _key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> (Vec<Point>, Point) {
        compute::intermediate(msg, signer_ids, nonces)
    }

    fn sign(
        &self,
        msg: &[u8],
        signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> Vec<SignatureShare> {
        vec![self.sign(msg, signer_ids, key_ids, nonces)]
    }

    fn sign_tweaked(
        &self,
        msg: &[u8],
        signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
        tweaked_public_key: &Point,
    ) -> Vec<SignatureShare> {
        vec![self.sign_tweaked(msg, signer_ids, key_ids, nonces, tweaked_public_key)]
    }
}

/// Helper functions for tests
pub mod test_helpers {
    use crate::common::{PolyCommitment, PublicNonce};
    use crate::errors::DkgError;
    use crate::v2;
    use crate::v2::SignatureShare;

    use hashbrown::HashMap;
    use rand_core::{CryptoRng, RngCore};

    #[allow(non_snake_case)]
    /// Run a distributed key generation round
    pub fn dkg<RNG: RngCore + CryptoRng>(
        signers: &mut [v2::Party],
        rng: &mut RNG,
    ) -> Result<Vec<PolyCommitment>, HashMap<u32, DkgError>> {
        let polys: Vec<PolyCommitment> =
            signers.iter().map(|s| s.get_poly_commitment(rng)).collect();

        // each party broadcasts their commitments
        let mut broadcast_shares = Vec::new();
        for party in signers.iter() {
            broadcast_shares.push((party.party_id, party.get_shares()));
        }

        // each party collects its shares from the broadcasts
        // maybe this should collect into a hashmap first?
        let mut secret_errors = HashMap::new();
        for party in signers.iter_mut() {
            let mut party_shares = HashMap::new();
            for key_id in party.key_ids.clone() {
                let mut key_shares = HashMap::new();

                for (id, shares) in &broadcast_shares {
                    key_shares.insert(*id, shares[&key_id]);
                }

                party_shares.insert(key_id, key_shares);
            }

            if let Err(secret_error) = party.compute_secret(&party_shares, &polys) {
                secret_errors.insert(party.party_id, secret_error);
            }
        }

        if secret_errors.is_empty() {
            Ok(polys)
        } else {
            Err(secret_errors)
        }
    }

    /// Run a signing round for the passed `msg`
    pub fn sign<RNG: RngCore + CryptoRng>(
        msg: &[u8],
        signers: &mut [v2::Party],
        rng: &mut RNG,
    ) -> (Vec<PublicNonce>, Vec<SignatureShare>, Vec<u32>) {
        let party_ids: Vec<u32> = signers.iter().map(|s| s.party_id).collect();
        let key_ids: Vec<u32> = signers.iter().flat_map(|s| s.key_ids.clone()).collect();
        let nonces: Vec<PublicNonce> = signers.iter_mut().map(|s| s.gen_nonce(rng)).collect();
        let shares = signers
            .iter()
            .map(|s| s.sign(msg, &party_ids, &key_ids, &nonces))
            .collect();

        (nonces, shares, key_ids)
    }
}

#[cfg(test)]
mod tests {
    use crate::v2;

    use rand_core::OsRng;

    #[test]
    fn party_save_load() {
        let mut rng = OsRng::default();
        let key_ids = [1, 2, 3];
        let n: u32 = 10;
        let t: u32 = 7;

        let signer = v2::Party::new(0, &key_ids, 1, n, t, &mut rng);

        let state = signer.save();
        let loaded = v2::Party::load(&state);

        assert_eq!(signer, loaded);
    }

    #[allow(non_snake_case)]
    #[test]
    fn aggregator_sign() {
        let mut rng = OsRng::default();
        let msg = "It was many and many a year ago".as_bytes();
        let Nk: u32 = 10;
        let T: u32 = 7;
        let party_key_ids: Vec<Vec<u32>> = [
            [0, 1, 2].to_vec(),
            [3, 4].to_vec(),
            [5, 6, 7].to_vec(),
            [8, 9].to_vec(),
        ]
        .to_vec();
        let Np = party_key_ids.len().try_into().unwrap();
        let mut signers: Vec<v2::Party> = party_key_ids
            .iter()
            .enumerate()
            .map(|(pid, pkids)| v2::Party::new(pid.try_into().unwrap(), pkids, Np, Nk, T, &mut rng))
            .collect();

        let A = match v2::test_helpers::dkg(&mut signers, &mut rng) {
            Ok(A) => A,
            Err(secret_errors) => {
                panic!("Got secret errors from DKG: {:?}", secret_errors);
            }
        };

        // signers [0,1,3] who have T keys
        {
            let mut signers = [signers[0].clone(), signers[1].clone(), signers[3].clone()].to_vec();
            let mut sig_agg =
                v2::SignatureAggregator::new(Nk, T, A.clone()).expect("aggregator ctor failed");

            let (nonces, sig_shares, key_ids) =
                v2::test_helpers::sign(&msg, &mut signers, &mut rng);
            if let Err(e) = sig_agg.sign(&msg, &nonces, &sig_shares, &key_ids) {
                panic!("Aggregator sign failed: {:?}", e);
            }
        }
    }
}
