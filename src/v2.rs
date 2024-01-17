use hashbrown::{HashMap, HashSet};
use num_traits::{One, Zero};
use polynomial::Polynomial;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    common::{Nonce, PolyCommitment, PublicNonce, Signature, SignatureShare},
    compute,
    curve::{
        point::{Point, G},
        scalar::Scalar,
    },
    errors::{AggregatorError, DkgError},
    schnorr::ID,
    taproot::SchnorrProof,
    traits,
    vss::VSS,
};

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

    /// Get a public commitment to the private polynomial
    pub fn get_poly_commitment<RNG: RngCore + CryptoRng>(&self, rng: &mut RNG) -> PolyCommitment {
        PolyCommitment {
            id: ID::new(&self.id(), &self.f.data()[0], rng),
            poly: (0..self.f.data().len())
                .map(|i| &self.f.data()[i] * G)
                .collect(),
        }
    }

    /// Get the shares of this party's private polynomial for all keys
    pub fn get_shares(&self) -> HashMap<u32, Scalar> {
        let mut shares = HashMap::new();
        for i in 1..self.num_keys + 1 {
            shares.insert(i, self.f.eval(compute::id(i)));
        }
        shares
    }

    /// Compute this party's share of the group secret key
    pub fn compute_secret(
        &mut self,
        shares: &HashMap<u32, HashMap<u32, Scalar>>,
        comms: &HashMap<u32, PolyCommitment>,
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
        for (i, comm) in comms.iter() {
            if !comm.verify() {
                bad_ids.push(*i);
            }
            self.group_key += comm.poly[0];
        }
        if !bad_ids.is_empty() {
            return Err(DkgError::BadIds(bad_ids));
        }

        let mut not_enough_shares = Vec::new();
        for key_id in &self.key_ids {
            let num_parties: usize = self.num_parties.try_into().unwrap();
            if shares[key_id].len() != num_parties {
                not_enough_shares.push(*key_id);
            }
        }
        if !not_enough_shares.is_empty() {
            return Err(DkgError::NotEnoughShares(not_enough_shares));
        }

        let mut bad_shares = Vec::new();
        for key_id in &self.key_ids {
            for (sender, s) in &shares[key_id] {
                let comm = &comms[sender];
                if s * G != compute::poly(&compute::id(*key_id), &comm.poly)? {
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
    pub fn sign(
        &self,
        msg: &[u8],
        party_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> SignatureShare {
        self.sign_with_tweak(msg, party_ids, key_ids, nonces, &Scalar::from(0))
    }

    /// Sign `msg` with this party's shares of the group private key, using the set of `party_ids`, `key_ids` and corresponding `nonces` with a tweaked public key
    #[allow(non_snake_case)]
    pub fn sign_with_tweak(
        &self,
        msg: &[u8],
        party_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
        tweak: &Scalar,
    ) -> SignatureShare {
        let tweaked_public_key = self.group_key + tweak * G;
        let (_, R) = compute::intermediate(msg, party_ids, nonces);
        let c = compute::challenge(&tweaked_public_key, &R, msg);
        let mut r = &self.nonce.d + &self.nonce.e * compute::binding(&self.id(), nonces, msg);
        if tweak != &Scalar::zero() && !R.has_even_y() {
            r = -r;
        }

        let mut cx = Scalar::zero();
        for key_id in self.key_ids.iter() {
            cx += c * &self.private_keys[key_id] * compute::lambda(*key_id, key_ids);
        }

        if tweak != &Scalar::zero() && !tweaked_public_key.has_even_y() {
            cx = -cx;
        }

        let z = r + cx;

        SignatureShare {
            id: self.party_id,
            z_i: z,
            key_ids: self.key_ids.clone(),
        }
    }
}

/// The group signature aggregator
#[derive(Clone, Debug)]
pub struct Aggregator {
    /// The total number of keys
    pub num_keys: u32,
    /// The threshold of signing keys needed to construct a valid signature
    pub threshold: u32,
    /// The aggregate group polynomial; poly[0] is the group public key
    pub poly: Vec<Point>,
}

impl Aggregator {
    /// Check and aggregate the party signatures
    #[allow(non_snake_case)]
    pub fn sign_with_tweak(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[u32],
        tweak: &Scalar,
    ) -> Result<(Point, Signature), AggregatorError> {
        if nonces.len() != sig_shares.len() {
            return Err(AggregatorError::BadNonceLen(nonces.len(), sig_shares.len()));
        }

        let party_ids: Vec<u32> = sig_shares.iter().map(|ss| ss.id).collect();
        let (Rs, R) = compute::intermediate(msg, &party_ids, nonces);
        let mut z = Scalar::zero();
        let mut bad_party_keys = Vec::new();
        let mut bad_party_sigs = Vec::new();
        let aggregate_public_key = self.poly[0];
        let tweaked_public_key = aggregate_public_key + tweak * G;
        let c = compute::challenge(&tweaked_public_key, &R, msg);
        let mut r_sign = Scalar::one();
        let mut cx_sign = Scalar::one();
        if tweak != &Scalar::zero() {
            if !R.has_even_y() {
                r_sign = -Scalar::one();
            }
            if !tweaked_public_key.has_even_y() {
                cx_sign = -Scalar::one();
            }
        }

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

            if z_i * G != (r_sign * Rs[i] + cx_sign * cx) {
                bad_party_sigs.push(sig_shares[i].id);
            }

            z += z_i;
        }

        z += cx_sign * c * tweak;

        if bad_party_sigs.is_empty() {
            let sig = Signature { R, z };
            Ok((tweaked_public_key, sig))
        } else if !bad_party_keys.is_empty() {
            Err(AggregatorError::BadPartyKeys(bad_party_keys))
        } else {
            Err(AggregatorError::BadPartySigs(bad_party_sigs))
        }
    }
}

impl traits::Aggregator for Aggregator {
    /// Construct an Aggregator with the passed parameters
    fn new(num_keys: u32, threshold: u32) -> Self {
        Self {
            num_keys,
            threshold,
            poly: Default::default(),
        }
    }

    /// Initialize the Aggregator polynomial
    fn init(&mut self, comms: &HashMap<u32, PolyCommitment>) -> Result<(), AggregatorError> {
        let mut bad_poly_commitments = Vec::new();
        for (_id, comm) in comms {
            if !comm.verify() {
                bad_poly_commitments.push(comm.id.id);
            }
        }
        if !bad_poly_commitments.is_empty() {
            return Err(AggregatorError::BadPolyCommitments(bad_poly_commitments));
        }

        let mut poly = Vec::with_capacity(self.threshold.try_into().unwrap());

        for i in 0..poly.capacity() {
            poly.push(Point::zero());
            for (_, comm) in comms {
                poly[i] += &comm.poly[i];
            }
        }

        self.poly = poly;

        Ok(())
    }

    /// Check and aggregate the party signatures
    fn sign(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[u32],
    ) -> Result<Signature, AggregatorError> {
        let (key, sig) = self.sign_with_tweak(msg, nonces, sig_shares, key_ids, &Scalar::zero())?;

        if sig.verify(&key, msg) {
            Ok(sig)
        } else {
            Err(AggregatorError::BadGroupSig)
        }
    }

    /// Check and aggregate the party signatures
    fn sign_taproot(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[u32],
        merkle_root: Option<[u8; 32]>,
    ) -> Result<SchnorrProof, AggregatorError> {
        let tweak = compute::tweak(&self.poly[0], merkle_root);
        let (key, sig) = self.sign_with_tweak(msg, nonces, sig_shares, key_ids, &tweak)?;
        let proof = SchnorrProof::new(&sig);

        if proof.verify(&key.x(), msg) {
            Ok(proof)
        } else {
            Err(AggregatorError::BadGroupSig)
        }
    }
}

/// Typedef so we can use the same tokens for v1 and v2
pub type SignerState = PartyState;
/// Typedef so we can use the same tokens for v1 and v2
pub type Signer = Party;

impl traits::Signer for Party {
    fn new<RNG: RngCore + CryptoRng>(
        party_id: u32,
        key_ids: &[u32],
        num_signers: u32,
        num_keys: u32,
        threshold: u32,
        rng: &mut RNG,
    ) -> Self {
        Party::new(party_id, key_ids, num_signers, num_keys, threshold, rng)
    }

    fn get_id(&self) -> u32 {
        self.party_id
    }

    fn get_key_ids(&self) -> Vec<u32> {
        self.key_ids.clone()
    }

    fn get_num_parties(&self) -> u32 {
        self.num_parties
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
        polys: &HashMap<u32, PolyCommitment>,
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

    fn sign_taproot(
        &self,
        msg: &[u8],
        signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
        merkle_root: Option<[u8; 32]>,
    ) -> Vec<SignatureShare> {
        let tweak = compute::tweak(&self.group_key, merkle_root);
        vec![self.sign_with_tweak(msg, signer_ids, key_ids, nonces, &tweak)]
    }
}

/// Helper functions for tests
pub mod test_helpers {
    use crate::common::{PolyCommitment, PublicNonce};
    use crate::errors::DkgError;
    use crate::traits::Signer;
    use crate::v2;
    use crate::v2::SignatureShare;

    use hashbrown::HashMap;
    use rand_core::{CryptoRng, RngCore};

    /// Run a distributed key generation round
    pub fn dkg<RNG: RngCore + CryptoRng>(
        signers: &mut [v2::Party],
        rng: &mut RNG,
    ) -> Result<HashMap<u32, PolyCommitment>, HashMap<u32, DkgError>> {
        let polys: HashMap<u32, PolyCommitment> = signers
            .iter()
            .map(|s| (s.get_id(), s.get_poly_commitment(rng)))
            .collect();

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
    use crate::{traits::Aggregator, v2};

    use rand_core::OsRng;

    #[test]
    fn party_save_load() {
        let mut rng = OsRng;
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
        let mut rng = OsRng;
        let msg = "It was many and many a year ago".as_bytes();
        let Nk: u32 = 10;
        let T: u32 = 7;
        let party_key_ids: Vec<Vec<u32>> = [
            [1, 2, 3].to_vec(),
            [4, 5].to_vec(),
            [6, 7, 8].to_vec(),
            [9, 10].to_vec(),
        ]
        .to_vec();
        let Np = party_key_ids.len().try_into().unwrap();
        let mut signers: Vec<v2::Party> = party_key_ids
            .iter()
            .enumerate()
            .map(|(pid, pkids)| v2::Party::new(pid.try_into().unwrap(), pkids, Np, Nk, T, &mut rng))
            .collect();

        let comms = match v2::test_helpers::dkg(&mut signers, &mut rng) {
            Ok(comms) => comms,
            Err(secret_errors) => {
                panic!("Got secret errors from DKG: {:?}", secret_errors);
            }
        };

        // signers [0,1,3] who have T keys
        {
            let mut signers = [signers[0].clone(), signers[1].clone(), signers[3].clone()].to_vec();
            let mut sig_agg = v2::Aggregator::new(Nk, T);

            sig_agg.init(&comms).expect("aggregator init failed");

            let (nonces, sig_shares, key_ids) = v2::test_helpers::sign(msg, &mut signers, &mut rng);
            if let Err(e) = sig_agg.sign(msg, &nonces, &sig_shares, &key_ids) {
                panic!("Aggregator sign failed: {:?}", e);
            }
        }
    }
}
