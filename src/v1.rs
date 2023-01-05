use num_traits::Zero;
use polynomial::Polynomial;
use rand_core::{CryptoRng, RngCore};
use secp256k1_math::{
    point::{Point, G},
    scalar::Scalar,
};
use serde::{Deserialize, Serialize};

use crate::common::{Nonce, PolyCommitment, PublicNonce, Signature, SignatureShare};
use crate::compute;
use crate::schnorr::ID;
use crate::vss::VSS;

use hashbrown::HashMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
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
    nonce: Nonce,
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
            nonce: Nonce::new(),
        }
    }

    pub fn gen_nonce<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG) -> PublicNonce {
        let nonce = Nonce {
            d: Scalar::random(rng),
            e: Scalar::random(rng),
        };

        self.nonce = nonce;

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
        for i in 0..self.n as usize {
            shares.insert(i, self.f.eval(Scalar::from((i + 1) as u32)));
        }
        shares
    }

    // TODO: Maybe this should be private? If receive_share is keeping track
    // of which it receives, then this could be called when it has N shares from unique ids
    #[allow(non_snake_case)]
    pub fn compute_secret(&mut self, shares: HashMap<usize, Scalar>, A: &[PolyCommitment]) {
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
    pub fn sign(&self, msg: &[u8], signers: &[usize], nonces: &[PublicNonce]) -> Scalar {
        let (_R_vec, R) = compute::intermediate(msg, &signers, nonces);
        let mut z = &self.nonce.d + &self.nonce.e * compute::binding(&self.id(), nonces, msg);
        z += compute::challenge(&self.group_key, &R, msg)
            * &self.private_key
            * compute::lambda(&self.id, signers);
        z
    }
}

#[allow(non_snake_case)]
pub struct SignatureAggregator {
    pub N: usize,
    pub T: usize,
    pub A: Vec<PolyCommitment>,
    pub B: Vec<PublicNonce>,
    pub key: Point,
}

impl SignatureAggregator {
    #[allow(non_snake_case)]
    pub fn new(N: usize, T: usize, A: Vec<PolyCommitment>, B: Vec<PublicNonce>) -> Self {
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
        // TODO: Check that each B_i is len num_nonces?

        Self {
            N: N,
            T: T,
            A: A,
            B: B,
            key: key,
        }
    }

    #[allow(non_snake_case)]
    pub fn sign(
        &mut self,
        msg: &[u8],
        signers: &[usize],
        sig_shares: &[SignatureShare],
    ) -> Signature {
        let (R_vec, R) = compute::intermediate(msg, &signers, &self.B);

        let mut z = Scalar::zero();
        let c = compute::challenge(&self.key, &R, &msg); // only needed for checking z_i
        for i in 0..signers.len() {
            let z_i = sig_shares[i].z_i;
            assert!(
                z_i * G
                    == R_vec[i]
                        + (compute::lambda(&sig_shares[i].id, signers)
                            * c
                            * sig_shares[i].public_key)
            ); // TODO: This should return a list of bad parties.
            z += z_i;
        }

        Signature { R: R, z: z }
    }

    #[allow(non_snake_case)]
    pub fn set_party_nonce(&mut self, i: usize, B: &PublicNonce) {
        self.B[i] = B.clone();
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Signer {
    pub parties: Vec<Party>,
}

impl crate::traits::Signer for Signer {
    fn new<RNG: RngCore + CryptoRng>(ids: &[usize], n: usize, t: usize, rng: &mut RNG) -> Self {
        let parties = ids.iter().map(|id| Party::new(*id, n, t, rng)).collect();
        Signer { parties }
    }

    fn gen_nonces<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG) -> Vec<(usize, PublicNonce)> {
        self.parties
            .iter_mut()
            .map(|p| (p.id, p.gen_nonce(rng)))
            .collect()
    }

    fn sign(&self, msg: &[u8], signers: &[usize], nonces: &[PublicNonce]) -> Vec<SignatureShare> {
        self.parties
            .iter()
            .map(|p| SignatureShare {
                id: p.id,
                z_i: p.sign(msg, signers, nonces),
                public_key: p.public_key,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::common::Nonce;
    use crate::traits::Signer;
    use crate::v1;
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
            assert!(party.nonce == Nonce::new());
        }

        let nonces = signer.gen_nonces(&mut rng);

        assert_eq!(nonces.len(), ids.len());

        for party in &signer.parties {
            assert!(party.nonce != Nonce::new());
        }
    }
}
