use p256k1::{
    field,
    point::{Error as PointError, Point, G},
    scalar::Scalar,
};

use crate::{common::Signature, compute};

/// Errors from BIP-340 operations
#[derive(Clone, Debug)]
pub enum Error {
    /// Point R is odd
    OddR,
    /// Error doing point operations
    Point(PointError),
}

/// A SchnorrProof in BIP-340 format
#[allow(non_snake_case)]
#[derive(Debug, PartialEq, Eq)]
pub struct SchnorrProof {
    /// The schnorr public commitment (FROST Signature R)
    pub r: field::Element,
    /// The schnorr response (FROST Signature z)
    pub s: Scalar,
}

impl SchnorrProof {
    /// Construct a BIP-340 schnorr proof from a FROST signature
    pub fn new(sig: &Signature) -> Result<Self, Error> {
        /*if !sig.R.has_even_y() {
            Err(Error::OddR)
        } else {*/
        Ok(Self {
            r: sig.R.x(),
            s: sig.z,
        })
        //}
    }

    /// Verify a BIP-340 schnorr proof
    #[allow(non_snake_case)]
    pub fn verify(&self, public_key: &field::Element, msg: &[u8]) -> bool {
        let Y = match Point::lift_x(public_key) {
            Ok(Y) => Y,
            Err(_) => return false,
        };
        let R = match Point::lift_x(&self.r) {
            Ok(R) => R,
            Err(_) => return false,
        };
        let c = compute::challenge(&Y, &R, msg);
        let Rp = self.s * G - c * Y;

        Rp.has_even_y() && Rp.x() == self.r
    }

    /// Serialize this proof into a 64-byte buffer
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];

        bytes[0..32].copy_from_slice(&self.r.to_bytes());
        bytes[32..64].copy_from_slice(&self.s.to_bytes());

        bytes
    }
}

impl From<[u8; 64]> for SchnorrProof {
    fn from(bytes: [u8; 64]) -> Self {
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];

        r_bytes.copy_from_slice(&bytes[0..32]);
        s_bytes.copy_from_slice(&bytes[32..64]);

        Self {
            r: field::Element::from(r_bytes),
            s: Scalar::from(s_bytes),
        }
    }
}

/// Helper functions for tests
pub mod test_helpers {
    use crate::{
        common::{PolyCommitment, PublicNonce, SignatureShare},
        compute,
        errors::DkgError,
        traits, Point,
    };

    use hashbrown::HashMap;
    use rand_core::{CryptoRng, RngCore};

    /// Run a distributed key generation round
    #[allow(non_snake_case)]
    pub fn dkg<RNG: RngCore + CryptoRng, Signer: traits::Signer>(
        signers: &mut [Signer],
        rng: &mut RNG,
        merkle_root: Option<[u8; 32]>,
    ) -> Result<Vec<PolyCommitment>, HashMap<u32, DkgError>> {
        let mut A: Vec<PolyCommitment> = signers
            .iter()
            .flat_map(|s| s.get_poly_commitments(rng))
            .collect();

        // keep trying until the group key has even y coord
        loop {
            let group_key = A.iter().fold(Point::new(), |s, a| s + a.A[0]);
            if group_key.has_even_y() {
                let tweaked = compute::tweaked_public_key(&group_key, merkle_root);
                if tweaked.has_even_y() {
                    break;
                }
            }

            for signer in signers.iter_mut() {
                signer.reset_polys(rng);
            }

            A = signers
                .iter()
                .flat_map(|s| s.get_poly_commitments(rng))
                .collect();
        }

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

    #[allow(non_snake_case)]
    fn sign_params<RNG: RngCore + CryptoRng, Signer: traits::Signer>(
        _msg: &[u8],
        signers: &mut [Signer],
        rng: &mut RNG,
    ) -> (Vec<u32>, Vec<u32>, Vec<PublicNonce>) {
        let signer_ids: Vec<u32> = signers.iter().map(|s| s.get_id()).collect();
        let key_ids: Vec<u32> = signers.iter().flat_map(|s| s.get_key_ids()).collect();
        let nonces: Vec<PublicNonce> = signers.iter_mut().flat_map(|s| s.gen_nonces(rng)).collect();

        (signer_ids, key_ids, nonces)
    }

    /// Run a signing round for the passed `msg`
    #[allow(non_snake_case)]
    pub fn sign<RNG: RngCore + CryptoRng, Signer: traits::Signer>(
        msg: &[u8],
        signers: &mut [Signer],
        rng: &mut RNG,
        merkle_root: Option<[u8; 32]>,
    ) -> (Vec<PublicNonce>, Vec<SignatureShare>) {
        let (signer_ids, key_ids, nonces) = sign_params(msg, signers, rng);
        let shares = signers
            .iter()
            .flat_map(|s| s.sign_taproot(msg, &signer_ids, &key_ids, &nonces, merkle_root))
            .collect();

        (nonces, shares)
    }
}

#[cfg(test)]
mod test {
    use super::{test_helpers, SchnorrProof};

    use crate::{compute, traits::Signer, v1, v2};
    use rand_core::OsRng;

    #[test]
    #[allow(non_snake_case)]
    fn test_taproot_sign_verify_v1() {
        let script = "OP_1".as_bytes();
        let merkle_root = compute::merkle_root(script);

        taproot_sign_verify_v1(Some(merkle_root));
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_taproot_sign_verify_v1_no_merkle_root() {
        taproot_sign_verify_v1(None);
    }

    #[allow(non_snake_case)]
    fn taproot_sign_verify_v1(merkle_root: Option<[u8; 32]>) {
        let mut rng = OsRng::default();

        // First create and verify a frost signature
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

        let A = match test_helpers::dkg(&mut signers, &mut rng, merkle_root) {
            Ok(A) => A,
            Err(secret_errors) => {
                panic!("Got secret errors from DKG: {:?}", secret_errors);
            }
        };

        let mut S = [signers[0].clone(), signers[1].clone(), signers[3].clone()].to_vec();
        let mut sig_agg =
            v1::SignatureAggregator::new(N, T, A.clone()).expect("aggregator ctor failed");

        let (nonces, sig_shares) = test_helpers::sign(&msg, &mut S, &mut rng, merkle_root);
        let (tweaked_public_key, proof) =
            match sig_agg.sign_taproot(&msg, &nonces, &sig_shares, merkle_root) {
                Err(e) => panic!("Aggregator sign failed: {:?}", e),
                Ok((key, proof)) => (key, proof),
            };

        assert!(proof.verify(&tweaked_public_key.x(), msg));

        // now ser/de the proof
        let proof_bytes = proof.to_bytes();
        let proof_deser = SchnorrProof::from(proof_bytes);

        assert_eq!(proof, proof_deser);
        assert!(proof_deser.verify(&tweaked_public_key.x(), msg));
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_taproot_sign_verify_v2() {
        let script = "OP_1".as_bytes();
        let merkle_root = compute::merkle_root(script);

        taproot_sign_verify_v2(Some(merkle_root));
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_taproot_sign_verify_v2_no_merkle_root() {
        taproot_sign_verify_v2(None);
    }

    #[allow(non_snake_case)]
    fn taproot_sign_verify_v2(merkle_root: Option<[u8; 32]>) {
        let mut rng = OsRng::default();

        // First create and verify a frost signature
        let msg = "It was many and many a year ago".as_bytes();
        let Nk: u32 = 10;
        let Np: u32 = 4;
        let T: u32 = 7;
        let signer_ids: Vec<Vec<u32>> = [
            [0, 1, 2].to_vec(),
            [3, 4].to_vec(),
            [5, 6, 7].to_vec(),
            [8, 9].to_vec(),
        ]
        .to_vec();
        let mut signers: Vec<v2::Signer> = signer_ids
            .iter()
            .enumerate()
            .map(|(id, ids)| v2::Signer::new(id.try_into().unwrap(), ids, Np, Nk, T, &mut rng))
            .collect();

        let A = match test_helpers::dkg(&mut signers, &mut rng, merkle_root) {
            Ok(A) => A,
            Err(secret_errors) => {
                panic!("Got secret errors from DKG: {:?}", secret_errors);
            }
        };

        let mut S = [signers[0].clone(), signers[1].clone(), signers[3].clone()].to_vec();
        let key_ids = S.iter().flat_map(|s| s.get_key_ids()).collect::<Vec<u32>>();
        let mut sig_agg =
            v2::SignatureAggregator::new(Nk, T, A.clone()).expect("aggregator ctor failed");
        let (nonces, sig_shares) = test_helpers::sign(&msg, &mut S, &mut rng, merkle_root);
        let (tweaked_public_key, proof) =
            match sig_agg.sign_taproot(&msg, &nonces, &sig_shares, &key_ids, merkle_root) {
                Err(e) => panic!("Aggregator sign failed: {:?}", e),
                Ok((key, proof)) => (key, proof),
            };

        assert!(proof.verify(&tweaked_public_key.x(), msg));

        // now ser/de the proof
        let proof_bytes = proof.to_bytes();
        let proof_deser = SchnorrProof::from(proof_bytes);

        assert_eq!(proof, proof_deser);
        assert!(proof_deser.verify(&tweaked_public_key.x(), msg));
    }
}
