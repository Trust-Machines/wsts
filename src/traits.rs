use hashbrown::HashMap;
use p256k1::{point::Point, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};

use crate::{
    common::{PolyCommitment, PublicNonce, SignatureShare},
    errors::DkgError,
};

/// A trait which provides a common interface for `v1` and `v2`
pub trait Signer {
    /// Get the signer ID for this signer
    fn get_id(&self) -> usize;

    /// Get all key IDs for this signer
    fn get_key_ids(&self) -> Vec<usize>;

    /// Get all poly commitments for this signer
    fn get_poly_commitments<RNG: RngCore + CryptoRng>(&self, rng: &mut RNG) -> Vec<PolyCommitment>;

    /// Reset all poly commitments for this signer
    fn reset_polys<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG);

    /// Get all private shares for this signer
    fn get_shares(&self) -> HashMap<usize, HashMap<usize, Scalar>>;

    /// Compute all secrets for this signer
    fn compute_secrets(
        &mut self,
        shares: &HashMap<usize, HashMap<usize, Scalar>>,
        polys: &[PolyCommitment],
    ) -> Result<(), HashMap<usize, DkgError>>;

    /// Generate all nonces for this signer
    fn gen_nonces<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG) -> Vec<PublicNonce>;

    /// Compute intermediate values
    fn compute_intermediate(
        msg: &[u8],
        signer_ids: &[usize],
        key_ids: &[usize],
        nonces: &[PublicNonce],
    ) -> (Vec<Point>, Point);

    /// Sign `msg` using all this signer's keys
    fn sign(
        &self,
        msg: &[u8],
        signer_ids: &[usize],
        key_ids: &[usize],
        nonces: &[PublicNonce],
    ) -> Vec<SignatureShare>;
}
