use core::{cmp::PartialEq, fmt::Debug};
use hashbrown::HashMap;
use polynomial::Polynomial;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    common::{MerkleRoot, Nonce, PolyCommitment, PublicNonce, Signature, SignatureShare},
    curve::{point::Point, scalar::Scalar},
    errors::{AggregatorError, DkgError},
    taproot::SchnorrProof,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
/// The saved state required to reconstruct a party
pub struct PartyState {
    /// The party's private polynomial
    pub polynomial: Polynomial<Scalar>,
    /// The key IDS and associate private keys for this party
    pub private_keys: Vec<(u32, Scalar)>,
    /// The nonce being used by this party
    pub nonce: Nonce,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
/// The saved state required to reconstruct a signer
pub struct SignerState {
    /// The signer ID
    pub id: u32,
    /// The key IDs this signer controls
    pub key_ids: Vec<u32>,
    /// The total number of keys
    pub num_keys: u32,
    /// The total number of parties
    pub num_parties: u32,
    /// The threshold for signing
    pub threshold: u32,
    /// The aggregate group public key
    pub group_key: Point,
    /// The party IDs and associated state for this signer
    pub parties: Vec<(u32, PartyState)>,
}

/// A trait which provides a common `Signer` interface for `v1` and `v2`
pub trait Signer: Clone + Debug + PartialEq {
    /// Create a new `Signer`
    fn new<RNG: RngCore + CryptoRng>(
        party_id: u32,
        key_ids: &[u32],
        num_signers: u32,
        num_keys: u32,
        threshold: u32,
        rng: &mut RNG,
    ) -> Self;

    /// Load a signer from the previously saved `state`
    fn load(state: &SignerState) -> Self;

    /// Save the state required to reconstruct the party
    fn save(&self) -> SignerState;

    /// Get the signer ID for this signer
    fn get_id(&self) -> u32;

    /// Get all key IDs for this signer
    fn get_key_ids(&self) -> Vec<u32>;

    /// Get the total number of parties
    fn get_num_parties(&self) -> u32;

    /// Get all poly commitments for this signer
    fn get_poly_commitments<RNG: RngCore + CryptoRng>(&self, rng: &mut RNG) -> Vec<PolyCommitment>;

    /// Reset all poly commitments for this signer
    fn reset_polys<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG);

    /// Get all private shares for this signer
    fn get_shares(&self) -> HashMap<u32, HashMap<u32, Scalar>>;

    /// Compute all secrets for this signer
    fn compute_secrets(
        &mut self,
        shares: &HashMap<u32, HashMap<u32, Scalar>>,
        polys: &HashMap<u32, PolyCommitment>,
    ) -> Result<(), HashMap<u32, DkgError>>;

    /// Generate all nonces for this signer
    fn gen_nonces<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG) -> Vec<PublicNonce>;

    /// Compute intermediate values
    fn compute_intermediate(
        msg: &[u8],
        signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> (Vec<Point>, Point);

    /// Sign `msg` using all this signer's keys
    fn sign(
        &self,
        msg: &[u8],
        signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> Vec<SignatureShare>;

    /// Sign `msg` using all this signer's keys and a tweaked public key
    fn sign_taproot(
        &self,
        msg: &[u8],
        signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
        merkle_root: Option<MerkleRoot>,
    ) -> Vec<SignatureShare>;
}

/// A trait which provides a common `Aggregator` interface for `v1` and `v2`
pub trait Aggregator: Clone + Debug + PartialEq {
    /// Construct an Aggregator with the passed parameters
    fn new(num_keys: u32, threshold: u32) -> Self;

    /// Initialize an Aggregator with the passed polynomial commitments
    fn init(&mut self, poly_comms: &HashMap<u32, PolyCommitment>) -> Result<(), AggregatorError>;

    /// Check and aggregate the signature shares into a `Signature`
    fn sign(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[u32],
    ) -> Result<Signature, AggregatorError>;

    /// Check and aggregate the signature shares into a `SchnorrProof`
    fn sign_taproot(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[u32],
        merkle_root: Option<MerkleRoot>,
    ) -> Result<SchnorrProof, AggregatorError>;
}
