use p256k1::point::Point;

use crate::{
    common::MerkleRoot, errors::AggregatorError, net::Packet, state_machine::OperationResult,
    Scalar,
};

#[derive(Clone, Debug, PartialEq)]
/// Coordinator states
pub enum State {
    /// The coordinator is idle
    Idle,
    /// The coordinator is distributing public shares
    DkgPublicDistribute,
    /// The coordinator is gathering public shares
    DkgPublicGather,
    /// The coordinator is distributing private shares
    DkgPrivateDistribute,
    /// The coordinator is gathering DKG End messages
    DkgEndGather,
    /// The coordinator is requesting nonces
    NonceRequest(bool, Option<MerkleRoot>),
    /// The coordinator is gathering nonces
    NonceGather(bool, Option<MerkleRoot>),
    /// The coordinator is requesting signature shares
    SigShareRequest(bool, Option<MerkleRoot>),
    /// The coordinator is gathering signature shares
    SigShareGather(bool, Option<MerkleRoot>),
}

#[derive(thiserror::Error, Debug)]
/// The error type for the coordinator
pub enum Error {
    /// A bad state change was made
    #[error("Bad State Change: {0}")]
    BadStateChange(String),
    /// A bad dkg_id in received message
    #[error("Bad dkg_id: got {0} expected {1}")]
    BadDkgId(u64, u64),
    /// A bad sign_id in received message
    #[error("Bad sign_id: got {0} expected {1}")]
    BadSignId(u64, u64),
    /// A bad sign_iter_id in received message
    #[error("Bad sign_iter_id: got {0} expected {1}")]
    BadSignIterId(u64, u64),
    /// SignatureAggregator error
    #[error("Aggregator: {0}")]
    Aggregator(AggregatorError),
    /// Schnorr proof failed to verify
    #[error("Schnorr Proof failed to verify")]
    SchnorrProofFailed,
    /// No aggregate public key set
    #[error("No aggregate public key set")]
    MissingAggregatePublicKey,
    /// No schnorr proof set
    #[error("No schnorr proof set")]
    MissingSchnorrProof,
    /// No signature set
    #[error("No signature set")]
    MissingSignature,
}

impl From<AggregatorError> for Error {
    fn from(err: AggregatorError) -> Self {
        Error::Aggregator(err)
    }
}

/// Coordinator trait for handling the coordination of DKG and sign messages
pub trait Coordinator {
    /// Create a new Coordinator
    fn new(
        total_signers: u32,
        total_keys: u32,
        threshold: u32,
        message_private_key: Scalar,
    ) -> Self;

    /// Process inbound messages
    fn process_inbound_messages(
        &mut self,
        packets: &[Packet],
    ) -> Result<(Vec<Packet>, Vec<OperationResult>), Error>;

    /// Retrieve the aggregate public key
    fn get_aggregate_public_key(&self) -> Option<Point>;

    /// Set the aggregate public key
    fn set_aggregate_public_key(&mut self, aggregate_public_key: Option<Point>);

    /// Retrive the current state
    fn get_state(&self) -> State;

    /// Set the current state
    fn set_state(&mut self, state: State);

    /// Trigger a DKG round
    fn start_dkg_round(&mut self) -> Result<Packet, Error>;

    /// Trigger a signing round
    fn start_signing_round(
        &mut self,
        message: &[u8],
        is_taproot: bool,
        merkle_root: Option<MerkleRoot>,
    ) -> Result<Packet, Error>;

    /// Reset internal state
    fn reset(&mut self);
}

/// The coordinator for the FROST algorithm
pub mod frost;

/// The coordinator for the FIRE algorithm
pub mod fire;
