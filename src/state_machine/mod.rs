use hashbrown::HashMap;
use thiserror::Error;

use crate::{
    common::Signature,
    ecdsa,
    errors::{AggregatorError, DkgError as DkgCryptoError},
    taproot::SchnorrProof,
    Point,
};

/// A generic state machine
pub trait StateMachine<S, E> {
    /// Attempt to move the state machine to a new state
    fn move_to(&mut self, state: S) -> Result<(), E>;
    /// Check if the state machine can move to a new state
    fn can_move_to(&self, state: &S) -> Result<(), E>;
}

/// DKG errors
#[derive(Error, Debug, Clone)]
pub enum DkgError {
    /// DKG public timeout
    #[error("DKG public timeout, waiting for {0:?}")]
    DkgPublicTimeout(Vec<u32>),
    /// DKG end timeout
    #[error("DKG end timeout, waiting for {0:?}")]
    DkgEndTimeout(Vec<u32>),
    /// DKG crypto error
    #[error("DKG crypto error")]
    Crypto(#[from] DkgCryptoError),
}

/// Sign errors
#[derive(Error, Debug, Clone)]
pub enum SignError {
    /// Nonce timeout
    #[error("Nonce timeout, valid responses from {0:?}, signers {1:?} are malicious")]
    NonceTimeout(Vec<u32>, Vec<u32>),
    /// Insufficient signers
    #[error("Insufficient signers, {0:?} are malicious")]
    InsufficientSigners(Vec<u32>),
    /// Signature aggregator error
    #[error("Signature aggregator error")]
    Aggregator(#[from] AggregatorError),
}

/// Result of a DKG or sign operation
pub enum OperationResult {
    /// DKG succeeded with the wrapped public key
    Dkg(Point),
    /// Sign succeeded with the wrapped Signature
    Sign(Signature),
    /// Sign taproot succeeded with the wrapped SchnorrProof
    SignTaproot(SchnorrProof),
    /// DKG error
    DkgError(DkgError),
    /// Sign error
    SignError(SignError),
}

#[derive(Default, Clone, Debug)]
/// Map of signer_id and key_id to the relevant ecdsa public keys
pub struct PublicKeys {
    /// signer_id -> public key
    pub signers: HashMap<u32, ecdsa::PublicKey>,
    /// key_id -> public key
    pub key_ids: HashMap<u32, ecdsa::PublicKey>,
}

/// State machine for a simple FROST coordinator
pub mod coordinator;

/// State machine for signers
pub mod signer;
