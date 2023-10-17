use hashbrown::HashMap;

use crate::{common::Signature, ecdsa, taproot::SchnorrProof, Point};

/// A generic state machine
pub trait StateMachine<S, E> {
    /// Attempt to move the state machine to a new state
    fn move_to(&mut self, state: S) -> Result<(), E>;
    /// Check if the state machine can move to a new state
    fn can_move_to(&self, state: &S) -> Result<(), E>;
}

/// Result of a DKG or sign operation
pub enum OperationResult {
    /// The DKG result
    Dkg(Point),
    /// The sign result
    Sign(Signature),
    /// The sign taproot result
    SignTaproot(SchnorrProof),
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
