use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    common::{MerkleRoot, PolyCommitment, PublicNonce, SignatureShare},
    curve::{ecdsa, scalar::Scalar},
};

/// Trait to encapsulate sign/verify, users only need to impl hash
pub trait Signable {
    /// Hash this object in a consistent way so it can be signed/verified
    fn hash(&self, hasher: &mut Sha256);

    /// Sign a hash of this object using the passed private key
    fn sign(&self, private_key: &Scalar) -> Result<Vec<u8>, ecdsa::Error> {
        let mut hasher = Sha256::new();

        self.hash(&mut hasher);

        let hash = hasher.finalize();
        match ecdsa::Signature::new(hash.as_slice(), private_key) {
            Ok(sig) => Ok(sig.to_bytes().to_vec()),
            Err(e) => Err(e),
        }
    }

    /// Verify a hash of this object using the passed public key
    fn verify(&self, signature: &[u8], public_key: &ecdsa::PublicKey) -> bool {
        let mut hasher = Sha256::new();

        self.hash(&mut hasher);

        let hash = hasher.finalize();
        let sig = match ecdsa::Signature::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        sig.verify(hash.as_slice(), public_key)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
/// Final DKG status after receiving public and private shares
pub enum DkgStatus {
    /// DKG completed successfully
    Success,
    /// DKG failed with error
    Failure(String),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
/// Encapsulation of all possible network message types
pub enum Message {
    /// Tell signers to begin DKG by sending DKG public shares
    DkgBegin(DkgBegin),
    /// Send DKG public shares
    DkgPublicShares(DkgPublicShares),
    /// Tell signers to send DKG private shares
    DkgPrivateBegin(DkgBegin),
    /// Send DKG private shares
    DkgPrivateShares(DkgPrivateShares),
    /// Tell coordinator that DKG is complete
    DkgEnd(DkgEnd),
    /// Tell signers to send signing nonces
    NonceRequest(NonceRequest),
    /// Tell coordinator signing nonces
    NonceResponse(NonceResponse),
    /// Tell signers to construct signature shares
    SignatureShareRequest(SignatureShareRequest),
    /// Tell coordinator signature shares
    SignatureShareResponse(SignatureShareResponse),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
/// DKG begin message from coordinator to signers
pub struct DkgBegin {
    /// DKG round ID
    pub dkg_id: u64,
}

impl Signable for DkgBegin {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_BEGIN".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
/// DKG public shares message from signer to all signers and coordinator
pub struct DkgPublicShares {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// List of (party_id, commitment)
    pub comms: Vec<(u32, PolyCommitment)>,
}

impl Signable for DkgPublicShares {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_PUBLIC_SHARES".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());
        for (party_id, comm) in &self.comms {
            hasher.update(party_id.to_be_bytes());
            for a in &comm.poly {
                hasher.update(a.compress().as_bytes());
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
/// DKG private shares message from signer to all signers and coordinator
pub struct DkgPrivateShares {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// List of (src_key_id, Map(dst_key_id, encrypted_share))
    pub shares: Vec<(u32, HashMap<u32, Vec<u8>>)>,
}

impl Signable for DkgPrivateShares {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_PRIVATE_SHARES".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());
        // make sure we iterate sequentially
        for (src_id, share) in &self.shares {
            hasher.update(src_id.to_be_bytes());
            for dst_id in 0..share.len() as u32 {
                hasher.update(dst_id.to_be_bytes());
                hasher.update(&share[&dst_id]);
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
/// DKG end message from signers to coordinator
pub struct DkgEnd {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// DKG status for this Signer after receiving public/private shares
    pub status: DkgStatus,
}

impl Signable for DkgEnd {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_END".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
/// Nonce request message from coordinator to signers
pub struct NonceRequest {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
}

impl Signable for NonceRequest {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("NONCE_REQUEST".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());
        hasher.update(self.sign_iter_id.to_be_bytes());
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
/// Nonce response message from signers to coordinator
pub struct NonceResponse {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// Key IDs
    pub key_ids: Vec<u32>,
    /// Public nonces
    pub nonces: Vec<PublicNonce>,
}

impl Signable for NonceResponse {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("NONCE_RESPONSE".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());
        hasher.update(self.sign_iter_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());

        for key_id in &self.key_ids {
            hasher.update(key_id.to_be_bytes());
        }

        for nonce in &self.nonces {
            hasher.update(nonce.D.compress().as_bytes());
            hasher.update(nonce.E.compress().as_bytes());
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
/// Signature share request message from coordinator to signers
pub struct SignatureShareRequest {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// Nonces responses used for this signature
    pub nonce_responses: Vec<NonceResponse>,
    /// Bytes to sign
    pub message: Vec<u8>,
    /// Whether to make a taproot signature
    pub is_taproot: bool,
    /// Taproot merkle root
    pub merkle_root: Option<MerkleRoot>,
}

impl Signable for SignatureShareRequest {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("SIGNATURE_SHARE_REQUEST".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());

        for nonce_response in &self.nonce_responses {
            nonce_response.hash(hasher);
        }

        hasher.update(self.message.as_slice());

        hasher.update((self.is_taproot as u16).to_be_bytes());
        if let Some(merkle_root) = self.merkle_root {
            hasher.update(merkle_root);
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
/// Signature share response message from signers to coordinator
pub struct SignatureShareResponse {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// Signature shares from this Signer
    pub signature_shares: Vec<SignatureShare>,
}

impl Signable for SignatureShareResponse {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("SIGNATURE_SHARE_RESPONSE".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());

        for signature_share in &self.signature_shares {
            hasher.update(signature_share.id.to_be_bytes());
            hasher.update(signature_share.z_i.to_bytes());
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Network packets need to be signed so they can be verified
pub struct Packet {
    /// The message to sign
    pub msg: Message,
    /// The bytes of the signature
    pub sig: Vec<u8>,
}
