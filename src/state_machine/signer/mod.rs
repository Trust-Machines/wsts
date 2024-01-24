use hashbrown::{HashMap, HashSet};
use rand_core::{CryptoRng, OsRng, RngCore};
use std::collections::BTreeMap;
use tracing::{debug, info, trace, warn};

use crate::{
    common::{PolyCommitment, PublicNonce},
    curve::{
        point::{Compressed, Point},
        scalar::Scalar,
    },
    net::{
        DkgBegin, DkgEnd, DkgEndBegin, DkgPrivateBegin, DkgPrivateShares, DkgPublicShares,
        DkgStatus, Message, NonceRequest, NonceResponse, Packet, Signable, SignatureShareRequest,
        SignatureShareResponse,
    },
    state_machine::{PublicKeys, StateMachine},
    traits::Signer as SignerTrait,
    util::{decrypt, encrypt, make_shared_secret},
};

#[derive(Debug, Clone, PartialEq)]
/// Signer states
pub enum State {
    /// The signer is idle
    Idle,
    /// The signer is distributing DKG public shares
    DkgPublicDistribute,
    /// The signer is gathering DKG public shares
    DkgPublicGather,
    /// The signer is distributing DKG private shares
    DkgPrivateDistribute,
    /// The signer is gathering DKG private shares
    DkgPrivateGather,
    /// The signer is distributing signature shares
    SignGather,
    /// The signer is finished signing
    Signed,
}

#[derive(thiserror::Error, Clone, Debug)]
/// The error type for a signer
pub enum Error {
    /// The party ID was invalid
    #[error("InvalidPartyID")]
    InvalidPartyID,
    /// A DKG public share was invalid
    #[error("InvalidDkgPublicShares")]
    InvalidDkgPublicShares,
    /// A DKG private share was invalid
    #[error("InvalidDkgPrivateShares")]
    InvalidDkgPrivateShares(Vec<u32>),
    /// A nonce response was invalid
    #[error("InvalidNonceResponse")]
    InvalidNonceResponse,
    /// A signature share was invalid
    #[error("InvalidSignatureShare")]
    InvalidSignatureShare,
    /// A bad state change was made
    #[error("Bad State Change: {0}")]
    BadStateChange(String),
}

/// A state machine for a signing round
#[derive(Clone)]
pub struct Signer<SignerType: SignerTrait> {
    /// current DKG round ID
    pub dkg_id: u64,
    /// current signing round ID
    pub sign_id: u64,
    /// current signing iteration ID
    pub sign_iter_id: u64,
    /// the threshold of the keys needed for a valid signature
    pub threshold: u32,
    /// the total number of signers
    pub total_signers: u32,
    /// the total number of keys
    pub total_keys: u32,
    /// the Signer object
    pub signer: SignerType,
    /// the Signer ID
    pub signer_id: u32,
    /// the current state
    pub state: State,
    /// map of party_id to the polynomial commitment for that party
    pub commitments: HashMap<u32, PolyCommitment>,
    /// map of decrypted DKG private shares
    pub decrypted_shares: HashMap<u32, HashMap<u32, Scalar>>,
    /// invalid private shares
    pub invalid_private_shares: Vec<u32>,
    /// public nonces for this signing round
    pub public_nonces: Vec<PublicNonce>,
    /// the private key used to sign messages sent over the network
    pub network_private_key: Scalar,
    /// the public keys for all signers and coordinator
    pub public_keys: PublicKeys,
    /// the DKG public shares received in this round
    pub dkg_public_shares: BTreeMap<u32, DkgPublicShares>,
    /// the DKG private shares received in this round
    pub dkg_private_shares: BTreeMap<u32, DkgPrivateShares>,
    /// the DKG private begin message received in this round
    pub dkg_private_begin_msg: Option<DkgPrivateBegin>,
    /// the DKG end begin message received in this round
    pub dkg_end_begin_msg: Option<DkgEndBegin>,
}

impl<SignerType: SignerTrait> Signer<SignerType> {
    /// create a Signer
    pub fn new(
        threshold: u32,
        total_signers: u32,
        total_keys: u32,
        signer_id: u32,
        key_ids: Vec<u32>,
        network_private_key: Scalar,
        public_keys: PublicKeys,
    ) -> Self {
        assert!(threshold <= total_keys);
        let mut rng = OsRng;
        let signer = SignerType::new(
            signer_id,
            &key_ids,
            total_signers,
            total_keys,
            threshold,
            &mut rng,
        );
        debug!(
            "new Signer for signer_id {} with key_ids {:?}",
            signer_id, &key_ids
        );
        Signer {
            dkg_id: 0,
            sign_id: 1,
            sign_iter_id: 1,
            threshold,
            total_signers,
            total_keys,
            signer,
            signer_id,
            state: State::Idle,
            commitments: Default::default(),
            decrypted_shares: HashMap::new(),
            invalid_private_shares: Vec::new(),
            public_nonces: vec![],
            network_private_key,
            public_keys,
            dkg_public_shares: Default::default(),
            dkg_private_shares: Default::default(),
            dkg_private_begin_msg: Default::default(),
            dkg_end_begin_msg: Default::default(),
        }
    }

    /// Reset internal state
    pub fn reset<T: RngCore + CryptoRng>(&mut self, dkg_id: u64, rng: &mut T) {
        self.dkg_id = dkg_id;
        self.commitments.clear();
        self.decrypted_shares.clear();
        self.invalid_private_shares.clear();
        self.public_nonces.clear();
        self.signer.reset_polys(rng);
        self.dkg_public_shares.clear();
        self.dkg_private_shares.clear();
        self.dkg_private_begin_msg = None;
        self.dkg_end_begin_msg = None;
        self.state = State::Idle;
    }

    ///
    pub fn process_inbound_messages(&mut self, messages: &[Packet]) -> Result<Vec<Packet>, Error> {
        let mut responses = vec![];
        for message in messages {
            let outbounds = self.process(&message.msg)?;
            for out in outbounds {
                let msg = Packet {
                    sig: match &out {
                        Message::DkgBegin(msg) => msg
                            .sign(&self.network_private_key)
                            .expect("failed to sign DkgBegin")
                            .to_vec(),
                        Message::DkgPrivateBegin(msg) => msg
                            .sign(&self.network_private_key)
                            .expect("failed to sign DkgPrivateBegin")
                            .to_vec(),
                        Message::DkgEndBegin(msg) => msg
                            .sign(&self.network_private_key)
                            .expect("failed to sign DkgEndBegin")
                            .to_vec(),
                        Message::DkgEnd(msg) => msg
                            .sign(&self.network_private_key)
                            .expect("failed to sign DkgEnd")
                            .to_vec(),
                        Message::DkgPublicShares(msg) => msg
                            .sign(&self.network_private_key)
                            .expect("failed to sign DkgPublicShares")
                            .to_vec(),
                        Message::DkgPrivateShares(msg) => msg
                            .sign(&self.network_private_key)
                            .expect("failed to sign DkgPrivateShare")
                            .to_vec(),
                        Message::NonceRequest(msg) => msg
                            .sign(&self.network_private_key)
                            .expect("failed to sign NonceRequest")
                            .to_vec(),
                        Message::NonceResponse(msg) => msg
                            .sign(&self.network_private_key)
                            .expect("failed to sign NonceResponse")
                            .to_vec(),
                        Message::SignatureShareRequest(msg) => msg
                            .sign(&self.network_private_key)
                            .expect("failed to sign SignShareRequest")
                            .to_vec(),
                        Message::SignatureShareResponse(msg) => msg
                            .sign(&self.network_private_key)
                            .expect("failed to sign SignShareResponse")
                            .to_vec(),
                    },
                    msg: out,
                };
                responses.push(msg);
            }
        }
        Ok(responses)
    }

    /// process the passed incoming message, and return any outgoing messages needed in response
    pub fn process(&mut self, message: &Message) -> Result<Vec<Message>, Error> {
        let out_msgs = match message {
            Message::DkgBegin(dkg_begin) => self.dkg_begin(dkg_begin),
            Message::DkgPrivateBegin(dkg_private_begin) => {
                self.dkg_private_begin(dkg_private_begin)
            }
            Message::DkgEndBegin(dkg_end_begin) => self.dkg_end_begin(dkg_end_begin),
            Message::DkgPublicShares(dkg_public_shares) => self.dkg_public_share(dkg_public_shares),
            Message::DkgPrivateShares(dkg_private_shares) => {
                self.dkg_private_shares(dkg_private_shares)
            }
            Message::SignatureShareRequest(sign_share_request) => {
                self.sign_share_request(sign_share_request)
            }
            Message::NonceRequest(nonce_request) => self.nonce_request(nonce_request),
            _ => Ok(vec![]), // TODO
        };

        match out_msgs {
            Ok(mut out) => {
                if self.can_dkg_end() {
                    let dkg_end_msgs = self.dkg_ended()?;
                    out.push(dkg_end_msgs);
                    self.move_to(State::Idle)?;
                }
                Ok(out)
            }
            Err(e) => Err(e),
        }
    }

    /// DKG is done so compute secrets
    pub fn dkg_ended(&mut self) -> Result<Message, Error> {
        if !self.can_dkg_end() {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure("Bad state".to_string()),
            }));
        }

        // only use the public shares from the DkgEndBegin signers
        if let Some(dkg_end_begin) = &self.dkg_end_begin_msg {
            for signer_id in &dkg_end_begin.signer_ids {
                let shares = &self.dkg_public_shares[signer_id];
                for (party_id, comm) in shares.comms.iter() {
                    self.commitments.insert(*party_id, comm.clone());
                }
            }
        }

        let dkg_end = if self.invalid_private_shares.is_empty() {
            match self
                .signer
                .compute_secrets(&self.decrypted_shares, &self.commitments)
            {
                Ok(()) => DkgEnd {
                    dkg_id: self.dkg_id,
                    signer_id: self.signer_id,
                    status: DkgStatus::Success,
                },
                Err(dkg_error_map) => DkgEnd {
                    dkg_id: self.dkg_id,
                    signer_id: self.signer_id,
                    status: DkgStatus::Failure(format!("{:?}", dkg_error_map)),
                },
            }
        } else {
            DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(format!("{:?}", self.invalid_private_shares)),
            }
        };

        info!(
            "Signer {} sending DkgEnd round {} status {:?}",
            self.signer_id, self.dkg_id, dkg_end.status,
        );

        let dkg_end = Message::DkgEnd(dkg_end);
        Ok(dkg_end)
    }

    /// do we have all DkgPublicShares?
    pub fn public_shares_done(&self) -> bool {
        debug!(
            "public_shares_done state {:?} commitments {}",
            self.state,
            self.commitments.len(),
        );
        self.state == State::DkgPublicGather
            && self.commitments.len() == usize::try_from(self.signer.get_num_parties()).unwrap()
    }

    /// do we have all DkgPublicShares and DkgPrivateShares?
    pub fn can_dkg_end(&self) -> bool {
        debug!(
            "can_dkg_end: state {:?} DkgPrivateBegin {} DkgEndBegin {}",
            self.state,
            self.dkg_private_begin_msg.is_some(),
            self.dkg_end_begin_msg.is_some(),
        );

        if self.state == State::DkgPrivateGather {
            if let Some(dkg_private_begin) = &self.dkg_private_begin_msg {
                // need public shares from active signers
                for signer_id in &dkg_private_begin.signer_ids {
                    if !self.dkg_public_shares.contains_key(signer_id) {
                        debug!(
                            "can_dkg_end: false, missing public shares from signer {}",
                            signer_id
                        );
                        return false;
                    }
                }

                if let Some(dkg_end_begin) = &self.dkg_end_begin_msg {
                    // need private shares from active signers
                    for signer_id in &dkg_end_begin.signer_ids {
                        if !self.dkg_private_shares.contains_key(signer_id) {
                            debug!(
                                "can_dkg_end: false, missing private shares from signer {}",
                                signer_id
                            );
                            return false;
                        }
                    }
                    debug!("can_dkg_end: true");

                    return true;
                }
            }
        } else {
            debug!("can_dkg_end: false, bad state {:?}", self.state);
            return false;
        }
        false
    }

    fn nonce_request(&mut self, nonce_request: &NonceRequest) -> Result<Vec<Message>, Error> {
        let mut rng = OsRng;
        let mut msgs = vec![];
        let signer_id = self.signer_id;
        let key_ids = self.signer.get_key_ids();
        let nonces = self.signer.gen_nonces(&mut rng);

        let response = NonceResponse {
            dkg_id: nonce_request.dkg_id,
            sign_id: nonce_request.sign_id,
            sign_iter_id: nonce_request.sign_iter_id,
            signer_id,
            key_ids,
            nonces,
            message: nonce_request.message.clone(),
        };

        let response = Message::NonceResponse(response);

        info!(
            "Signer {} sending NonceResponse for DKG round {} sign round {} sign iteration {}",
            signer_id, nonce_request.dkg_id, nonce_request.sign_id, nonce_request.sign_iter_id,
        );
        msgs.push(response);

        Ok(msgs)
    }

    fn sign_share_request(
        &mut self,
        sign_request: &SignatureShareRequest,
    ) -> Result<Vec<Message>, Error> {
        let mut msgs = vec![];

        let signer_ids = sign_request
            .nonce_responses
            .iter()
            .map(|nr| nr.signer_id)
            .collect::<Vec<u32>>();

        debug!("Got SignatureShareRequest for signer_ids {:?}", signer_ids);

        for signer_id in &signer_ids {
            if *signer_id == self.signer_id {
                let key_ids: Vec<u32> = sign_request
                    .nonce_responses
                    .iter()
                    .flat_map(|nr| nr.key_ids.iter().copied())
                    .collect::<Vec<u32>>();
                let nonces = sign_request
                    .nonce_responses
                    .iter()
                    .flat_map(|nr| nr.nonces.clone())
                    .collect::<Vec<PublicNonce>>();
                let signature_shares = if sign_request.is_taproot {
                    self.signer.sign_taproot(
                        &sign_request.message,
                        &signer_ids,
                        &key_ids,
                        &nonces,
                        sign_request.merkle_root,
                    )
                } else {
                    self.signer
                        .sign(&sign_request.message, &signer_ids, &key_ids, &nonces)
                };

                let response = SignatureShareResponse {
                    dkg_id: sign_request.dkg_id,
                    sign_id: sign_request.sign_id,
                    sign_iter_id: sign_request.sign_iter_id,
                    signer_id: *signer_id,
                    signature_shares,
                };

                info!(
                    "Signer {} sending SignatureShareResponse for DKG round {} sign round {} sign iteration {}",
                    signer_id, self.dkg_id, self.sign_id, self.sign_iter_id,
                );

                let response = Message::SignatureShareResponse(response);

                msgs.push(response);
            } else {
                debug!("SignatureShareRequest for {} dropped.", signer_id);
            }
        }
        Ok(msgs)
    }

    fn dkg_begin(&mut self, dkg_begin: &DkgBegin) -> Result<Vec<Message>, Error> {
        let mut rng = OsRng;

        self.reset(dkg_begin.dkg_id, &mut rng);
        self.move_to(State::DkgPublicDistribute)?;

        //let _party_state = self.signer.save();

        self.dkg_public_begin()
    }

    fn dkg_public_begin(&mut self) -> Result<Vec<Message>, Error> {
        let mut rng = OsRng;
        let mut msgs = vec![];
        let comms = self.signer.get_poly_commitments(&mut rng);

        info!(
            "Signer {} sending DkgPublicShares for round {}",
            self.signer.get_id(),
            self.dkg_id,
        );

        let mut public_share = DkgPublicShares {
            dkg_id: self.dkg_id,
            signer_id: self.signer_id,
            comms: Vec::new(),
        };

        for poly in &comms {
            public_share
                .comms
                .push((poly.id.id.get_u32(), poly.clone()));
        }

        let public_share = Message::DkgPublicShares(public_share);
        msgs.push(public_share);

        self.move_to(State::DkgPublicGather)?;
        Ok(msgs)
    }

    fn dkg_private_begin(
        &mut self,
        dkg_private_begin: &DkgPrivateBegin,
    ) -> Result<Vec<Message>, Error> {
        let mut rng = OsRng;
        let mut msgs = vec![];
        let mut private_shares = DkgPrivateShares {
            dkg_id: self.dkg_id,
            signer_id: self.signer_id,
            shares: Vec::new(),
        };
        let active_key_ids = dkg_private_begin
            .key_ids
            .iter()
            .cloned()
            .collect::<HashSet<u32>>();

        self.dkg_private_begin_msg = Some(dkg_private_begin.clone());
        self.move_to(State::DkgPrivateDistribute)?;

        info!(
            "Signer {} sending DkgPrivateShares for round {}",
            self.signer.get_id(),
            self.dkg_id,
        );

        trace!(
            "Signer {} shares {:?}",
            self.signer_id,
            &self.signer.get_shares()
        );
        for (key_id, shares) in &self.signer.get_shares() {
            debug!(
                "Signer {} addding dkg private share for key_id {}",
                self.signer_id, key_id
            );
            // encrypt each share for the recipient
            let mut encrypted_shares = HashMap::new();

            for (dst_key_id, private_share) in shares {
                if active_key_ids.contains(dst_key_id) {
                    debug!("encrypting dkg private share for key_id {}", dst_key_id);
                    let compressed =
                        Compressed::from(self.public_keys.key_ids[dst_key_id].to_bytes());
                    let dst_public_key = Point::try_from(&compressed).unwrap();
                    let shared_secret =
                        make_shared_secret(&self.network_private_key, &dst_public_key);
                    let encrypted_share =
                        encrypt(&shared_secret, &private_share.to_bytes(), &mut rng).unwrap();

                    encrypted_shares.insert(*dst_key_id, encrypted_share);
                }
            }

            private_shares.shares.push((*key_id, encrypted_shares));
        }

        let private_shares = Message::DkgPrivateShares(private_shares);
        msgs.push(private_shares);

        self.move_to(State::DkgPrivateGather)?;
        Ok(msgs)
    }

    /// handle incoming DkgEndBegin
    pub fn dkg_end_begin(&mut self, dkg_end_begin: &DkgEndBegin) -> Result<Vec<Message>, Error> {
        let msgs = vec![];

        self.dkg_end_begin_msg = Some(dkg_end_begin.clone());

        info!(
            "Signer {} received DkgEndBegin for round {}",
            self.signer.get_id(),
            self.dkg_id,
        );

        Ok(msgs)
    }

    /// handle incoming DkgPublicShares
    pub fn dkg_public_share(
        &mut self,
        dkg_public_shares: &DkgPublicShares,
    ) -> Result<Vec<Message>, Error> {
        debug!(
            "received DkgPublicShares from signer {} {}/{}",
            dkg_public_shares.signer_id,
            self.commitments.len(),
            self.signer.get_num_parties(),
        );
        self.dkg_public_shares
            .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
        Ok(vec![])
    }

    /// handle incoming DkgPrivateShares
    pub fn dkg_private_shares(
        &mut self,
        dkg_private_shares: &DkgPrivateShares,
    ) -> Result<Vec<Message>, Error> {
        // go ahead and decrypt here, since we know the signer_id and hence the pubkey of the sender
        self.dkg_private_shares
            .insert(dkg_private_shares.signer_id, dkg_private_shares.clone());

        // make a HashSet of our key_ids so we can quickly query them
        let key_ids: HashSet<u32> = self.signer.get_key_ids().into_iter().collect();
        let compressed =
            Compressed::from(self.public_keys.signers[&dkg_private_shares.signer_id].to_bytes());
        let public_key = Point::try_from(&compressed).unwrap();
        let shared_secret = make_shared_secret(&self.network_private_key, &public_key);

        for (src_id, shares) in &dkg_private_shares.shares {
            let mut decrypted_shares = HashMap::new();
            for (dst_key_id, bytes) in shares {
                if key_ids.contains(dst_key_id) {
                    match decrypt(&shared_secret, bytes) {
                        Ok(plain) => match Scalar::try_from(&plain[..]) {
                            Ok(s) => {
                                decrypted_shares.insert(*dst_key_id, s);
                            }
                            Err(e) => {
                                warn!("Failed to parse Scalar for dkg private share from src_id {} to dst_id {}: {:?}", src_id, dst_key_id, e);
                                self.invalid_private_shares.push(*src_id);
                            }
                        },
                        Err(e) => {
                            warn!("Failed to decrypt dkg private share from src_id {} to dst_id {}: {:?}", src_id, dst_key_id, e);
                            self.invalid_private_shares.push(*src_id);
                        }
                    }
                }
            }
            self.decrypted_shares.insert(*src_id, decrypted_shares);
        }
        debug!(
            "received DkgPrivateShares from signer {} {}/{}",
            dkg_private_shares.signer_id,
            self.decrypted_shares.len(),
            self.signer.get_num_parties(),
        );
        Ok(vec![])
    }
}

impl<SignerType: SignerTrait> StateMachine<State, Error> for Signer<SignerType> {
    fn move_to(&mut self, state: State) -> Result<(), Error> {
        self.can_move_to(&state)?;
        self.state = state;
        Ok(())
    }

    fn can_move_to(&self, state: &State) -> Result<(), Error> {
        let prev_state = &self.state;
        let accepted = match state {
            State::Idle => true,
            State::DkgPublicDistribute => {
                prev_state == &State::Idle
                    || prev_state == &State::DkgPublicGather
                    || prev_state == &State::DkgPrivateDistribute
            }
            State::DkgPublicGather => prev_state == &State::DkgPublicDistribute,
            State::DkgPrivateDistribute => prev_state == &State::DkgPublicGather,
            State::DkgPrivateGather => prev_state == &State::DkgPrivateDistribute,
            State::SignGather => prev_state == &State::Idle,
            State::Signed => prev_state == &State::SignGather,
        };
        if accepted {
            debug!("state change from {:?} to {:?}", prev_state, state);
            Ok(())
        } else {
            Err(Error::BadStateChange(format!(
                "{:?} to {:?}",
                prev_state, state
            )))
        }
    }
}

#[cfg(test)]
pub mod test {
    use rand_core::OsRng;

    use crate::{
        common::PolyCommitment,
        curve::{ecdsa, scalar::Scalar},
        net::{DkgBegin, DkgEndBegin, DkgPrivateBegin, DkgPublicShares, DkgStatus, Message},
        schnorr::ID,
        state_machine::{
            signer::{Signer, State as SignerState},
            PublicKeys,
        },
        traits::Signer as SignerTrait,
        v1, v2,
    };

    #[test]
    fn dkg_public_share_v1() {
        dkg_public_share::<v1::Signer>();
    }

    #[test]
    fn dkg_public_share_v2() {
        dkg_public_share::<v2::Signer>();
    }

    fn dkg_public_share<SignerType: SignerTrait>() {
        let mut rnd = OsRng;
        let mut signer =
            Signer::<SignerType>::new(1, 1, 1, 1, vec![1], Default::default(), Default::default());
        let public_share = DkgPublicShares {
            dkg_id: 0,
            signer_id: 0,
            comms: vec![(
                0,
                PolyCommitment {
                    id: ID::new(&Scalar::new(), &Scalar::new(), &mut rnd),
                    poly: vec![],
                },
            )],
        };
        signer.dkg_public_share(&public_share).unwrap();
        assert_eq!(1, signer.dkg_public_shares.len())
    }

    #[test]
    fn public_shares_done_v1() {
        public_shares_done::<v1::Signer>();
    }

    #[test]
    fn public_shares_done_v2() {
        public_shares_done::<v2::Signer>();
    }

    fn public_shares_done<SignerType: SignerTrait>() {
        let mut rnd = OsRng;
        let mut signer =
            Signer::<SignerType>::new(1, 1, 1, 1, vec![1], Default::default(), Default::default());
        // publich_shares_done starts out as false
        assert!(!signer.public_shares_done());

        // meet the conditions for all public keys received
        signer.state = SignerState::DkgPublicGather;
        signer.commitments.insert(
            1,
            PolyCommitment {
                id: ID::new(&Scalar::new(), &Scalar::new(), &mut rnd),
                poly: vec![],
            },
        );

        // public_shares_done should be true
        assert!(signer.public_shares_done());
    }

    #[test]
    fn can_dkg_end_v1() {
        can_dkg_end::<v1::Signer>();
    }

    #[test]
    fn can_dkg_end_v2() {
        can_dkg_end::<v2::Signer>();
    }

    fn can_dkg_end<SignerType: SignerTrait>() {
        let mut rnd = OsRng;
        let private_key = Scalar::random(&mut rnd);
        let public_key = ecdsa::PublicKey::new(&private_key).unwrap();
        let mut public_keys: PublicKeys = Default::default();

        public_keys.signers.insert(0, public_key.clone());
        public_keys.key_ids.insert(1, public_key.clone());

        let mut signer = Signer::<SignerType>::new(1, 1, 1, 0, vec![1], private_key, public_keys);
        // can_dkg_end starts out as false
        assert!(!signer.can_dkg_end());

        // meet the conditions for DKG_END
        let dkg_begin = Message::DkgBegin(DkgBegin { dkg_id: 1 });
        let dkg_public_shares = signer
            .process(&dkg_begin)
            .expect("failed to process DkgBegin");
        let _ = signer
            .process(&dkg_public_shares[0])
            .expect("failed to process DkgPublicShares");
        let dkg_private_begin = Message::DkgPrivateBegin(DkgPrivateBegin {
            dkg_id: 1,
            signer_ids: vec![0],
            key_ids: vec![1],
        });
        let dkg_private_shares = signer
            .process(&dkg_private_begin)
            .expect("failed to process DkgBegin");
        let _ = signer
            .process(&dkg_private_shares[0])
            .expect("failed to process DkgPrivateShares");
        let dkg_end_begin = DkgEndBegin {
            dkg_id: 1,
            signer_ids: vec![0],
            key_ids: vec![1],
        };
        let _ = signer
            .dkg_end_begin(&dkg_end_begin)
            .expect("failed to process DkgPrivateShares");

        // can_dkg_end should be true
        assert!(signer.can_dkg_end());
    }

    #[test]
    fn dkg_ended_v1() {
        dkg_ended::<v1::Signer>();
    }

    #[test]
    fn dkg_ended_v2() {
        dkg_ended::<v2::Signer>();
    }
    //use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    fn dkg_ended<SignerType: SignerTrait>() {
        /*tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();*/
        let mut signer =
            Signer::<SignerType>::new(1, 1, 1, 0, vec![1], Default::default(), Default::default());

        if let Ok(Message::DkgEnd(dkg_end)) = signer.dkg_ended() {
            match dkg_end.status {
                DkgStatus::Failure(_) => {}
                _ => panic!("Expected DkgStatus::Failure"),
            }
        } else {
            panic!("Unexpected Error");
        }
    }
}
