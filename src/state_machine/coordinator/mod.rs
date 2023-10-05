use hashbrown::HashSet;
use p256k1::{point::Point, scalar::Scalar};
use std::collections::BTreeMap;
use tracing::{debug, info};

use crate::{
    common::{MerkleRoot, PolyCommitment, PublicNonce, Signature, SignatureShare},
    compute,
    errors::AggregatorError,
    net::{
        DkgBegin, DkgPublicShares, Message, NonceRequest, NonceResponse, Packet, Signable,
        SignatureShareRequest,
    },
    state_machine::{OperationResult, StateMachine},
    taproot::SchnorrProof,
    traits::Aggregator as AggregatorTrait,
};

#[derive(Debug, PartialEq)]
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

/// Coordinatable trait for handling the coordination of DKG and sign messages
pub trait Coordinatable {
    /// Process inbound messages
    fn process_inbound_messages(
        &mut self,
        packets: Vec<Packet>,
    ) -> Result<(Vec<Packet>, Vec<OperationResult>), Error>;
    /// Retrieve the aggregate public key
    fn get_aggregate_public_key(&self) -> Option<Point>;
    /// Set the aggregate public key
    fn set_aggregate_public_key(&mut self, aggregate_public_key: Option<Point>);
    /// Trigger a DKG round
    fn start_distributed_key_generation(&mut self) -> Result<Packet, Error>;
    /// Trigger a signing round
    fn start_signing_message(
        &mut self,
        message: &[u8],
        is_taproot: bool,
        merkle_root: Option<MerkleRoot>,
    ) -> Result<Packet, Error>;
    /// Reset internal state
    fn reset(&mut self);
}

/// The coordinator for the FROST algorithm
pub struct Coordinator<Aggregator: AggregatorTrait> {
    /// current DKG round ID
    pub current_dkg_id: u64,
    /// current signing round ID
    current_sign_id: u64,
    /// current signing iteration ID
    current_sign_iter_id: u64,
    /// total number of signers
    pub total_signers: u32, // Assuming the signers cover all id:s in {1, 2, ..., total_signers}
    /// total number of keys
    pub total_keys: u32,
    /// the threshold of the keys needed for a valid signature
    pub threshold: u32,
    dkg_public_shares: BTreeMap<u32, DkgPublicShares>,
    party_polynomials: BTreeMap<u32, PolyCommitment>,
    public_nonces: BTreeMap<u32, NonceResponse>,
    signature_shares: BTreeMap<u32, Vec<SignatureShare>>,
    /// aggregate public key
    pub aggregate_public_key: Option<Point>,
    signature: Option<Signature>,
    schnorr_proof: Option<SchnorrProof>,
    /// key used to sign packet messages
    pub message_private_key: Scalar,
    /// which signers we're currently waiting on
    pub ids_to_await: HashSet<u32>,
    /// the bytes that we're signing
    pub message: Vec<u8>,
    /// current state of the state machine
    pub state: State,
    /// Aggregator object
    aggregator: Aggregator,
}

impl<Aggregator: AggregatorTrait> Coordinator<Aggregator> {
    /// Create a new coordinator
    pub fn new(
        total_signers: u32,
        total_keys: u32,
        threshold: u32,
        message_private_key: Scalar,
    ) -> Self {
        Self {
            current_dkg_id: 0,
            current_sign_id: 0,
            current_sign_iter_id: 0,
            total_signers,
            total_keys,
            threshold,
            dkg_public_shares: Default::default(),
            party_polynomials: Default::default(),
            public_nonces: Default::default(),
            signature_shares: Default::default(),
            aggregate_public_key: None,
            signature: None,
            schnorr_proof: None,
            message: Default::default(),
            message_private_key,
            ids_to_await: (0..total_signers).collect(),
            state: State::Idle,
            aggregator: Aggregator::new(total_keys, threshold),
        }
    }

    /// Process the message inside the passed packet
    pub fn process_message(
        &mut self,
        packet: &Packet,
    ) -> Result<(Option<Packet>, Option<OperationResult>), Error> {
        loop {
            match self.state {
                State::Idle => {
                    // do nothing
                    // We are the coordinator and should be the only thing triggering messages right now
                    return Ok((None, None));
                }
                State::DkgPublicDistribute => {
                    let packet = self.start_public_shares()?;
                    return Ok((Some(packet), None));
                }
                State::DkgPublicGather => {
                    self.gather_public_shares(packet)?;
                    if self.state == State::DkgPublicGather {
                        // We need more data
                        return Ok((None, None));
                    }
                }
                State::DkgPrivateDistribute => {
                    let packet = self.start_private_shares()?;
                    return Ok((Some(packet), None));
                }
                State::DkgEndGather => {
                    self.gather_dkg_end(packet)?;
                    if self.state == State::DkgEndGather {
                        // We need more data
                        return Ok((None, None));
                    } else if self.state == State::Idle {
                        // We are done with the DKG round! Return the operation result
                        return Ok((
                            None,
                            Some(OperationResult::Dkg(
                                self.aggregate_public_key
                                    .ok_or(Error::MissingAggregatePublicKey)?,
                            )),
                        ));
                    }
                }
                State::NonceRequest(is_taproot, merkle_root) => {
                    let packet = self.request_nonces(is_taproot, merkle_root)?;
                    return Ok((Some(packet), None));
                }
                State::NonceGather(is_taproot, merkle_root) => {
                    self.gather_nonces(packet, is_taproot, merkle_root)?;
                    if self.state == State::NonceGather(is_taproot, merkle_root) {
                        // We need more data
                        return Ok((None, None));
                    }
                }
                State::SigShareRequest(is_taproot, merkle_root) => {
                    let packet = self.request_sig_shares(is_taproot, merkle_root)?;
                    return Ok((Some(packet), None));
                }
                State::SigShareGather(is_taproot, merkle_root) => {
                    self.gather_sig_shares(packet, is_taproot, merkle_root)?;
                    if self.state == State::SigShareGather(is_taproot, merkle_root) {
                        // We need more data
                        return Ok((None, None));
                    } else if self.state == State::Idle {
                        // We are done with the DKG round! Return the operation result
                        if is_taproot {
                            let schnorr_proof = self
                                .schnorr_proof
                                .as_ref()
                                .ok_or(Error::MissingSchnorrProof)?;
                            return Ok((
                                None,
                                Some(OperationResult::SignTaproot(SchnorrProof {
                                    r: schnorr_proof.r,
                                    s: schnorr_proof.s,
                                })),
                            ));
                        } else {
                            let signature =
                                self.signature.as_ref().ok_or(Error::MissingSignature)?;
                            return Ok((
                                None,
                                Some(OperationResult::Sign(Signature {
                                    R: signature.R,
                                    z: signature.z,
                                })),
                            ));
                        }
                    }
                }
            }
        }
    }

    /// Start a DKG round
    pub fn start_dkg_round(&mut self) -> Result<Packet, Error> {
        self.current_dkg_id = self.current_dkg_id.wrapping_add(1);
        info!("Starting DKG round {}", self.current_dkg_id);
        self.move_to(State::DkgPublicDistribute)?;
        self.start_public_shares()
    }

    /// Start a signing round
    pub fn start_signing_round(
        &mut self,
        is_taproot: bool,
        merkle_root: Option<MerkleRoot>,
    ) -> Result<Packet, Error> {
        // We cannot sign if we haven't first set DKG (either manually or via DKG round).
        if self.aggregate_public_key.is_none() {
            return Err(Error::MissingAggregatePublicKey);
        }
        self.current_sign_id = self.current_sign_id.wrapping_add(1);
        info!("Starting signing round {}", self.current_sign_id);
        self.move_to(State::NonceRequest(is_taproot, merkle_root))?;
        self.request_nonces(is_taproot, merkle_root)
    }

    /// Ask signers to send DKG public shares
    pub fn start_public_shares(&mut self) -> Result<Packet, Error> {
        self.dkg_public_shares.clear();
        self.party_polynomials.clear();
        info!(
            "DKG Round {}: Starting Public Share Distribution",
            self.current_dkg_id,
        );
        let dkg_begin = DkgBegin {
            dkg_id: self.current_dkg_id,
        };

        let dkg_begin_packet = Packet {
            sig: dkg_begin.sign(&self.message_private_key).expect(""),
            msg: Message::DkgBegin(dkg_begin),
        };
        self.move_to(State::DkgPublicGather)?;
        Ok(dkg_begin_packet)
    }

    /// Ask signers to send DKG private shares
    pub fn start_private_shares(&mut self) -> Result<Packet, Error> {
        info!(
            "DKG Round {}: Starting Private Share Distribution",
            self.current_dkg_id
        );
        let dkg_begin = DkgBegin {
            dkg_id: self.current_dkg_id,
        };
        let dkg_private_begin_msg = Packet {
            sig: dkg_begin.sign(&self.message_private_key).expect(""),
            msg: Message::DkgPrivateBegin(dkg_begin),
        };
        self.move_to(State::DkgEndGather)?;
        Ok(dkg_private_begin_msg)
    }

    fn gather_public_shares(&mut self, packet: &Packet) -> Result<(), Error> {
        if let Message::DkgPublicShares(dkg_public_shares) = &packet.msg {
            if dkg_public_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_public_shares.dkg_id,
                    self.current_dkg_id,
                ));
            }

            self.ids_to_await.remove(&dkg_public_shares.signer_id);

            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
            for (party_id, comm) in &dkg_public_shares.comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }

            debug!(
                "DKG round {} DkgPublicShares from signer {}",
                dkg_public_shares.dkg_id, dkg_public_shares.signer_id
            );
        }

        if self.ids_to_await.is_empty() {
            // Calculate the aggregate public key
            let key = self
                .party_polynomials
                .iter()
                .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);

            info!("Aggregate public key: {}", key);
            self.aggregate_public_key = Some(key);
            self.move_to(State::DkgPrivateDistribute)?;
            self.ids_to_await = (0..self.total_signers).collect();
        }
        Ok(())
    }

    fn gather_dkg_end(&mut self, packet: &Packet) -> Result<(), Error> {
        debug!(
            "DKG Round {}: waiting for Dkg End from signers {:?}",
            self.current_dkg_id, self.ids_to_await
        );
        if let Message::DkgEnd(dkg_end) = &packet.msg {
            if dkg_end.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(dkg_end.dkg_id, self.current_dkg_id));
            }
            self.ids_to_await.remove(&dkg_end.signer_id);
            debug!(
                "DKG_End round {} from signer {}. Waiting on {:?}",
                dkg_end.dkg_id, dkg_end.signer_id, self.ids_to_await
            );
        }

        if self.ids_to_await.is_empty() {
            self.ids_to_await = (0..self.total_signers).collect();
            self.move_to(State::Idle)?;
        }
        Ok(())
    }

    fn request_nonces(
        &mut self,
        is_taproot: bool,
        merkle_root: Option<MerkleRoot>,
    ) -> Result<Packet, Error> {
        self.public_nonces.clear();
        info!(
            "Sign Round {} Nonce round {} Requesting Nonces",
            self.current_sign_id, self.current_sign_iter_id,
        );
        let nonce_request = NonceRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
        };
        let nonce_request_msg = Packet {
            sig: nonce_request.sign(&self.message_private_key).expect(""),
            msg: Message::NonceRequest(nonce_request),
        };
        self.ids_to_await = (0..self.total_signers).collect();
        self.move_to(State::NonceGather(is_taproot, merkle_root))?;
        Ok(nonce_request_msg)
    }

    fn gather_nonces(
        &mut self,
        packet: &Packet,
        is_taproot: bool,
        merkle_root: Option<MerkleRoot>,
    ) -> Result<(), Error> {
        if let Message::NonceResponse(nonce_response) = &packet.msg {
            if nonce_response.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(nonce_response.dkg_id, self.current_dkg_id));
            }
            if nonce_response.sign_id != self.current_sign_id {
                return Err(Error::BadSignId(
                    nonce_response.sign_id,
                    self.current_sign_id,
                ));
            }
            if nonce_response.sign_iter_id != self.current_sign_iter_id {
                return Err(Error::BadSignIterId(
                    nonce_response.sign_iter_id,
                    self.current_sign_iter_id,
                ));
            }

            self.public_nonces
                .insert(nonce_response.signer_id, nonce_response.clone());
            self.ids_to_await.remove(&nonce_response.signer_id);
            debug!(
                "Sign round {} nonce round {} NonceResponse from signer {}. Waiting on {:?}",
                nonce_response.sign_id,
                nonce_response.sign_iter_id,
                nonce_response.signer_id,
                self.ids_to_await
            );
        }
        if self.ids_to_await.is_empty() {
            let aggregate_nonce = self.compute_aggregate_nonce();
            info!("Aggregate nonce: {}", aggregate_nonce);

            self.move_to(State::SigShareRequest(is_taproot, merkle_root))?;
        }
        Ok(())
    }

    fn request_sig_shares(
        &mut self,
        is_taproot: bool,
        merkle_root: Option<MerkleRoot>,
    ) -> Result<Packet, Error> {
        self.signature_shares.clear();
        info!(
            "Sign Round {} Requesting Signature Shares",
            self.current_sign_id,
        );
        let nonce_responses = (0..self.total_signers)
            .map(|i| self.public_nonces[&i].clone())
            .collect::<Vec<NonceResponse>>();
        let sig_share_request = SignatureShareRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            nonce_responses,
            message: self.message.clone(),
            is_taproot,
            merkle_root,
        };
        let sig_share_request_msg = Packet {
            sig: sig_share_request.sign(&self.message_private_key).expect(""),
            msg: Message::SignatureShareRequest(sig_share_request),
        };
        self.ids_to_await = (0..self.total_signers).collect();
        self.move_to(State::SigShareGather(is_taproot, merkle_root))?;

        Ok(sig_share_request_msg)
    }

    fn gather_sig_shares(
        &mut self,
        packet: &Packet,
        is_taproot: bool,
        merkle_root: Option<MerkleRoot>,
    ) -> Result<(), Error> {
        if let Message::SignatureShareResponse(sig_share_response) = &packet.msg {
            if sig_share_response.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    sig_share_response.dkg_id,
                    self.current_dkg_id,
                ));
            }
            if sig_share_response.sign_id != self.current_sign_id {
                return Err(Error::BadSignId(
                    sig_share_response.sign_id,
                    self.current_sign_id,
                ));
            }
            self.signature_shares.insert(
                sig_share_response.signer_id,
                sig_share_response.signature_shares.clone(),
            );
            self.ids_to_await.remove(&sig_share_response.signer_id);
            debug!(
                "Sign round {} SignatureShareResponse from signer {}. Waiting on {:?}",
                sig_share_response.sign_id, sig_share_response.signer_id, self.ids_to_await
            );
        }
        if self.ids_to_await.is_empty() {
            // Calculate the aggregate signature
            let polys: Vec<PolyCommitment> = self.party_polynomials.values().cloned().collect();

            let nonce_responses = (0..self.total_signers)
                .map(|i| self.public_nonces[&i].clone())
                .collect::<Vec<NonceResponse>>();

            let nonces = nonce_responses
                .iter()
                .flat_map(|nr| nr.nonces.clone())
                .collect::<Vec<PublicNonce>>();

            let key_ids = nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.clone())
                .collect::<Vec<u32>>();

            let shares = &self
                .public_nonces
                .iter()
                .flat_map(|(i, _)| self.signature_shares[i].clone())
                .collect::<Vec<SignatureShare>>();

            debug!(
                "aggregator.sign({:?}, {:?}, {:?})",
                self.message,
                nonces.len(),
                shares.len()
            );

            self.aggregator.init(polys)?;

            if is_taproot {
                let schnorr_proof = self.aggregator.sign_taproot(
                    &self.message,
                    &nonces,
                    shares,
                    &key_ids,
                    merkle_root,
                )?;
                info!("SchnorrProof ({}, {})", schnorr_proof.r, schnorr_proof.s);
                self.schnorr_proof = Some(schnorr_proof);
            } else {
                let signature = self
                    .aggregator
                    .sign(&self.message, &nonces, shares, &key_ids)?;
                info!("Signature ({}, {})", signature.R, signature.z);
                self.signature = Some(signature);
            }

            self.move_to(State::Idle)?;
        }
        Ok(())
    }

    #[allow(non_snake_case)]
    fn compute_aggregate_nonce(&self) -> Point {
        // XXX this needs to be key_ids for v1 and signer_ids for v2
        let party_ids = self
            .public_nonces
            .values()
            .flat_map(|pn| pn.key_ids.clone())
            .collect::<Vec<u32>>();
        let nonces = self
            .public_nonces
            .values()
            .flat_map(|pn| pn.nonces.clone())
            .collect::<Vec<PublicNonce>>();
        let (_, R) = compute::intermediate(&self.message, &party_ids, &nonces);

        R
    }
}

impl<Aggregator: AggregatorTrait> StateMachine<State, Error> for Coordinator<Aggregator> {
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
                    || prev_state == &State::DkgEndGather
            }
            State::DkgPublicGather => {
                prev_state == &State::DkgPublicDistribute || prev_state == &State::DkgPublicGather
            }
            State::DkgPrivateDistribute => prev_state == &State::DkgPublicGather,
            State::DkgEndGather => prev_state == &State::DkgPrivateDistribute,
            State::NonceRequest(_, _) => {
                prev_state == &State::Idle || prev_state == &State::DkgEndGather
            }
            State::NonceGather(is_taproot, merkle_root) => {
                prev_state == &State::NonceRequest(*is_taproot, *merkle_root)
                    || prev_state == &State::NonceGather(*is_taproot, *merkle_root)
            }
            State::SigShareRequest(is_taproot, merkle_root) => {
                prev_state == &State::NonceGather(*is_taproot, *merkle_root)
            }
            State::SigShareGather(is_taproot, merkle_root) => {
                prev_state == &State::SigShareRequest(*is_taproot, *merkle_root)
                    || prev_state == &State::SigShareGather(*is_taproot, *merkle_root)
            }
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

impl<Aggregator: AggregatorTrait> Coordinatable for Coordinator<Aggregator> {
    /// Process inbound messages
    fn process_inbound_messages(
        &mut self,
        packets: Vec<Packet>,
    ) -> Result<(Vec<Packet>, Vec<OperationResult>), Error> {
        let mut outbound_packets = vec![];
        let mut operation_results = vec![];
        for packet in &packets {
            let (outbound_packet, operation_result) = self.process_message(packet)?;
            if let Some(outbound_packet) = outbound_packet {
                outbound_packets.push(outbound_packet);
            }
            if let Some(operation_result) = operation_result {
                operation_results.push(operation_result);
            }
        }
        Ok((outbound_packets, operation_results))
    }

    /// Retrieve the aggregate public key
    fn get_aggregate_public_key(&self) -> Option<Point> {
        self.aggregate_public_key
    }

    /// Set the aggregate public key
    fn set_aggregate_public_key(&mut self, aggregate_public_key: Option<Point>) {
        self.aggregate_public_key = aggregate_public_key;
    }

    /// Trigger a DKG round
    fn start_distributed_key_generation(&mut self) -> Result<Packet, Error> {
        self.start_dkg_round()
    }

    // Trigger a signing round
    fn start_signing_message(
        &mut self,
        message: &[u8],
        is_taproot: bool,
        merkle_root: Option<MerkleRoot>,
    ) -> Result<Packet, Error> {
        self.message = message.to_vec();
        self.start_signing_round(is_taproot, merkle_root)
    }

    // Reset internal state
    fn reset(&mut self) {
        self.state = State::Idle;
        self.dkg_public_shares.clear();
        self.party_polynomials.clear();
        self.public_nonces.clear();
        self.signature_shares.clear();
        self.ids_to_await = (0..self.total_signers).collect();
    }
}
