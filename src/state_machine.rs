use p256k1::point::Point;

use crate::{common::Signature, taproot::SchnorrProof};

/// A generic state machine
pub trait StateMachine<S, E> {
    /// Attempt to move the state machine to a new state
    fn move_to(&mut self, state: S) -> Result<(), E>;
    /// Check if the state machine can move to a new state
    fn can_move_to(&self, state: &S) -> Result<(), E>;
}

/// Result of a DKG or sign operation
#[allow(dead_code)]
pub enum OperationResult {
    /// The DKG result
    Dkg(Point),
    /// The sign result
    Sign(Signature, SchnorrProof),
}

/// State machine for a simple FROST coordinator
pub mod coordinator {
    use hashbrown::HashSet;
    use p256k1::{point::Point, scalar::Scalar};
    use std::collections::BTreeMap;
    use tracing::{info, warn};

    use crate::{
        common::{PolyCommitment, PublicNonce, Signature, SignatureShare},
        compute,
        errors::AggregatorError,
        net::{
            DkgBegin, DkgPublicShares, Message, NonceRequest, NonceResponse, Packet, Signable,
            SignatureShareRequest,
        },
        taproot::SchnorrProof,
        traits::Aggregator,
        v1,
    };

    use super::{OperationResult, StateMachine};

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
        NonceRequest,
        /// The coordinator is gathering nonces
        NonceGather,
        /// The coordinator is requesting signature shares
        SigShareRequest,
        /// The coordinator is gathering signature shares
        SigShareGather,
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
        /// A bad dkg_public_id in received message
        #[error("Bad dkg_public_id: got {0} expected {1}")]
        BadDkgPublicId(u64, u64),
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
        fn get_aggregate_public_key(&self) -> Point;
        /// Trigger a DKG round
        fn start_distributed_key_generation(&mut self) -> Result<Packet, Error>;
        /// Trigger a signing round
        fn start_signing_message(&mut self, _message: &[u8]) -> Result<Packet, Error>;
        /// Reset internal state
        fn reset(&mut self);
    }

    /// The coordinator for the FROST algorithm
    pub struct Coordinator {
        /// current DKG round ID
        pub current_dkg_id: u64,
        current_sign_id: u64,
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
        aggregate_public_key: Point,
        signature: Signature,
        schnorr_proof: SchnorrProof,
        /// key used to sign packet messages
        pub message_private_key: Scalar,
        /// which signers we're currently waiting on
        pub ids_to_await: HashSet<u32>,
        /// the bytes that we're signing
        pub message: Vec<u8>,
        /// current state of the state machine
        pub state: State,
    }

    impl Coordinator {
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
                aggregate_public_key: Point::default(),
                signature: Signature {
                    R: Default::default(),
                    z: Default::default(),
                },
                schnorr_proof: SchnorrProof {
                    r: Default::default(),
                    s: Default::default(),
                },
                message: Default::default(),
                message_private_key,
                ids_to_await: (0..total_signers).collect(),
                state: State::Idle,
            }
        }
    }

    impl Coordinator {
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
                                Some(OperationResult::Dkg(self.aggregate_public_key)),
                            ));
                        }
                    }
                    State::NonceRequest => {
                        let packet = self.request_nonces()?;
                        return Ok((Some(packet), None));
                    }
                    State::NonceGather => {
                        self.gather_nonces(packet)?;
                        if self.state == State::NonceGather {
                            // We need more data
                            return Ok((None, None));
                        }
                    }
                    State::SigShareRequest => {
                        let packet = self.request_sig_shares()?;
                        return Ok((Some(packet), None));
                    }
                    State::SigShareGather => {
                        self.gather_sig_shares(packet)?;
                        if self.state == State::SigShareGather {
                            // We need more data
                            return Ok((None, None));
                        } else if self.state == State::Idle {
                            // We are done with the DKG round! Return the operation result
                            return Ok((
                                None,
                                Some(OperationResult::Sign(
                                    Signature {
                                        R: self.signature.R,
                                        z: self.signature.z,
                                    },
                                    SchnorrProof {
                                        r: self.schnorr_proof.r,
                                        s: self.schnorr_proof.s,
                                    },
                                )),
                            ));
                        }
                    }
                }
            }
        }

        /// Start a DKG round
        pub fn start_dkg_round(&mut self) -> Result<Packet, Error> {
            self.current_dkg_id = self.current_dkg_id.wrapping_add(1);
            info!("Starting DKG round #{}", self.current_dkg_id);
            self.move_to(State::DkgPublicDistribute)?;
            self.start_public_shares()
        }

        /// Start a signing round
        pub fn start_signing_round(&mut self) -> Result<Packet, Error> {
            self.current_sign_id = self.current_sign_id.wrapping_add(1);
            info!("Starting signing round #{}", self.current_sign_id);
            self.move_to(State::NonceRequest)?;
            self.request_nonces()
        }

        /// Ask signers to send DKG public shares
        pub fn start_public_shares(&mut self) -> Result<Packet, Error> {
            self.dkg_public_shares.clear();
            info!(
                "DKG Round #{}: Starting Public Share Distribution",
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
                "DKG Round #{}: Starting Private Share Distribution",
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

                info!(
                    "DKG round #{} DkgPublicShares from signer #{}",
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
                self.aggregate_public_key = key;
                self.move_to(State::DkgPrivateDistribute)?;
                self.ids_to_await = (0..self.total_signers).collect();
            }
            Ok(())
        }

        fn gather_dkg_end(&mut self, packet: &Packet) -> Result<(), Error> {
            info!(
                "DKG Round #{}: waiting for Dkg End from signers {:?}",
                self.current_dkg_id, self.ids_to_await
            );
            if let Message::DkgEnd(dkg_end) = &packet.msg {
                if dkg_end.dkg_id != self.current_dkg_id {
                    return Err(Error::BadDkgId(dkg_end.dkg_id, self.current_dkg_id));
                }
                self.ids_to_await.remove(&dkg_end.signer_id);
                info!(
                    "DKG_End round #{} from signer #{}. Waiting on {:?}",
                    dkg_end.dkg_id, dkg_end.signer_id, self.ids_to_await
                );
            }

            if self.ids_to_await.is_empty() {
                self.ids_to_await = (0..self.total_signers).collect();
                self.move_to(State::Idle)?;
            }
            Ok(())
        }

        fn request_nonces(&mut self) -> Result<Packet, Error> {
            info!(
                "Sign Round #{} Nonce round #{} Requesting Nonces",
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
            self.move_to(State::NonceGather)?;
            Ok(nonce_request_msg)
        }

        fn gather_nonces(&mut self, packet: &Packet) -> Result<(), Error> {
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
                info!(
                    "Sign round #{} nonce round #{} NonceResponse from signer #{}. Waiting on {:?}",
                    nonce_response.sign_id,
                    nonce_response.sign_iter_id,
                    nonce_response.signer_id,
                    self.ids_to_await
                );
            }
            if self.ids_to_await.is_empty() {
                let aggregate_nonce = self.compute_aggregate_nonce();
                info!("Aggregate nonce: {}", aggregate_nonce);

                self.move_to(State::SigShareRequest)?;
            }
            Ok(())
        }

        fn request_sig_shares(&mut self) -> Result<Packet, Error> {
            info!(
                "Sign Round #{} Requesting Signature Shares",
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
            };
            let sig_share_request_msg = Packet {
                sig: sig_share_request.sign(&self.message_private_key).expect(""),
                msg: Message::SignatureShareRequest(sig_share_request),
            };
            self.ids_to_await = (0..self.total_signers).collect();
            self.move_to(State::SigShareGather)?;
            Ok(sig_share_request_msg)
        }

        fn gather_sig_shares(&mut self, packet: &Packet) -> Result<(), Error> {
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
                info!(
                    "Sign round #{} SignatureShareResponse from signer #{}. Waiting on {:?}",
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

                let shares = &self
                    .public_nonces
                    .iter()
                    .flat_map(|(i, _)| self.signature_shares[i].clone())
                    .collect::<Vec<SignatureShare>>();

                info!(
                    "aggregator.sign({:?}, {:?}, {:?})",
                    self.message,
                    nonces.len(),
                    shares.len()
                );

                let mut aggregator = v1::Aggregator::new(self.total_keys, self.threshold);

                aggregator.init(polys)?;

                let sig = aggregator.sign(&self.message, &nonces, shares, &[])?; // XXX need key_ids for v2

                info!("Signature ({}, {})", sig.R, sig.z);

                let proof = SchnorrProof::new(&sig);

                info!("SchnorrProof ({}, {})", proof.r, proof.s);

                if !proof.verify(&self.aggregate_public_key.x(), &self.message) {
                    warn!("SchnorrProof failed to verify!");
                    return Err(Error::SchnorrProofFailed);
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

    impl StateMachine<State, Error> for Coordinator {
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
                    prev_state == &State::DkgPublicDistribute
                        || prev_state == &State::DkgPublicGather
                }
                State::DkgPrivateDistribute => prev_state == &State::DkgPublicGather,
                State::DkgEndGather => prev_state == &State::DkgPrivateDistribute,
                State::NonceRequest => {
                    prev_state == &State::Idle
                        || prev_state == &State::DkgEndGather
                        || prev_state == &State::NonceGather
                }
                State::NonceGather => {
                    prev_state == &State::NonceRequest || prev_state == &State::NonceGather
                }
                State::SigShareRequest => prev_state == &State::NonceGather,
                State::SigShareGather => {
                    prev_state == &State::SigShareRequest || prev_state == &State::SigShareGather
                }
            };
            if accepted {
                info!("state change from {:?} to {:?}", prev_state, state);
                Ok(())
            } else {
                Err(Error::BadStateChange(format!(
                    "{:?} to {:?}",
                    prev_state, state
                )))
            }
        }
    }

    impl Coordinatable for Coordinator {
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
        fn get_aggregate_public_key(&self) -> Point {
            self.aggregate_public_key
        }

        /// Trigger a DKG round
        fn start_distributed_key_generation(&mut self) -> Result<Packet, Error> {
            let packet = self.start_dkg_round()?;
            Ok(packet)
        }

        // Trigger a signing round
        fn start_signing_message(&mut self, message: &[u8]) -> Result<Packet, Error> {
            self.message = message.to_vec();
            let packet = self.start_signing_round()?;
            Ok(packet)
        }

        // Reset internal state
        fn reset(&mut self) {
            self.state = State::Idle;
            self.dkg_public_shares.clear();
            self.public_nonces.clear();
            self.signature_shares.clear();
            self.ids_to_await = (0..self.total_signers).collect();
        }
    }
}
#[cfg(test)]
mod test {
    //use frost_signer::{config::PublicKeys, signing_round::SigningRound};
    //use hashbrown::HashMap;
    use p256k1::scalar::Scalar;
    use rand_core::OsRng;

    //use crate::runloop::process_inbound_messages;
    use crate::net::Message;

    use super::coordinator::*;
    use super::*;

    #[test]
    fn test_state_machine() {
        let mut rng = OsRng;
        let message_private_key = Scalar::random(&mut rng);

        let mut coordinator = Coordinator::new(3, 3, 3, message_private_key);
        assert!(coordinator.can_move_to(&State::DkgPublicDistribute).is_ok());
        assert!(coordinator.can_move_to(&State::DkgPublicGather).is_err());
        assert!(coordinator
            .can_move_to(&State::DkgPrivateDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_err());
        assert!(coordinator.can_move_to(&State::Idle).is_ok());

        coordinator.move_to(State::DkgPublicDistribute).unwrap();
        assert!(coordinator
            .can_move_to(&State::DkgPublicDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPublicGather).is_ok());
        assert!(coordinator
            .can_move_to(&State::DkgPrivateDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_err());
        assert!(coordinator.can_move_to(&State::Idle).is_ok());

        coordinator.move_to(State::DkgPublicGather).unwrap();
        assert!(coordinator.can_move_to(&State::DkgPublicDistribute).is_ok());
        assert!(coordinator.can_move_to(&State::DkgPublicGather).is_ok());
        assert!(coordinator
            .can_move_to(&State::DkgPrivateDistribute)
            .is_ok());
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_err());
        assert!(coordinator.can_move_to(&State::Idle).is_ok());

        coordinator.move_to(State::DkgPrivateDistribute).unwrap();
        assert!(coordinator
            .can_move_to(&State::DkgPublicDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPublicGather).is_err());
        assert!(coordinator
            .can_move_to(&State::DkgPrivateDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_ok());
        assert!(coordinator.can_move_to(&State::Idle).is_ok());

        coordinator.move_to(State::DkgEndGather).unwrap();
        assert!(coordinator.can_move_to(&State::DkgPublicDistribute).is_ok());
    }

    #[test]
    fn test_new_coordinator() {
        let total_signers = 10;
        let total_keys = 40;
        let threshold = 28;
        let mut rng = OsRng;
        let message_private_key = Scalar::random(&mut rng);

        let coordinator =
            Coordinator::new(total_signers, total_keys, threshold, message_private_key);

        assert_eq!(coordinator.total_signers, total_signers);
        assert_eq!(coordinator.total_keys, total_keys);
        assert_eq!(coordinator.threshold, threshold);
        assert_eq!(coordinator.message_private_key, message_private_key);
        assert_eq!(coordinator.ids_to_await.len(), total_signers as usize);
        assert_eq!(coordinator.state, State::Idle);
    }

    #[test]
    fn test_start_dkg_round() {
        let total_signers = 10;
        let total_keys = 40;
        let threshold = 28;
        let mut rng = OsRng;
        let message_private_key = Scalar::random(&mut rng);
        let mut coordinator =
            Coordinator::new(total_signers, total_keys, threshold, message_private_key);

        let result = coordinator.start_dkg_round();

        assert!(result.is_ok());
        assert!(matches!(result.unwrap().msg, Message::DkgBegin(_)));
        assert_eq!(coordinator.state, State::DkgPublicGather);
        assert_eq!(coordinator.current_dkg_id, 1);
    }

    #[test]
    fn test_start_public_shares() {
        let total_signers = 10;
        let total_keys = 40;
        let threshold = 28;
        let mut rng = OsRng;
        let message_private_key = Scalar::random(&mut rng);
        let mut coordinator =
            Coordinator::new(total_signers, total_keys, threshold, message_private_key);
        coordinator.state = State::DkgPublicDistribute; // Must be in this state before calling start public shares

        let result = coordinator.start_public_shares().unwrap();

        assert!(matches!(result.msg, Message::DkgBegin(_)));
        assert_eq!(coordinator.state, State::DkgPublicGather);
        assert_eq!(coordinator.current_dkg_id, 0);
    }

    #[test]
    fn test_start_private_shares() {
        let total_signers = 10;
        let total_keys = 40;
        let threshold = 28;
        let mut rng = OsRng;
        let message_private_key = Scalar::random(&mut rng);
        let mut coordinator =
            Coordinator::new(total_signers, total_keys, threshold, message_private_key);
        coordinator.state = State::DkgPrivateDistribute; // Must be in this state before calling start private shares

        let message = coordinator.start_private_shares().unwrap();
        assert!(matches!(message.msg, Message::DkgPrivateBegin(_)));
        assert_eq!(coordinator.state, State::DkgEndGather);
        assert_eq!(coordinator.current_dkg_id, 0);
    }
    /*
        fn setup() -> (Coordinator, Vec<SigningRound>) {
            let mut rng = OsRng;
            let total_signers = 5;
            let threshold = total_signers / 10 + 7;
            let keys_per_signer = 3;
            let total_keys = total_signers * keys_per_signer;
            let key_pairs = (0..total_signers)
                .map(|_| {
                    let private_key = Scalar::random(&mut rng);
                    let public_key = ecdsa::PublicKey::new(&private_key).unwrap();
                    (private_key, public_key)
                })
                .collect::<Vec<(Scalar, ecdsa::PublicKey)>>();
            let mut key_id: u32 = 0;
            let mut signer_ids_map = HashMap::new();
            let mut key_ids_map = HashMap::new();
            let mut key_ids = Vec::new();
            for (i, (_private_key, public_key)) in key_pairs.iter().enumerate() {
                for _ in 0..keys_per_signer {
                    key_ids_map.insert(key_id + 1, *public_key);
                    key_ids.push(key_id);
                    key_id += 1;
                }
                signer_ids_map.insert(i as u32, *public_key);
            }
            let public_keys = PublicKeys {
                signers: signer_ids_map,
                key_ids: key_ids_map,
            };

            let signing_rounds = key_pairs
                .iter()
                .enumerate()
                .map(|(signer_id, (private_key, _public_key))| {
                    SigningRound::new(
                        threshold,
                        total_signers,
                        total_keys,
                        signer_id as u32,
                        key_ids.clone(),
                        *private_key,
                        public_keys.clone(),
                    )
                })
                .collect::<Vec<SigningRound>>();

            let coordinator = Coordinator::new(total_signers, total_keys, threshold, key_pairs[0].0);
            (coordinator, signing_rounds)
        }

        /// Helper function for feeding messages back from the processor into the signing rounds and coordinator
        fn feedback_messages(
            coordinator: &mut Coordinator,
            signing_rounds: &mut Vec<SigningRound>,
            messages: Vec<Message>,
        ) -> (Vec<Message>, Vec<OperationResult>) {
            let mut inbound_messages = vec![];
            let mut feedback_messages = vec![];
            for signing_round in signing_rounds.as_mut_slice() {
                let outbound_messages =
                    process_inbound_messages(signing_round, messages.clone()).unwrap();
                feedback_messages.extend_from_slice(outbound_messages.as_slice());
                inbound_messages.extend(outbound_messages);
            }
            for signing_round in signing_rounds.as_mut_slice() {
                let outbound_messages =
                    process_inbound_messages(signing_round, feedback_messages.clone()).unwrap();
                inbound_messages.extend(outbound_messages);
            }
            coordinator
                .process_inbound_messages(inbound_messages)
                .unwrap()
        }

        #[test]
        fn test_process_inbound_messages_dkg() {
            let (mut coordinator, mut signing_rounds) = setup();
            // We have started a dkg round
            let message = coordinator.start_dkg_round().unwrap();
            assert_eq!(coordinator.aggregate_public_key, Point::default());
            assert_eq!(coordinator.state, State::DkgPublicGather);
            // we have to loop in case we get an invalid y coord...
            loop {
                // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
                let (outbound_messages, operation_results) =
                    feedback_messages(&mut coordinator, &mut signing_rounds, vec![message.clone()]);
                assert!(operation_results.is_empty());
                if coordinator.state == State::DkgEndGather {
                    // Successfully got an Aggregate Public Key...
                    assert_eq!(outbound_messages.len(), 1);
                    match &outbound_messages[0].msg {
                        Message::DkgPrivateBegin(_) => {}
                        _ => {
                            panic!("Expected DkgPrivateBegin message");
                        }
                    }
                    // Send the DKG Private Begin message to all signers and share their responses with the coordinator and signers
                    let (outbound_messages, operation_results) =
                        feedback_messages(&mut coordinator, &mut signing_rounds, outbound_messages);
                    assert!(outbound_messages.is_empty());
                    assert_eq!(operation_results.len(), 1);
                    match operation_results[0] {
                        OperationResult::Dkg(point) => {
                            assert_ne!(point, Point::default());
                            assert_eq!(coordinator.aggregate_public_key, point);
                            assert_eq!(coordinator.state, State::Idle);
                            break;
                        }
                        _ => panic!("Expected Dkg Operation result"),
                    }
                }
            }
            assert_ne!(coordinator.aggregate_public_key, Point::default());
        }
    */
}
