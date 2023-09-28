use hashbrown::HashMap;
use p256k1::{ecdsa, point::Point};

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

#[derive(Default, Clone, Debug)]
/// Map of signer_id and key_id to the relevant ecdsa public keys
pub struct PublicKeys {
    /// signer_id -> public key
    pub signers: HashMap<u32, ecdsa::PublicKey>,
    /// key_id -> public key
    pub key_ids: HashMap<u32, ecdsa::PublicKey>,
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
        state_machine::{OperationResult, StateMachine},
        taproot::SchnorrProof,
        traits::Aggregator,
        v1,
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
        pub aggregate_public_key: Point,
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
            self.party_polynomials.clear();
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
            self.public_nonces.clear();
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
            self.signature_shares.clear();
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
            self.start_dkg_round()
        }

        // Trigger a signing round
        fn start_signing_message(&mut self, message: &[u8]) -> Result<Packet, Error> {
            self.message = message.to_vec();
            self.start_signing_round()
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
}

/// State machine for signers
pub mod signer {
    use hashbrown::{HashMap, HashSet};
    use p256k1::{
        point::{Compressed, Point},
        scalar::Scalar,
    };
    use rand_core::{CryptoRng, OsRng, RngCore};
    use std::collections::BTreeMap;
    use tracing::{debug, info, warn};

    use crate::{
        common::{PolyCommitment, PublicNonce},
        net::{
            DkgBegin, DkgEnd, DkgPrivateShares, DkgPublicShares, DkgStatus, Message, NonceRequest,
            NonceResponse, Packet, Signable, SignatureShareRequest, SignatureShareResponse,
        },
        state_machine::{PublicKeys, StateMachine},
        traits::Signer as SignerTrait,
        util::{decrypt, encrypt, make_shared_secret},
        v1,
    };

    #[derive(Debug, PartialEq)]
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

    #[derive(thiserror::Error, Debug)]
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
    pub struct SigningRound {
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
        pub signer: v1::Signer,
        /// the Signer ID
        pub signer_id: u32,
        /// the current state
        pub state: State,
        /// map of party_id to the polynomial commitment for that party
        pub commitments: BTreeMap<u32, PolyCommitment>,
        /// map of DKG private shares from each key_id
        pub shares: HashMap<u32, HashMap<u32, Vec<u8>>>,
        /// public nonces for this signing round
        pub public_nonces: Vec<PublicNonce>,
        /// the private key used to sign messages sent over the network
        pub network_private_key: Scalar,
        /// the public keys for all signers and coordinator
        pub public_keys: PublicKeys,
    }

    impl SigningRound {
        /// create a SigningRound
        pub fn new(
            threshold: u32,
            total_signers: u32,
            total_keys: u32,
            signer_id: u32,
            key_ids: Vec<u32>,
            network_private_key: Scalar,
            public_keys: PublicKeys,
        ) -> SigningRound {
            assert!(threshold <= total_keys);
            let mut rng = OsRng;
            let signer = v1::Signer::new(signer_id, &key_ids, total_keys, threshold, &mut rng);

            SigningRound {
                dkg_id: 0,
                sign_id: 1,
                sign_iter_id: 1,
                threshold,
                total_signers,
                total_keys,
                signer,
                signer_id,
                state: State::Idle,
                commitments: BTreeMap::new(),
                shares: HashMap::new(),
                public_nonces: vec![],
                network_private_key,
                public_keys,
            }
        }

        fn reset<T: RngCore + CryptoRng>(&mut self, dkg_id: u64, rng: &mut T) {
            self.dkg_id = dkg_id;
            self.commitments.clear();
            self.shares.clear();
            self.public_nonces.clear();
            self.signer.reset_polys(rng);
        }

        ///
        pub fn process_inbound_messages(
            &mut self,
            messages: Vec<Packet>,
        ) -> Result<Vec<Packet>, Error> {
            let mut responses = vec![];
            for message in messages {
                // TODO: this code was swiped from frost-signer. Expose it there so we don't have duplicate code
                // See: https://github.com/stacks-network/stacks-blockchain/issues/3913
                let outbounds = self.process(message.msg)?;
                for out in outbounds {
                    let msg = Packet {
                        msg: out.clone(),
                        sig: match out {
                            Message::DkgBegin(msg) | Message::DkgPrivateBegin(msg) => msg
                                .sign(&self.network_private_key)
                                .expect("failed to sign DkgBegin")
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
                    };
                    responses.push(msg);
                }
            }
            Ok(responses)
        }

        /// process the passed incoming message, and return any outgoing messages needed in response
        pub fn process(&mut self, message: Message) -> Result<Vec<Message>, Error> {
            let out_msgs = match message {
                Message::DkgBegin(dkg_begin) => self.dkg_begin(dkg_begin),
                Message::DkgPrivateBegin(_) => self.dkg_private_begin(),
                Message::DkgPublicShares(dkg_public_shares) => {
                    self.dkg_public_share(dkg_public_shares)
                }
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
                    if self.public_shares_done() {
                        debug!(
                            "public_shares_done==true. commitments {}",
                            self.commitments.len()
                        );
                        self.move_to(State::DkgPrivateDistribute)?;
                    } else if self.can_dkg_end() {
                        debug!(
                            "can_dkg_end==true. shares {} commitments {}",
                            self.shares.len(),
                            self.commitments.len()
                        );
                        let dkg_end_msgs = self.dkg_ended()?;
                        out.push(dkg_end_msgs);
                        self.move_to(State::Idle)?;
                    }
                    Ok(out)
                }
                Err(e) => Err(e),
            }
        }

        /// DKG is done so decrypt private shares and compute secrets
        pub fn dkg_ended(&mut self) -> Result<Message, Error> {
            let polys: Vec<PolyCommitment> = self.commitments.clone().into_values().collect();

            let mut decrypted_shares = HashMap::new();

            // go through private shares, and decrypt any for owned keys, leaving the rest as zero scalars
            let key_ids: HashSet<u32> = self.signer.get_key_ids().into_iter().collect();
            let mut invalid_dkg_private_shares = Vec::new();

            for (src_key_id, encrypted_shares) in &self.shares {
                let mut decrypted_key_shares = HashMap::new();

                for (dst_key_id, private_share) in encrypted_shares {
                    if key_ids.contains(dst_key_id) {
                        debug!(
                            "decrypting dkg private share for key_id #{}",
                            dst_key_id + 1
                        );
                        let compressed = Compressed::from(
                            self.public_keys.key_ids[&(src_key_id + 1)].to_bytes(),
                        );
                        let src_public_key = Point::try_from(&compressed).unwrap();
                        let shared_secret =
                            make_shared_secret(&self.network_private_key, &src_public_key);

                        match decrypt(&shared_secret, private_share) {
                            Ok(plain) => match Scalar::try_from(&plain[..]) {
                                Ok(s) => {
                                    decrypted_key_shares.insert(*dst_key_id, s);
                                }
                                Err(e) => {
                                    warn!("Failed to parse Scalar for dkg private share from key_id {} to key_id {}: {:?}", src_key_id, dst_key_id, e);
                                    invalid_dkg_private_shares.push(*src_key_id);
                                }
                            },
                            Err(e) => {
                                warn!("Failed to decrypt dkg private share from key_id {} to key_id {}: {:?}", src_key_id, dst_key_id, e);
                                invalid_dkg_private_shares.push(*src_key_id);
                            }
                        }
                    } else {
                        decrypted_key_shares.insert(*dst_key_id, Scalar::new());
                    }
                }

                decrypted_shares.insert(*src_key_id, decrypted_key_shares);
            }

            let dkg_end = if invalid_dkg_private_shares.is_empty() {
                match self.signer.compute_secrets(&decrypted_shares, &polys) {
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
                    status: DkgStatus::Failure(format!("{:?}", invalid_dkg_private_shares)),
                }
            };

            let dkg_end = Message::DkgEnd(dkg_end);
            info!(
                "DKG_END round #{} signer_id {}",
                self.dkg_id, self.signer_id
            );
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
                && self.commitments.len() == usize::try_from(self.total_keys).unwrap()
        }

        /// do we have all DkgPublicShares and DkgPrivateShares?
        pub fn can_dkg_end(&self) -> bool {
            debug!(
                "can_dkg_end state {:?} commitments {} shares {}",
                self.state,
                self.commitments.len(),
                self.shares.len()
            );
            self.state == State::DkgPrivateGather
                && self.commitments.len() == usize::try_from(self.total_keys).unwrap()
                && self.shares.len() == usize::try_from(self.total_keys).unwrap()
        }

        fn nonce_request(&mut self, nonce_request: NonceRequest) -> Result<Vec<Message>, Error> {
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
            };

            let response = Message::NonceResponse(response);

            info!(
                "nonce request with dkg_id {:?}. response sent from signer_id {}",
                nonce_request.dkg_id, signer_id
            );
            msgs.push(response);

            Ok(msgs)
        }

        fn sign_share_request(
            &mut self,
            sign_request: SignatureShareRequest,
        ) -> Result<Vec<Message>, Error> {
            let mut msgs = vec![];

            let signer_ids = sign_request
                .nonce_responses
                .iter()
                .map(|nr| nr.signer_id)
                .collect::<Vec<u32>>();

            info!("Got SignatureShareRequest for signer_ids {:?}", signer_ids);

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
                    let signature_shares =
                        self.signer
                            .sign(&sign_request.message, &signer_ids, &key_ids, &nonces);

                    let response = SignatureShareResponse {
                        dkg_id: sign_request.dkg_id,
                        sign_id: sign_request.sign_id,
                        sign_iter_id: sign_request.sign_iter_id,
                        signer_id: *signer_id,
                        signature_shares,
                    };

                    info!(
                        "Sending SignatureShareResponse for signer_id {:?}",
                        signer_id
                    );

                    let response = Message::SignatureShareResponse(response);

                    msgs.push(response);
                } else {
                    debug!("SignatureShareRequest for {} dropped.", signer_id);
                }
            }
            Ok(msgs)
        }

        fn dkg_begin(&mut self, dkg_begin: DkgBegin) -> Result<Vec<Message>, Error> {
            let mut rng = OsRng;

            self.reset(dkg_begin.dkg_id, &mut rng);
            self.move_to(State::DkgPublicDistribute)?;

            let _party_state = self.signer.save();

            self.dkg_public_begin()
        }

        fn dkg_public_begin(&mut self) -> Result<Vec<Message>, Error> {
            let mut rng = OsRng;
            let mut msgs = vec![];
            let polys = self.signer.get_poly_commitments(&mut rng);

            info!(
                "sending DkgPublicSharess for round #{}, {} poly commitments for signer #{}",
                self.dkg_id,
                polys.len(),
                self.signer.get_id(),
            );

            let mut public_share = DkgPublicShares {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                comms: Vec::new(),
            };

            for poly in &polys {
                public_share
                    .comms
                    .push((poly.id.id.get_u32(), poly.clone()));
            }

            let public_share = Message::DkgPublicShares(public_share);
            msgs.push(public_share);

            self.move_to(State::DkgPublicGather)?;
            Ok(msgs)
        }

        fn dkg_private_begin(&mut self) -> Result<Vec<Message>, Error> {
            let mut rng = OsRng;
            let mut msgs = vec![];
            let mut private_shares = DkgPrivateShares {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                shares: Vec::new(),
            };

            for (key_id, shares) in &self.signer.get_shares() {
                info!(
                    "signer {} addding dkg private share for key_id #{}",
                    self.signer_id, key_id
                );
                // encrypt each share for the recipient
                let mut encrypted_shares = HashMap::new();

                for (dst_key_id, private_share) in shares {
                    debug!(
                        "encrypting dkg private share for key_id #{}",
                        dst_key_id + 1
                    );
                    let compressed =
                        Compressed::from(self.public_keys.key_ids[&(dst_key_id + 1)].to_bytes());
                    let dst_public_key = Point::try_from(&compressed).unwrap();
                    let shared_secret =
                        make_shared_secret(&self.network_private_key, &dst_public_key);
                    let encrypted_share =
                        encrypt(&shared_secret, &private_share.to_bytes(), &mut rng).unwrap();

                    encrypted_shares.insert(*dst_key_id, encrypted_share);
                }

                private_shares.shares.push((*key_id, encrypted_shares));
            }

            let private_shares = Message::DkgPrivateShares(private_shares);
            msgs.push(private_shares);

            self.move_to(State::DkgPrivateGather)?;
            Ok(msgs)
        }

        /// handle incoming DkgPublicShares
        pub fn dkg_public_share(
            &mut self,
            dkg_public_shares: DkgPublicShares,
        ) -> Result<Vec<Message>, Error> {
            for (party_id, comm) in &dkg_public_shares.comms {
                self.commitments.insert(*party_id, comm.clone());
            }
            info!(
                "received DkgPublicShares from signer #{} {}/{}",
                dkg_public_shares.signer_id,
                self.commitments.len(),
                self.total_keys
            );
            Ok(vec![])
        }

        /// handle incoming DkgPrivateShares
        pub fn dkg_private_shares(
            &mut self,
            dkg_private_shares: DkgPrivateShares,
        ) -> Result<Vec<Message>, Error> {
            for (src_key_id, shares) in &dkg_private_shares.shares {
                self.shares.insert(*src_key_id, shares.clone());
            }
            info!(
                "received DkgPrivateShares from signer #{} {}/{}",
                dkg_private_shares.signer_id,
                self.shares.len(),
                self.total_keys,
            );
            Ok(vec![])
        }
    }

    impl StateMachine<State, Error> for SigningRound {
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
}

#[cfg(test)]
mod test {
    use hashbrown::HashMap;
    use p256k1::{ecdsa, point::Point, scalar::Scalar};
    use rand_core::{CryptoRng, OsRng, RngCore};

    //use crate::runloop::process_inbound_messages;
    use crate::{
        common::PolyCommitment,
        net::{DkgPrivateShares, DkgPublicShares, DkgStatus, Message, Packet},
        schnorr::ID,
        state_machine::{
            coordinator::{Coordinatable, Coordinator, State as CoordinatorState},
            signer::{SigningRound, State as SignerState},
            OperationResult, PublicKeys, StateMachine,
        },
    };

    #[test]
    fn test_coordinator_state_machine() {
        let mut rng = OsRng;
        let message_private_key = Scalar::random(&mut rng);

        let mut coordinator = Coordinator::new(3, 3, 3, message_private_key);
        assert!(coordinator
            .can_move_to(&CoordinatorState::DkgPublicDistribute)
            .is_ok());
        assert!(coordinator
            .can_move_to(&CoordinatorState::DkgPublicGather)
            .is_err());
        assert!(coordinator
            .can_move_to(&CoordinatorState::DkgPrivateDistribute)
            .is_err());
        assert!(coordinator
            .can_move_to(&CoordinatorState::DkgEndGather)
            .is_err());
        assert!(coordinator.can_move_to(&CoordinatorState::Idle).is_ok());

        coordinator
            .move_to(CoordinatorState::DkgPublicDistribute)
            .unwrap();
        assert!(coordinator
            .can_move_to(&CoordinatorState::DkgPublicDistribute)
            .is_err());
        assert!(coordinator
            .can_move_to(&CoordinatorState::DkgPublicGather)
            .is_ok());
        assert!(coordinator
            .can_move_to(&CoordinatorState::DkgPrivateDistribute)
            .is_err());
        assert!(coordinator
            .can_move_to(&CoordinatorState::DkgEndGather)
            .is_err());
        assert!(coordinator.can_move_to(&CoordinatorState::Idle).is_ok());

        coordinator
            .move_to(CoordinatorState::DkgPublicGather)
            .unwrap();
        assert!(coordinator
            .can_move_to(&CoordinatorState::DkgPublicDistribute)
            .is_ok());
        assert!(coordinator
            .can_move_to(&CoordinatorState::DkgPublicGather)
            .is_ok());
        assert!(coordinator
            .can_move_to(&CoordinatorState::DkgPrivateDistribute)
            .is_ok());
        assert!(coordinator
            .can_move_to(&CoordinatorState::DkgEndGather)
            .is_err());
        assert!(coordinator.can_move_to(&CoordinatorState::Idle).is_ok());

        coordinator
            .move_to(CoordinatorState::DkgPrivateDistribute)
            .unwrap();
        assert!(coordinator
            .can_move_to(&CoordinatorState::DkgPublicDistribute)
            .is_err());
        assert!(coordinator
            .can_move_to(&CoordinatorState::DkgPublicGather)
            .is_err());
        assert!(coordinator
            .can_move_to(&CoordinatorState::DkgPrivateDistribute)
            .is_err());
        assert!(coordinator
            .can_move_to(&CoordinatorState::DkgEndGather)
            .is_ok());
        assert!(coordinator.can_move_to(&CoordinatorState::Idle).is_ok());

        coordinator.move_to(CoordinatorState::DkgEndGather).unwrap();
        assert!(coordinator
            .can_move_to(&CoordinatorState::DkgPublicDistribute)
            .is_ok());
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
        assert_eq!(coordinator.state, CoordinatorState::Idle);
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
        assert_eq!(coordinator.state, CoordinatorState::DkgPublicGather);
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
        coordinator.state = CoordinatorState::DkgPublicDistribute; // Must be in this state before calling start public shares

        let result = coordinator.start_public_shares().unwrap();

        assert!(matches!(result.msg, Message::DkgBegin(_)));
        assert_eq!(coordinator.state, CoordinatorState::DkgPublicGather);
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
        coordinator.state = CoordinatorState::DkgPrivateDistribute; // Must be in this state before calling start private shares

        let message = coordinator.start_private_shares().unwrap();
        assert!(matches!(message.msg, Message::DkgPrivateBegin(_)));
        assert_eq!(coordinator.state, CoordinatorState::DkgEndGather);
        assert_eq!(coordinator.current_dkg_id, 0);
    }

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
        messages: Vec<Packet>,
    ) -> (Vec<Packet>, Vec<OperationResult>) {
        let mut inbound_messages = vec![];
        let mut feedback_messages = vec![];
        for signing_round in signing_rounds.as_mut_slice() {
            let outbound_messages = signing_round
                .process_inbound_messages(messages.clone())
                .unwrap();
            feedback_messages.extend_from_slice(outbound_messages.as_slice());
            inbound_messages.extend(outbound_messages);
        }
        for signing_round in signing_rounds.as_mut_slice() {
            let outbound_messages = signing_round
                .process_inbound_messages(feedback_messages.clone())
                .unwrap();
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
        assert_eq!(coordinator.state, CoordinatorState::DkgPublicGather);
        // we have to loop in case we get an invalid y coord...
        loop {
            // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
            let (outbound_messages, operation_results) =
                feedback_messages(&mut coordinator, &mut signing_rounds, vec![message.clone()]);
            assert!(operation_results.is_empty());
            if coordinator.state == CoordinatorState::DkgEndGather {
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
                        assert_eq!(coordinator.state, CoordinatorState::Idle);
                        break;
                    }
                    _ => panic!("Expected Dkg Operation result"),
                }
            }
        }
        assert_ne!(coordinator.aggregate_public_key, Point::default());
    }

    fn get_rng() -> impl RngCore + CryptoRng {
        let rnd = OsRng;
        //rand::rngs::StdRng::seed_from_u64(rnd.next_u64()) // todo: fix trait `rand_core::RngCore` is not implemented for `StdRng`
        rnd
    }

    #[test]
    fn dkg_public_share() {
        let mut rnd = get_rng();
        let mut signing_round =
            SigningRound::new(1, 1, 1, 1, vec![1], Default::default(), Default::default());
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
        signing_round.dkg_public_share(public_share).unwrap();
        assert_eq!(1, signing_round.commitments.len())
    }

    #[test]
    fn dkg_private_shares() {
        let mut signing_round =
            SigningRound::new(1, 1, 1, 1, vec![1], Default::default(), Default::default());
        let mut private_shares = DkgPrivateShares {
            dkg_id: 0,
            signer_id: 0,
            shares: Vec::new(),
        };
        let mut key_shares = HashMap::new();
        key_shares.insert(1, Vec::new());
        private_shares.shares.push((1, key_shares));
        signing_round.dkg_private_shares(private_shares).unwrap();
        assert_eq!(1, signing_round.shares.len())
    }

    #[test]
    fn public_shares_done() {
        let mut rnd = get_rng();
        let mut signing_round =
            SigningRound::new(1, 1, 1, 1, vec![1], Default::default(), Default::default());
        // publich_shares_done starts out as false
        assert_eq!(false, signing_round.public_shares_done());

        // meet the conditions for all public keys received
        signing_round.state = SignerState::DkgPublicGather;
        signing_round.commitments.insert(
            1,
            PolyCommitment {
                id: ID::new(&Scalar::new(), &Scalar::new(), &mut rnd),
                poly: vec![],
            },
        );

        // public_shares_done should be true
        assert!(signing_round.public_shares_done());
    }

    #[test]
    fn can_dkg_end() {
        let mut rnd = get_rng();
        let mut signing_round =
            SigningRound::new(1, 1, 1, 1, vec![1], Default::default(), Default::default());
        // can_dkg_end starts out as false
        assert_eq!(false, signing_round.can_dkg_end());

        // meet the conditions for DKG_END
        signing_round.state = SignerState::DkgPrivateGather;
        signing_round.commitments.insert(
            1,
            PolyCommitment {
                id: ID::new(&Scalar::new(), &Scalar::new(), &mut rnd),
                poly: vec![],
            },
        );
        let shares: HashMap<u32, Vec<u8>> = HashMap::new();
        signing_round.shares.insert(1, shares);

        // can_dkg_end should be true
        assert!(signing_round.can_dkg_end());
    }

    #[test]
    fn dkg_ended() {
        let mut signing_round =
            SigningRound::new(1, 1, 1, 1, vec![1], Default::default(), Default::default());
        match signing_round.dkg_ended() {
            Ok(dkg_end) => match dkg_end {
                Message::DkgEnd(dkg_end) => match dkg_end.status {
                    DkgStatus::Failure(_) => assert!(true),
                    _ => assert!(false),
                },
                _ => assert!(false),
            },
            _ => assert!(false),
        }
    }
}
