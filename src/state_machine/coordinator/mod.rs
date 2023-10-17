use crate::{
    common::MerkleRoot, errors::AggregatorError, net::Packet, state_machine::OperationResult,
    Point, Scalar,
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

#[cfg(test)]
pub mod test {
    use hashbrown::HashMap;
    use rand_core::OsRng;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    use crate::{
        ecdsa,
        net::{Message, Packet},
        state_machine::{
            coordinator::{
                frost::Coordinator as FrostCoordinator, Coordinator as CoordinatorTrait,
                State as CoordinatorState,
            },
            signer::SigningRound,
            OperationResult, PublicKeys, StateMachine,
        },
        traits::{Aggregator as AggregatorTrait, Signer as SignerTrait},
        v1, v2, Point, Scalar,
    };

    static mut LOG_INIT: AtomicBool = AtomicBool::new(false);

    #[test]
    fn test_coordinator_state_machine_v1() {
        test_coordinator_state_machine::<v1::Aggregator>();
    }

    #[test]
    fn test_coordinator_state_machine_v2() {
        test_coordinator_state_machine::<v2::Aggregator>();
    }

    fn test_coordinator_state_machine<Aggregator: AggregatorTrait>() {
        let mut rng = OsRng;
        let message_private_key = Scalar::random(&mut rng);

        let mut coordinator = FrostCoordinator::<Aggregator>::new(3, 3, 3, message_private_key);
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
    fn test_new_coordinator_v1() {
        test_new_coordinator::<v1::Aggregator>();
    }

    #[test]
    fn test_new_coordinator_v2() {
        test_new_coordinator::<v2::Aggregator>();
    }

    fn test_new_coordinator<Aggregator: AggregatorTrait>() {
        let total_signers = 10;
        let total_keys = 40;
        let threshold = 28;
        let mut rng = OsRng;
        let message_private_key = Scalar::random(&mut rng);

        let coordinator = FrostCoordinator::<Aggregator>::new(
            total_signers,
            total_keys,
            threshold,
            message_private_key,
        );

        assert_eq!(coordinator.total_signers, total_signers);
        assert_eq!(coordinator.total_keys, total_keys);
        assert_eq!(coordinator.threshold, threshold);
        assert_eq!(coordinator.message_private_key, message_private_key);
        assert_eq!(coordinator.ids_to_await.len(), 0);
        assert_eq!(coordinator.get_state(), CoordinatorState::Idle);
    }

    #[test]
    fn test_start_dkg_round_v1() {
        test_start_dkg_round::<v1::Aggregator>();
    }

    #[test]
    fn test_start_dkg_round_v2() {
        test_start_dkg_round::<v2::Aggregator>();
    }

    fn test_start_dkg_round<Aggregator: AggregatorTrait>() {
        let total_signers = 10;
        let total_keys = 40;
        let threshold = 28;
        let mut rng = OsRng;
        let message_private_key = Scalar::random(&mut rng);
        let mut coordinator = FrostCoordinator::<Aggregator>::new(
            total_signers,
            total_keys,
            threshold,
            message_private_key,
        );

        let result = coordinator.start_dkg_round();

        assert!(result.is_ok());
        assert!(matches!(result.unwrap().msg, Message::DkgBegin(_)));
        assert_eq!(coordinator.get_state(), CoordinatorState::DkgPublicGather);
        assert_eq!(coordinator.current_dkg_id, 1);
    }

    #[test]
    fn test_start_public_shares_v1() {
        test_start_public_shares::<v1::Aggregator>();
    }

    #[test]
    fn test_start_public_shares_v2() {
        test_start_public_shares::<v2::Aggregator>();
    }

    fn test_start_public_shares<Aggregator: AggregatorTrait>() {
        let total_signers = 10;
        let total_keys = 40;
        let threshold = 28;
        let mut rng = OsRng;
        let message_private_key = Scalar::random(&mut rng);
        let mut coordinator = FrostCoordinator::<Aggregator>::new(
            total_signers,
            total_keys,
            threshold,
            message_private_key,
        );

        coordinator.set_state(CoordinatorState::DkgPublicDistribute); // Must be in this state before calling start public shares

        let result = coordinator.start_public_shares().unwrap();

        assert!(matches!(result.msg, Message::DkgBegin(_)));
        assert_eq!(coordinator.get_state(), CoordinatorState::DkgPublicGather);
        assert_eq!(coordinator.current_dkg_id, 0);
    }

    #[test]
    fn test_start_private_shares_v1() {
        test_start_private_shares::<v1::Aggregator>();
    }

    #[test]
    fn test_start_private_shares_v2() {
        test_start_private_shares::<v2::Aggregator>();
    }

    fn test_start_private_shares<Aggregator: AggregatorTrait>() {
        let total_signers = 10;
        let total_keys = 40;
        let threshold = 28;
        let mut rng = OsRng;
        let message_private_key = Scalar::random(&mut rng);
        let mut coordinator = FrostCoordinator::<Aggregator>::new(
            total_signers,
            total_keys,
            threshold,
            message_private_key,
        );
        coordinator.set_state(CoordinatorState::DkgPrivateDistribute); // Must be in this state before calling start private shares

        let message = coordinator.start_private_shares().unwrap();
        assert!(matches!(message.msg, Message::DkgPrivateBegin(_)));
        assert_eq!(coordinator.get_state(), CoordinatorState::DkgEndGather);
        assert_eq!(coordinator.current_dkg_id, 0);
    }

    pub fn setup<Coordinator: CoordinatorTrait, Signer: SignerTrait>(
    ) -> (Coordinator, Vec<SigningRound<Signer>>) {
        unsafe {
            if let Ok(false) =
                LOG_INIT.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            {
                tracing_subscriber::registry()
                    .with(fmt::layer())
                    .with(EnvFilter::from_default_env())
                    .init()
            }
        }

        let mut rng = OsRng;
        let total_signers = 5;
        let keys_per_signer = 2;
        let total_keys = total_signers * keys_per_signer;
        let threshold = (total_keys * 7) / 10;
        let key_pairs = (0..total_signers)
            .map(|_| {
                let private_key = Scalar::random(&mut rng);
                let public_key = ecdsa::PublicKey::new(&private_key).unwrap();
                (private_key, public_key)
            })
            .collect::<Vec<(Scalar, ecdsa::PublicKey)>>();
        let mut key_id: u32 = 0;
        let mut signer_ids_map = HashMap::new();
        let mut signer_key_ids = HashMap::new();
        let mut key_ids_map = HashMap::new();
        for (i, (_private_key, public_key)) in key_pairs.iter().enumerate() {
            let mut key_ids = Vec::new();
            for _ in 0..keys_per_signer {
                key_ids_map.insert(key_id + 1, *public_key);
                key_ids.push(key_id);
                key_id += 1;
            }
            signer_ids_map.insert(i as u32, *public_key);
            signer_key_ids.insert(i as u32, key_ids);
        }
        let public_keys = PublicKeys {
            signers: signer_ids_map,
            key_ids: key_ids_map,
        };

        let signing_rounds = key_pairs
            .iter()
            .enumerate()
            .map(|(signer_id, (private_key, _public_key))| {
                SigningRound::<Signer>::new(
                    threshold,
                    total_signers,
                    total_keys,
                    signer_id as u32,
                    signer_key_ids[&(signer_id as u32)].clone(),
                    *private_key,
                    public_keys.clone(),
                )
            })
            .collect::<Vec<SigningRound<Signer>>>();

        let coordinator = Coordinator::new(total_signers, total_keys, threshold, key_pairs[0].0);
        (coordinator, signing_rounds)
    }

    /// Helper function for feeding messages back from the processor into the signing rounds and coordinator
    pub fn feedback_messages<Coordinator: CoordinatorTrait, Signer: SignerTrait>(
        coordinator: &mut Coordinator,
        signing_rounds: &mut Vec<SigningRound<Signer>>,
        messages: &[Packet],
    ) -> (Vec<Packet>, Vec<OperationResult>) {
        let mut inbound_messages = vec![];
        let mut feedback_messages = vec![];
        for signing_round in signing_rounds.as_mut_slice() {
            let outbound_messages = signing_round.process_inbound_messages(messages).unwrap();
            feedback_messages.extend_from_slice(outbound_messages.as_slice());
            inbound_messages.extend(outbound_messages);
        }
        for signing_round in signing_rounds.as_mut_slice() {
            let outbound_messages = signing_round
                .process_inbound_messages(&feedback_messages)
                .unwrap();
            inbound_messages.extend(outbound_messages);
        }
        coordinator
            .process_inbound_messages(&inbound_messages)
            .unwrap()
    }

    pub fn test_process_inbound_messages<Coordinator: CoordinatorTrait, Signer: SignerTrait>() {
        let (mut coordinator, mut signing_rounds) = setup::<Coordinator, Signer>();

        // We have started a dkg round
        let message = coordinator.start_dkg_round().unwrap();
        assert!(coordinator.get_aggregate_public_key().is_none());
        assert_eq!(coordinator.get_state(), CoordinatorState::DkgPublicGather);

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinator, &mut signing_rounds, &[message]);
        assert!(operation_results.is_empty());
        assert_eq!(coordinator.get_state(), CoordinatorState::DkgEndGather);

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
            feedback_messages(&mut coordinator, &mut signing_rounds, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match operation_results[0] {
            OperationResult::Dkg(point) => {
                assert_ne!(point, Point::default());
                assert_eq!(coordinator.get_aggregate_public_key(), Some(point));
                assert_eq!(coordinator.get_state(), CoordinatorState::Idle);
            }
            _ => panic!("Expected Dkg Operation result"),
        }

        // We have started a signing round
        let msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();
        let is_taproot = false;
        let merkle_root = None;
        let message = coordinator
            .start_signing_round(&msg, is_taproot, merkle_root)
            .unwrap();
        assert_eq!(
            coordinator.get_state(),
            CoordinatorState::NonceGather(is_taproot, merkle_root)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinator, &mut signing_rounds, &[message]);
        assert!(operation_results.is_empty());
        assert_eq!(
            coordinator.get_state(),
            CoordinatorState::SigShareGather(is_taproot, merkle_root)
        );

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0].msg {
            Message::SignatureShareRequest(_) => {}
            _ => {
                panic!("Expected SignatureShareRequest message");
            }
        }
        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinator, &mut signing_rounds, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::Sign(sig) => {
                assert!(sig.verify(
                    &coordinator
                        .get_aggregate_public_key()
                        .expect("No aggregate public key set!"),
                    &msg
                ));
            }
            _ => panic!("Expected Signature Operation result"),
        }

        assert_eq!(coordinator.get_state(), CoordinatorState::Idle);
    }
}
