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

#[cfg(test)]
mod test {
    use hashbrown::HashMap;
    use p256k1::{ecdsa, point::Point, scalar::Scalar};
    use rand_core::OsRng;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    use crate::{
        common::PolyCommitment,
        net::{DkgPublicShares, DkgStatus, Message, Packet},
        schnorr::ID,
        state_machine::{
            coordinator::{frost::Coordinator, Coordinatable, State as CoordinatorState},
            signer::{SigningRound, State as SignerState},
            OperationResult, PublicKeys, StateMachine,
        },
        traits::{Aggregator as AggregatorTrait, Signer as SignerTrait},
        v1, v2,
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

        let mut coordinator = Coordinator::<Aggregator>::new(3, 3, 3, message_private_key);
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

        let coordinator = Coordinator::<Aggregator>::new(
            total_signers,
            total_keys,
            threshold,
            message_private_key,
        );

        assert_eq!(coordinator.total_signers, total_signers);
        assert_eq!(coordinator.total_keys, total_keys);
        assert_eq!(coordinator.threshold, threshold);
        assert_eq!(coordinator.message_private_key, message_private_key);
        assert_eq!(coordinator.ids_to_await.len(), total_signers as usize);
        assert_eq!(coordinator.state, CoordinatorState::Idle);
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
        let mut coordinator = Coordinator::<Aggregator>::new(
            total_signers,
            total_keys,
            threshold,
            message_private_key,
        );

        let result = coordinator.start_dkg_round();

        assert!(result.is_ok());
        assert!(matches!(result.unwrap().msg, Message::DkgBegin(_)));
        assert_eq!(coordinator.state, CoordinatorState::DkgPublicGather);
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
        let mut coordinator = Coordinator::<Aggregator>::new(
            total_signers,
            total_keys,
            threshold,
            message_private_key,
        );
        coordinator.state = CoordinatorState::DkgPublicDistribute; // Must be in this state before calling start public shares

        let result = coordinator.start_public_shares().unwrap();

        assert!(matches!(result.msg, Message::DkgBegin(_)));
        assert_eq!(coordinator.state, CoordinatorState::DkgPublicGather);
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
        let mut coordinator = Coordinator::<Aggregator>::new(
            total_signers,
            total_keys,
            threshold,
            message_private_key,
        );
        coordinator.state = CoordinatorState::DkgPrivateDistribute; // Must be in this state before calling start private shares

        let message = coordinator.start_private_shares().unwrap();
        assert!(matches!(message.msg, Message::DkgPrivateBegin(_)));
        assert_eq!(coordinator.state, CoordinatorState::DkgEndGather);
        assert_eq!(coordinator.current_dkg_id, 0);
    }

    fn setup<Aggregator: AggregatorTrait, Signer: SignerTrait>(
    ) -> (Coordinator<Aggregator>, Vec<SigningRound<Signer>>) {
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

        let coordinator =
            Coordinator::<Aggregator>::new(total_signers, total_keys, threshold, key_pairs[0].0);
        (coordinator, signing_rounds)
    }

    /// Helper function for feeding messages back from the processor into the signing rounds and coordinator
    fn feedback_messages<Aggregator: AggregatorTrait, Signer: SignerTrait>(
        coordinator: &mut Coordinator<Aggregator>,
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

    #[test]
    fn test_process_inbound_messages_v1() {
        test_process_inbound_messages::<v1::Aggregator, v1::Signer>();
    }

    #[test]
    fn test_process_inbound_messages_v2() {
        test_process_inbound_messages::<v2::Aggregator, v2::Signer>();
    }

    fn test_process_inbound_messages<Aggregator: AggregatorTrait, Signer: SignerTrait>() {
        let (mut coordinator, mut signing_rounds) = setup::<Aggregator, Signer>();

        // We have started a dkg round
        let message = coordinator.start_dkg_round().unwrap();
        assert!(coordinator.aggregate_public_key.is_none());
        assert_eq!(coordinator.state, CoordinatorState::DkgPublicGather);

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinator, &mut signing_rounds, &[message]);
        assert!(operation_results.is_empty());
        assert_eq!(coordinator.state, CoordinatorState::DkgEndGather);

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
                assert_eq!(coordinator.aggregate_public_key, Some(point));
                assert_eq!(coordinator.state, CoordinatorState::Idle);
            }
            _ => panic!("Expected Dkg Operation result"),
        }

        // We have started a signing round
        let msg = vec![1, 2, 3];
        let is_taproot = false;
        let merkle_root = None;
        let message = coordinator
            .start_signing_message(&msg, is_taproot, merkle_root)
            .unwrap();
        assert_eq!(
            coordinator.state,
            CoordinatorState::NonceGather(is_taproot, merkle_root)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinator, &mut signing_rounds, &[message]);
        assert!(operation_results.is_empty());
        assert_eq!(
            coordinator.state,
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
                        .aggregate_public_key
                        .expect("No aggregate public key set!"),
                    &msg
                ));
            }
            _ => panic!("Expected Signature Operation result"),
        }

        assert_eq!(coordinator.state, CoordinatorState::Idle);
    }

    #[test]
    fn dkg_public_share_v1() {
        dkg_public_share::<v1::Signer>();
    }

    #[test]
    fn dkg_public_share_v2() {
        dkg_public_share::<v2::Signer>();
    }

    fn dkg_public_share<Signer: SignerTrait>() {
        let mut rnd = OsRng;
        let mut signing_round = SigningRound::<Signer>::new(
            1,
            1,
            1,
            1,
            vec![1],
            Default::default(),
            Default::default(),
        );
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
        signing_round.dkg_public_share(&public_share).unwrap();
        assert_eq!(1, signing_round.commitments.len())
    }

    #[test]
    fn public_shares_done_v1() {
        public_shares_done::<v1::Signer>();
    }

    #[test]
    fn public_shares_done_v2() {
        public_shares_done::<v2::Signer>();
    }

    fn public_shares_done<Signer: SignerTrait>() {
        let mut rnd = OsRng;
        let mut signing_round = SigningRound::<Signer>::new(
            1,
            1,
            1,
            1,
            vec![1],
            Default::default(),
            Default::default(),
        );
        // publich_shares_done starts out as false
        assert!(!signing_round.public_shares_done());

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
    fn can_dkg_end_v1() {
        can_dkg_end::<v1::Signer>();
    }

    #[test]
    fn can_dkg_end_v2() {
        can_dkg_end::<v2::Signer>();
    }

    fn can_dkg_end<Signer: SignerTrait>() {
        let mut rnd = OsRng;
        let mut signing_round = SigningRound::<Signer>::new(
            1,
            1,
            1,
            1,
            vec![1],
            Default::default(),
            Default::default(),
        );
        // can_dkg_end starts out as false
        assert!(!signing_round.can_dkg_end());

        // meet the conditions for DKG_END
        signing_round.state = SignerState::DkgPrivateGather;
        signing_round.commitments.insert(
            1,
            PolyCommitment {
                id: ID::new(&Scalar::new(), &Scalar::new(), &mut rnd),
                poly: vec![],
            },
        );
        let shares: HashMap<u32, Scalar> = HashMap::new();
        signing_round.decrypted_shares.insert(1, shares);

        // can_dkg_end should be true
        assert!(signing_round.can_dkg_end());
    }

    #[test]
    fn dkg_ended_v1() {
        dkg_ended::<v1::Signer>();
    }

    #[test]
    fn dkg_ended_v2() {
        dkg_ended::<v2::Signer>();
    }

    fn dkg_ended<Signer: SignerTrait>() {
        let mut signing_round = SigningRound::<Signer>::new(
            1,
            1,
            1,
            1,
            vec![1],
            Default::default(),
            Default::default(),
        );
        if let Ok(Message::DkgEnd(dkg_end)) = signing_round.dkg_ended() {
            match dkg_end.status {
                DkgStatus::Failure(_) => {}
                _ => panic!("Expected DkgStatus::Failure"),
            }
        } else {
            panic!("Unexpected Error");
        }
    }
}
