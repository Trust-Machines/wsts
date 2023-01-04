use rand_core::{CryptoRng, OsRng, RngCore};
use std::time;

use crate::v2::{
    Party, PolyCommitment, PubKeyMap, PublicNonce, SelectedSigners, SignatureAggregator,
    SignatureShare,
};
use secp256k1_math::scalar::Scalar;

use hashbrown::{HashMap, HashSet};

// pulls out on the shares relevant to party_id
// from all the shares that were broadcast
fn filter_party_shares(
    party_id: usize,
    key_owners: &[usize],
    broadcast_shares: &[Vec<(usize, Scalar)>],
) -> HashMap<usize, Vec<(usize, Scalar)>> {
    let mut shares: HashMap<usize, Vec<(usize, Scalar)>> = HashMap::new();

    for sender in 0..broadcast_shares.len() {
        for (key_id, s) in &broadcast_shares[sender] {
            if party_id == key_owners[*key_id] {
                // if shares[key_id] doesn't exist create a new vector
                if shares.contains_key(key_id) == false {
                    shares.insert(key_id.clone(), Vec::new());
                }

                let v = shares.entry(*key_id).or_insert(Vec::new());
                v.push((sender, s.clone()));
            }
        }
    }
    shares
}

// This will eventually need to be replaced by rpcs
#[allow(non_snake_case)]
fn distribute(
    parties: &mut Vec<Party>,
    key_owners: &[usize], // N-long vector with indices = key_id and values = party_id
    A: &[PolyCommitment],
    B: &Vec<Vec<PublicNonce>>,
) -> (u128, PubKeyMap) {
    // each party broadcasts their commitments
    // these will need to be serialized in tuples w/ the value encrypted
    let mut broadcast_shares = Vec::new();
    for party_id in 0..parties.len() {
        broadcast_shares.push(parties[party_id].get_shares());
    }

    let mut public_keys = HashMap::new();
    let mut total_compute_secret_time = 0;
    for party_id in 0..parties.len() {
        let party_shares = filter_party_shares(party_id, &key_owners, &broadcast_shares);
        let compute_secret_start = time::Instant::now();
        let pks = parties[party_id].compute_secret(party_shares, &A);
        public_keys.extend(pks);

        let compute_secret_time = compute_secret_start.elapsed();
        total_compute_secret_time += compute_secret_time.as_micros();
    }

    // each party copies the nonces
    for i in 0..parties.len() {
        parties[i].set_group_nonces(B.clone());
    }

    (total_compute_secret_time, public_keys)
}

#[allow(non_snake_case)]
fn select_parties<RNG: RngCore + CryptoRng>(
    key_owners: &[usize],
    T: usize,
    rng: &mut RNG,
) -> SelectedSigners {
    let mut signers = HashMap::new();
    let mut pts = Vec::new();

    for i in 0..key_owners.len() {
        pts.push(i);
    }

    while pts.len() > T {
        let i = rng.next_u64() as usize % pts.len();
        pts.swap_remove(i);
    }

    for k in pts {
        let s = signers.entry(key_owners[k]).or_insert(HashSet::new());
        s.insert(k);
    }

    signers
}

// There might be a slick one-liner for this?
fn collect_signatures(
    parties: &[Party],
    signers: &SelectedSigners,
    nonce_ctr: usize,
    msg: &[u8],
) -> Vec<SignatureShare> {
    signers
        .keys()
        .map(|party_id| SignatureShare {
            party_id: *party_id,
            z_i: parties[*party_id].sign(&msg, &signers, nonce_ctr),
        })
        .collect()
}

// In case one party loses their nonces & needs to regenerate
#[allow(non_snake_case)]
fn reset_nonce<RNG: RngCore + CryptoRng>(
    parties: &mut [Party],
    sa: &mut SignatureAggregator,
    i: usize,
    num_nonces: u32,
    rng: &mut RNG,
) {
    let B = &parties[i].gen_nonces(num_nonces, rng);
    for p in parties {
        p.set_party_nonces(i, B.clone());
    }
    sa.set_party_nonces(i, B.clone());
}

#[allow(non_snake_case)]
#[test]
pub fn test_v2() {
    let num_sigs = 7;
    let num_nonces = 5;
    let num_keys = 10;
    let threshold = (num_keys * 2) / 3;
    let mut rng = OsRng::default();

    // index is key_id and value is party_id
    //let key_owners = vec![0,1,2, 3, 4, 5, 6, 7, 8, 9];
    let key_owners = vec![0, 1, 2, 0, 0, 1, 1, 1, 2, 3];
    assert!(key_owners.len() == num_keys);
    let num_parties = *(key_owners.iter().max().unwrap()) + 1;

    // collect key_ids to each party
    // this is only used to initialize the parties & could be refactored?
    let mut party_keys: Vec<HashSet<usize>> = Vec::new();
    for key_id in 0..key_owners.len() {
        let party_id = key_owners[key_id];
        while party_id >= party_keys.len() {
            party_keys.push(HashSet::new());
        }
        party_keys[party_id].insert(key_id);
    }

    // Initial set-up
    let mut parties: Vec<Party> = (0..num_parties)
        .map(|i| {
            Party::new(
                i,
                party_keys[i].clone(),
                num_keys,
                num_parties,
                threshold,
                &mut rng,
            )
        })
        .collect();
    let A: Vec<PolyCommitment> = parties
        .iter()
        .map(|p| p.get_poly_commitment(&mut rng))
        .collect();
    let B: Vec<Vec<PublicNonce>> = parties
        .iter_mut()
        .map(|p| p.gen_nonces(num_nonces, &mut rng))
        .collect();
    let (total_compute_secret_time, public_keys) = distribute(&mut parties, &key_owners, &A, &B);

    let mut sig_agg = SignatureAggregator::new(num_keys, num_parties, threshold, A, B, public_keys);

    let mut total_sig_time = 0;
    let mut total_party_sig_time = 0;
    for sig_ct in 0..num_sigs {
        let msg = "It was many and many a year ago".as_bytes();

        let signers = select_parties(&key_owners, threshold, &mut rng); // signers[party_id] = Set(key_ids)
        let nonce_ctr = sig_agg.get_nonce_ctr();
        let party_sig_start = time::Instant::now();
        let sig_shares = collect_signatures(&parties, &signers, nonce_ctr, &msg);
        let party_sig_time = party_sig_start.elapsed();
        let sig_start = time::Instant::now();
        let sig = sig_agg.sign(&msg, &sig_shares, &signers);
        let sig_time = sig_start.elapsed();

        total_party_sig_time += party_sig_time.as_micros();
        total_sig_time += sig_time.as_micros();

        println!("Signature (R,z) = \n({},{})", sig.R, sig.z);
        assert!(sig.verify(&sig_agg.group_key, &msg));

        // this resets one party's nonces assuming it went down and needed to regenerate
        if sig_ct == 3 {
            let reset_party = 2;
            println!("Resetting nonce for party {}", reset_party);
            reset_nonce(
                &mut parties,
                &mut sig_agg,
                reset_party,
                num_nonces,
                &mut rng,
            );
        }

        // this refills the nonces if they run out
        // TODO: who should kick this off?
        if sig_agg.get_nonce_ctr() == num_nonces as usize {
            println!("Everyone's nonces were refilled.");
            let B: Vec<Vec<PublicNonce>> = parties
                .iter_mut()
                .map(|p| p.gen_nonces(num_nonces, &mut rng))
                .collect();
            for p in &mut parties {
                p.set_group_nonces(B.clone());
            }
            sig_agg.set_group_nonces(B.clone());
        }
    }
    // Note: The scaling likely depends on the distribution of keys across parties
    println!(
        "With {} keys across {} parties and {} signers:",
        num_keys, num_parties, threshold
    );
    println!(
        "{} party secrets in {} us ({} us/secret)",
        num_keys,
        total_compute_secret_time,
        total_compute_secret_time / (num_keys as u128)
    );
    println!(
        "{} party signatures in {} us ({} us/sig)",
        num_sigs * threshold as u32,
        total_party_sig_time,
        total_party_sig_time / (num_sigs * (threshold as u32)) as u128
    );
    println!(
        "{} signatures in {} us ({} us/sig)",
        num_sigs,
        total_sig_time,
        total_sig_time / num_sigs as u128
    );
}
