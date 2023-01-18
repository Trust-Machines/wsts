use rand_core::{CryptoRng, OsRng, RngCore};
use std::{env, time};

use frost::{
    common::{PolyCommitment, PublicNonce, SignatureShare},
    v1::{Party, SignatureAggregator},
};
use hashbrown::HashMap;

// This will eventually need to be replaced by rpcs
#[allow(non_snake_case)]
fn distribute(parties: &mut Vec<Party>, A: &[PolyCommitment]) -> u128 {
    // each party broadcasts their commitments
    // these hashmaps will need to be serialized in tuples w/ the value encrypted
    let mut broadcast_shares = Vec::new();
    for party in parties.iter() {
        broadcast_shares.push(party.get_shares());
    }

    let mut total_compute_secret_time = 0;

    // each party collects its shares from the broadcasts
    // maybe this should collect into a hashmap first?
    for i in 0..parties.len() {
        let mut h = HashMap::new();
        for j in 0..parties.len() {
            h.insert(j, broadcast_shares[j][&i]);
        }
        let compute_secret_start = time::Instant::now();
        parties[i].compute_secret(h, A).unwrap();
        let compute_secret_time = compute_secret_start.elapsed();
        total_compute_secret_time += compute_secret_time.as_micros();
    }

    total_compute_secret_time
}

#[allow(non_snake_case)]
fn select_parties<RNG: RngCore + CryptoRng>(N: usize, T: usize, rng: &mut RNG) -> Vec<usize> {
    let mut indices: Vec<usize> = Vec::new();

    for i in 0..N {
        indices.push(i);
    }

    while indices.len() > T {
        let i = rng.next_u64() as usize % indices.len();
        indices.swap_remove(i);
    }

    indices
}

// There might be a slick one-liner for this?
fn collect_signatures(
    parties: &[Party],
    signers: &[usize],
    nonces: &[PublicNonce],
    msg: &[u8],
) -> Vec<SignatureShare> {
    let mut sigs = Vec::new();
    for i in 0..signers.len() {
        let party = &parties[signers[i]];
        sigs.push(party.sign(msg, signers, nonces));
    }
    sigs
}

#[allow(non_snake_case)]
fn main() {
    let args: Vec<String> = env::args().collect();
    let num_sigs = 7;
    let N: usize = if args.len() > 1 {
        args[1].parse::<usize>().unwrap()
    } else {
        10
    };
    let T: usize = if args.len() > 2 {
        args[2].parse::<usize>().unwrap()
    } else {
        (N * 2) / 3
    };

    let mut rng = OsRng::default();

    // Initial set-up
    let mut parties: Vec<Party> = (0..N).map(|i| Party::new(i, N, T, &mut rng)).collect();
    let A: Vec<PolyCommitment> = parties
        .iter()
        .map(|p| p.get_poly_commitment(&mut rng))
        .collect();
    let total_compute_secret_time = distribute(&mut parties, &A);

    let mut total_sig_time = 0;
    let mut total_party_sig_time = 0;
    for _ in 0..num_sigs {
        let msg = "It was many and many a year ago".as_bytes();
        let signers = select_parties(N, T, &mut rng);

        let nonces: Vec<PublicNonce> = signers
            .iter()
            .map(|i| parties[*i].gen_nonce(&mut rng))
            .collect();

        let mut sig_agg =
            SignatureAggregator::new(N, T, A.clone()).expect("aggregator ctor failed");

        let party_sig_start = time::Instant::now();
        let sig_shares = collect_signatures(&parties, &signers, &nonces, msg);
        let party_sig_time = party_sig_start.elapsed();
        let sig_start = time::Instant::now();
        let sig_res = sig_agg.sign(msg, &nonces, &sig_shares);
        let sig_time = sig_start.elapsed();

        total_party_sig_time += party_sig_time.as_micros();
        total_sig_time += sig_time.as_micros();

        match sig_res {
            Ok(sig) => {
                println!("Signature (R,z) = \n({},{})", sig.R, sig.z);
            }
            Err(sig_error) => {
                panic!("Signing failed: {:?}", sig_error);
            }
        }
    }
    println!("With {} parties and {} signers:", N, T);
    println!(
        "{} party secrets in {} us ({} us/secret)",
        N,
        total_compute_secret_time,
        total_compute_secret_time / (N as u128)
    );
    println!(
        "{} party signatures in {} us ({} us/sig)",
        num_sigs * T as u32,
        total_party_sig_time,
        total_party_sig_time / (num_sigs * (T as u32)) as u128
    );
    println!(
        "{} signatures in {} us ({} us/sig)",
        num_sigs,
        total_sig_time,
        total_sig_time / num_sigs as u128
    );
}
