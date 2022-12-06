use rand_core::{CryptoRng, OsRng, RngCore};
use std::env;

use frost::frost::{Party, PolyCommitment, PublicNonce, SignatureAggregator, SignatureShare};

use std::collections::HashMap;

// This will eventually need to be replaced by rpcs
#[allow(non_snake_case)]
fn distribute(parties: &mut Vec<Party>, A: &Vec<PolyCommitment>, B: &Vec<Vec<PublicNonce>>) {
    // each party broadcasts their commitments
    // these hashmaps will need to be serialized in tuples w/ the value encrypted
    let mut broadcast_shares = Vec::new();
    for i in 0..parties.len() {
        broadcast_shares.push(parties[i].get_shares());
    }

    // each party collects its shares from the broadcasts
    // maybe this should collect into a hashmap first?
    for i in 0..parties.len() {
        let mut h = HashMap::new();
        for j in 0..parties.len() {
            h.insert(j, broadcast_shares[j][&i]);
        }
        parties[i].compute_secret(h, &A);
    }

    // each party copies the nonces
    for i in 0..parties.len() {
        parties[i].set_group_nonces(B.clone());
    }
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
    parties: &Vec<Party>,
    signers: &Vec<usize>,
    nonce_ctr: usize,
    msg: &String,
) -> Vec<SignatureShare> {
    let mut sigs = Vec::new();
    for i in 0..signers.len() {
        let party = &parties[signers[i]];
        sigs.push(SignatureShare {
            id: party.id.clone(),
            z_i: party.sign(&msg, &signers, nonce_ctr),
            public_key: party.public_key.clone(),
        });
    }
    sigs
}

#[allow(non_snake_case)]
fn main() {
    let _args: Vec<String> = env::args().collect();
    let num_sigs = 7;
    let num_nonces = 5;

    let mut rng = OsRng::default();
    const N: usize = 10;
    const T: usize = 7;

    // Initial set-up
    let mut parties: Vec<Party> = (0..N).map(|i| Party::new(i, N, T, &mut rng)).collect();
    let A: Vec<PolyCommitment> = parties
        .iter()
        .map(|p| p.get_poly_commitment(&mut rng))
        .collect();
    let B: Vec<Vec<PublicNonce>> = parties
        .iter_mut()
        .map(|p| p.gen_nonces(num_nonces, &mut rng))
        .collect();
    distribute(&mut parties, &A, &B);

    let mut sig_agg = SignatureAggregator::new(N, T, A, B);

    for _ in 0..num_sigs {
        let msg = "It was many and many a year ago".to_string();
        let signers = select_parties(N, T, &mut rng);
        let nonce_ctr = sig_agg.get_nonce_ctr();
        let sig_shares = collect_signatures(&parties, &signers, nonce_ctr, &msg);
        let sig = sig_agg.sign(&msg, &sig_shares, &signers);
        println!("Signature (R,z) = \n({},{})", sig.R, sig.z);
        assert!(sig.verify(&sig_agg.key, &msg));
    }
}
