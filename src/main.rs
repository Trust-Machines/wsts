use secp256k1_math::scalar::Scalar;

use rand_core::{CryptoRng, OsRng, RngCore};
use std::env;

use frost::frost::{Party, PublicNonce, Share, SignatureAggregator};

// This will eventually need to be replaced by rpcs
#[allow(non_snake_case)]
fn distribute(parties: &mut Vec<Party>, A: &Vec<Share>, B: &Vec<Vec<PublicNonce>>) {
    // round2
    for i in 0..parties.len() {
        for j in 0..parties.len() {
            if i == j {
                continue;
            }
            let s = parties[j].get_share2(parties[i].id);
            parties[i].receive_share(s);
        }
        parties[i].compute_secret();
        parties[i].set_group_key(&A);
        parties[i].receive_nonces(B.clone());
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

#[allow(non_snake_case)]
fn main() {
    let _args: Vec<String> = env::args().collect();
    let num_sigs = 7;
    let num_nonces = 5;

    let mut rng = OsRng::default();
    const N: usize = 10;
    const T: usize = 7;

    // Initial set-up
    let mut parties: Vec<Party> = (0..N)
        .map(|n| Party::new(&Scalar::from((n + 1) as u32), N, T, &mut rng))
        .collect();
    let A: Vec<Share> = parties.iter().map(|p| p.get_share(&mut rng)).collect();
    let B: Vec<Vec<PublicNonce>> = parties
        .iter_mut()
        .map(|p| p.gen_nonces(num_nonces, &mut rng))
        .collect();
    distribute(&mut parties, &A, &B);

    let mut sig_agg = SignatureAggregator::new(N, T, A, B);

    for _ in 0..num_sigs {
        let msg = "It was many and many a year ago".to_string();
        let signers = select_parties(N, T, &mut rng);
        let sig = sig_agg.sign(&msg, &mut parties, &signers);
        println!("Signature (R,z) = \n({},{})", sig.R, sig.z);
        assert!(sig.verify(&sig_agg.key, &msg));
    }
}
