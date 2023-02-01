use frost::common::{PolyCommitment, PublicNonce};
use frost::errors::DkgError;
use frost::v2;

use criterion::{criterion_group, criterion_main, Criterion};
use hashbrown::HashMap;
use rand_core::{CryptoRng, OsRng, RngCore};

#[allow(non_snake_case)]
fn dkg<RNG: RngCore + CryptoRng>(
    signers: &mut Vec<v2::Party>,
    rng: &mut RNG,
) -> Result<Vec<PolyCommitment>, HashMap<usize, DkgError>> {
    let A: Vec<PolyCommitment> = signers.iter().map(|s| s.get_poly_commitment(rng)).collect();

    // each party broadcasts their commitments
    // these hashmaps will need to be serialized in tuples w/ the value encrypted
    // Vec<(party_id, HashMap<key_id, Share>)>
    let mut broadcast_shares = Vec::new();
    for party in signers.iter() {
        broadcast_shares.push((party.party_id, party.get_shares()));
    }

    // each party collects its shares from the broadcasts
    // maybe this should collect into a hashmap first?
    let mut secret_errors = HashMap::new();
    for party in signers.iter_mut() {
        let mut h = HashMap::new();
        for key_id in party.key_ids.clone() {
            let mut g = Vec::new();

            for (id, shares) in &broadcast_shares {
                g.push((*id, shares[&key_id]));
            }

            h.insert(key_id, g);
        }

        if let Err(secret_error) = party.compute_secret(h, &A) {
            secret_errors.insert(party.party_id, secret_error);
        }
    }

    if secret_errors.is_empty() {
        Ok(A)
    } else {
        Err(secret_errors)
    }
}

// There might be a slick one-liner for this?
#[allow(dead_code)]
fn sign<RNG: RngCore + CryptoRng>(
    msg: &[u8],
    signers: &mut [v2::Party],
    rng: &mut RNG,
) -> (Vec<PublicNonce>, Vec<v2::SignatureShare>, Vec<usize>) {
    let party_ids: Vec<usize> = signers.iter().map(|s| s.party_id).collect();
    let key_ids: Vec<usize> = signers.iter().flat_map(|s| s.key_ids.clone()).collect();
    let nonces: Vec<PublicNonce> = signers.iter_mut().map(|s| s.gen_nonce(rng)).collect();
    let shares = signers
        .iter()
        .map(|s| s.sign(msg, &party_ids, &key_ids, &nonces))
        .collect();

    (nonces, shares, key_ids)
}

#[allow(non_snake_case)]
pub fn bench_dkg(c: &mut Criterion) {
    let mut rng = OsRng::default();
    //let msg = "It was many and many a year ago".as_bytes();
    let N: usize = 20;
    let T: usize = 13;
    let party_key_ids: Vec<Vec<usize>> = [
        (0..5).collect(),
        (5..10).collect(),
        (10..15).collect(),
        (15..20).collect(),
    ]
    .to_vec();

    let mut signers: Vec<v2::Party> = party_key_ids
        .iter()
        .enumerate()
        .map(|(pid, pkids)| v2::Party::new(pid, pkids, party_key_ids.len(), N, T, &mut rng))
        .collect();

    c.bench_function("v2 dkg 4 parties 20 keys", |b| {
        b.iter(|| dkg(&mut signers, &mut rng))
    });
}

criterion_group!(benches, bench_dkg);
criterion_main!(benches);
