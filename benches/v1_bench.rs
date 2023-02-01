use frost::common::{PolyCommitment, PublicNonce};
use frost::errors::DkgError;
use frost::traits::Signer;
use frost::v1;

use criterion::{criterion_group, criterion_main, Criterion};
use hashbrown::HashMap;
use rand_core::{CryptoRng, OsRng, RngCore};

#[allow(non_snake_case)]
fn dkg<RNG: RngCore + CryptoRng>(
    signers: &mut Vec<v1::Signer>,
    rng: &mut RNG,
) -> Result<Vec<PolyCommitment>, HashMap<usize, DkgError>> {
    let A: Vec<PolyCommitment> = signers
        .iter()
        .flat_map(|s| s.get_poly_commitments(rng))
        .collect();

    // each party broadcasts their commitments
    // these hashmaps will need to be serialized in tuples w/ the value encrypted
    let mut broadcast_shares = Vec::new();
    for signer in signers.iter() {
        for party in &signer.parties {
            broadcast_shares.push((party.id, party.get_shares()));
        }
    }

    // each party collects its shares from the broadcasts
    // maybe this should collect into a hashmap first?
    let mut secret_errors = HashMap::new();
    for signer in signers.iter_mut() {
        for party in signer.parties.iter_mut() {
            let mut h = HashMap::new();

            for (id, share) in &broadcast_shares {
                h.insert(*id, share[&party.id]);
            }

            if let Err(secret_error) = party.compute_secret(h, &A) {
                secret_errors.insert(party.id, secret_error);
            }
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
    signers: &mut [v1::Signer],
    rng: &mut RNG,
) -> (Vec<PublicNonce>, Vec<v1::SignatureShare>) {
    let ids: Vec<usize> = signers.iter().flat_map(|s| s.get_ids()).collect();
    let nonces: Vec<PublicNonce> = signers.iter_mut().flat_map(|s| s.gen_nonces(rng)).collect();
    let shares = signers
        .iter()
        .flat_map(|s| s.sign(msg, &ids, &nonces))
        .collect();

    (nonces, shares)
}

#[allow(non_snake_case)]
pub fn bench_dkg(c: &mut Criterion) {
    let mut rng = OsRng::default();
    //let msg = "It was many and many a year ago".as_bytes();
    let N: usize = 20;
    let T: usize = 13;
    let signer_ids: Vec<Vec<usize>> = [
        (0..5).collect(),
        (5..10).collect(),
        (10..15).collect(),
        (15..20).collect(),
    ]
        .to_vec();
    let mut signers: Vec<v1::Signer> = signer_ids
        .iter()
        .map(|ids| v1::Signer::new(ids, N, T, &mut rng))
        .collect();

    c.bench_function("v1 dkg 20", |b| b.iter(|| dkg(&mut signers, &mut rng)));
}

criterion_group!(benches, bench_dkg);
criterion_main!(benches);
