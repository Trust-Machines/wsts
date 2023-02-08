use frost::common::test_helpers::gen_signer_ids;
use frost::v2;
use frost::v2::test_helpers::{dkg, sign};

use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::OsRng;

const N: usize = 20;
const T: usize = 13;
const K: usize = 4;

#[allow(non_snake_case)]
pub fn bench_dkg(c: &mut Criterion) {
    let mut rng = OsRng::default();
    let party_key_ids = gen_signer_ids(N, K);
    let mut signers: Vec<v2::Party> = party_key_ids
        .iter()
        .enumerate()
        .map(|(pid, pkids)| v2::Party::new(pid, pkids, party_key_ids.len(), N, T, &mut rng))
        .collect();

    let s = format!("v2 dkg N={} T={} K={}", N, T, K);
    c.bench_function(&s, |b| b.iter(|| dkg(&mut signers, &mut rng)));
}

#[allow(non_snake_case)]
pub fn bench_party_sign(c: &mut Criterion) {
    let mut rng = OsRng::default();
    let msg = "It was many and many a year ago".as_bytes();
    let party_key_ids = gen_signer_ids(N, K);
    let mut signers: Vec<v2::Party> = party_key_ids
        .iter()
        .enumerate()
        .map(|(pid, pkids)| v2::Party::new(pid, pkids, party_key_ids.len(), N, T, &mut rng))
        .collect();

    let _A = match dkg(&mut signers, &mut rng) {
        Ok(A) => A,
        Err(secret_errors) => {
            panic!("Got secret errors from DKG: {:?}", secret_errors);
        }
    };

    let mut signers: Vec<v2::Party> = (0..(K * 3 / 4)).map(|i| signers[i].clone()).collect();
    let s = format!("v2 party sign N={} T={} K={}", N, T, K);
    c.bench_function(&s, |b| b.iter(|| sign(&msg, &mut signers, &mut rng)));
}

#[allow(non_snake_case)]
pub fn bench_aggregator_sign(c: &mut Criterion) {
    let mut rng = OsRng::default();
    let msg = "It was many and many a year ago".as_bytes();
    let party_key_ids = gen_signer_ids(N, K);
    let mut signers: Vec<v2::Party> = party_key_ids
        .iter()
        .enumerate()
        .map(|(pid, pkids)| v2::Party::new(pid, pkids, party_key_ids.len(), N, T, &mut rng))
        .collect();

    let A = match dkg(&mut signers, &mut rng) {
        Ok(A) => A,
        Err(secret_errors) => {
            panic!("Got secret errors from DKG: {:?}", secret_errors);
        }
    };

    let mut signers: Vec<v2::Party> = (0..(K * 3 / 4)).map(|i| signers[i].clone()).collect();

    let mut aggregator =
        v2::SignatureAggregator::new(N, T, A.clone()).expect("aggregator ctor failed");

    let (nonces, sig_shares, key_ids) = sign(&msg, &mut signers, &mut rng);

    let s = format!("v2 group sign N={} T={} K={}", N, T, K);
    c.bench_function(&s, |b| {
        b.iter(|| aggregator.sign(&msg, &nonces, &sig_shares, &key_ids))
    });
}

criterion_group!(benches, bench_dkg, bench_party_sign, bench_aggregator_sign);
criterion_main!(benches);
