use wtfrost::common::test_helpers::gen_signer_ids;
use wtfrost::v1;
use wtfrost::v1::test_helpers::{dkg, sign};

use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::OsRng;

const N: usize = 20;
const T: usize = 13;
const K: usize = 4;

#[allow(non_snake_case)]
pub fn bench_dkg(c: &mut Criterion) {
    let mut rng = OsRng::default();
    let signer_ids = gen_signer_ids(N, K);
    let mut signers: Vec<v1::Signer> = signer_ids
        .iter()
        .map(|ids| v1::Signer::new(ids, N, T, &mut rng))
        .collect();

    let s = format!("v1 dkg N={} T={} K={}", N, T, K);
    c.bench_function(&s, |b| b.iter(|| dkg(&mut signers, &mut rng)));
}

#[allow(non_snake_case)]
pub fn bench_party_sign(c: &mut Criterion) {
    let mut rng = OsRng::default();
    let msg = "It was many and many a year ago".as_bytes();
    let signer_ids = gen_signer_ids(N, K);
    let mut signers: Vec<v1::Signer> = signer_ids
        .iter()
        .map(|ids| v1::Signer::new(ids, N, T, &mut rng))
        .collect();

    let _A = match dkg(&mut signers, &mut rng) {
        Ok(A) => A,
        Err(secret_errors) => {
            panic!("Got secret errors from DKG: {:?}", secret_errors);
        }
    };

    let mut signers: Vec<v1::Signer> = (0..(K * 3 / 4)).map(|i| signers[i].clone()).collect();

    let s = format!("v1 party sign N={} T={} K={}", N, T, K);
    c.bench_function(&s, |b| b.iter(|| sign(&msg, &mut signers, &mut rng)));
}

#[allow(non_snake_case)]
pub fn bench_aggregator_sign(c: &mut Criterion) {
    let mut rng = OsRng::default();
    let msg = "It was many and many a year ago".as_bytes();
    let signer_ids = gen_signer_ids(N, K);
    let mut signers: Vec<v1::Signer> = signer_ids
        .iter()
        .map(|ids| v1::Signer::new(ids, N, T, &mut rng))
        .collect();

    let A = match dkg(&mut signers, &mut rng) {
        Ok(A) => A,
        Err(secret_errors) => {
            panic!("Got secret errors from DKG: {:?}", secret_errors);
        }
    };

    let mut signers: Vec<v1::Signer> = (0..(K * 3 / 4)).map(|i| signers[i].clone()).collect();

    let mut aggregator =
        v1::SignatureAggregator::new(N, T, A.clone()).expect("aggregator ctor failed");

    let (nonces, sig_shares) = sign(&msg, &mut signers, &mut rng);

    let s = format!("v1 group sign N={} T={} K={}", N, T, K);
    c.bench_function(&s, |b| {
        b.iter(|| aggregator.sign(&msg, &nonces, &sig_shares))
    });
}

criterion_group!(benches, bench_dkg, bench_party_sign, bench_aggregator_sign);
criterion_main!(benches);
