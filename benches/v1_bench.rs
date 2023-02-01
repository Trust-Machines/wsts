use frost::v1;
use frost::v1::test_helpers::dkg;

use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::OsRng;

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

    c.bench_function("v1 dkg 4 signers 20 keys", |b| {
        b.iter(|| dkg(&mut signers, &mut rng))
    });
}

criterion_group!(benches, bench_dkg);
criterion_main!(benches);
