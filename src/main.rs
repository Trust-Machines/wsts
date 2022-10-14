use curve25519_dalek::{
    scalar::Scalar,
};
use polynomial::Polynomial;
use std::env;
use rand_core::{
    OsRng,
};

mod frost;
mod schnorr;
mod util;
mod vss;

use vss::VSS;
use util::G;

fn main() {
    let _args: Vec<String> = env::args().collect();
    let mut rng = OsRng::default();
    const N: usize = 3;
    const T: usize = 2;

    let polys: Vec<Polynomial<Scalar>> = (0..N).map(|_| VSS::random_poly(T-1, &mut rng)).collect();

    let mut agg_params = Vec::new();
    for poly in &polys {
	let agg = (0..T).fold(Scalar::zero(), |acc,x| acc + poly.data()[x]);
	agg_params.push(agg);
    }

    let ids: Vec<schnorr::ID> = (0..N).map(|n| schnorr::ID::new(&n.to_string(), &polys[n].data()[0], &mut rng)).collect();

    let shares: Vec<frost::Share> = (0..N).map(|n| {
	frost::Share{
	    id: ids[n].clone(),
	    A: (0..T).map(|t| polys[n].data()[t] * G).collect(),
	}}).collect();

    // everybody checks everybody's shares
    for share in &shares {
	assert!(share.verify());
    }
    
    //let p = Polynomial::<Scalar>::lagrange(&xs, &ys).unwrap();
    //println!("Lagrange poly {:?}", p.pretty("x"));
}
