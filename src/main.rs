use curve25519_dalek::{
    ristretto::RistrettoPoint as Point,
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

use frost::{
    Party, Share,
};

fn main() {
    let _args: Vec<String> = env::args().collect();
    let mut rng = OsRng::default();
    const N: usize = 3;
    const T: usize = 2;

    let parties: Vec<Party> = (0..N).map(|n| Party::new(&n.to_string(), T, &mut rng)).collect();
    let shares: Vec<Share> = parties.iter().map(|p| p.share(&mut rng)).collect();

    // everybody checks everybody's shares
    for share in &shares {
	assert!(share.verify());
    }
    
    let mut agg_params = Vec::new();
    for share in &shares {
	let agg = (0..T).fold(Point::default(), |acc,x| acc + share.A[x]);
	agg_params.push(agg);
    }
    let agg_poly: Polynomial<Point> = Polynomial::new(agg_params);
    
    //let p = Polynomial::<Scalar>::lagrange(&xs, &ys).unwrap();
    //println!("Lagrange poly {:?}", agg_poly.pretty("x"));
}
