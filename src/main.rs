use curve25519_dalek::{
    ristretto::RistrettoPoint as Point, scalar::Scalar,
};
use num_traits::identities::Zero;
use polynomial::Polynomial;
use rand_core::{
    OsRng, RngCore,
};
use std::env;

mod frost;
mod schnorr;
mod util;
mod vss;

use frost::{
    Party, Share, Share2,
};

fn eval(p: &Polynomial<Point>, x: &Scalar) -> Point {
    let mut y = *x;
    let mut val = p.data()[0];

    for i in 1..p.data().len() {
	val += p.data()[i] * y;
	y *= y;
    }

    val
}

#[allow(non_snake_case)]
fn main() {
    let _args: Vec<String> = env::args().collect();
    let mut rng = OsRng::default();
    const N: usize = 3;
    const T: usize = 2;

    let mut parties: Vec<Party> = (0..N).map(|n| Party::new(&Scalar::from((n+1) as u64), T, &mut rng)).collect();
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
    let P: Polynomial<Point> = Polynomial::new(agg_params);

    let zero = eval(&P, &Scalar::zero());
    
    //let p = Polynomial::<Scalar>::lagrange(&xs, &ys).unwrap();
    println!("P(0) = {}", zero);

    // round2
    for i in 0..N {
	let party = parties[i].clone();
	for j in 0..N {
	    let party2 = &mut parties[j];
	    
	    // party sends party2 the round2 share
	    party2.send(Share2{
		i: party2.id,
		f_i: party.f.eval(party2.id),
	    });
	}
    }

    for party in &mut parties {
	party.compute_secret();
	println!("Party {} secret {}", &party.id, &party.secret);
    }

    // choose a random list of T parties to sign
    let mut available_parties = parties;
    let mut signing_parties = Vec::new();
    while signing_parties.len() < T {
	let i = rng.next_u64() as usize % available_parties.len();
	signing_parties.push(available_parties[i].clone());
	available_parties.remove(i);
	
    }

    let msg = "It was many and many a year ago".to_string();
    
    let _S: Vec<Scalar> = signing_parties.iter().map(|p| p.id).collect();
    
    //let B: Vec<PublicNonce> = signing_parties.iter().map(|p:&mut Party| p.pop_nonce(&mut rng)).collect();
    let mut B = Vec::new();
    for party in &mut signing_parties {
	B.push(party.get_nonce(&mut rng));
    }

    let rho: Vec<Scalar> = signing_parties.iter().map(|p| p.get_binding(&B, &msg)).collect();

    let mut R = Point::zero();
    for i in 0..B.len() {
	R += B[i].D + rho[i]*B[i].E;
    }

    let mut z = Scalar::zero();
    for (i,party) in signing_parties.iter().enumerate() {
	let l = Party::lambda(party.id, N);
	z += party.sign(&rho[i], &R, &msg, &l);
    }

    println!("Signature (R,z) = \n({},{})", R, z);
}
