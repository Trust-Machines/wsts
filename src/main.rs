use bitvec::prelude::*;
use curve25519_dalek::{
    scalar::Scalar,
};
use polynomial::Polynomial;
use std::env;
use rand_core::{
    OsRng, //RngCore,
};

fn main() {
    let _args: Vec<String> = env::args().collect();
    let mut rng = OsRng::default();
    let n = 16;
    let mut p_i: Vec<Polynomial<Scalar>> = Vec::new();
    let xs: Vec<Scalar> = (0..n).map(|x| Scalar::from(x as u64)).collect();
    let ys: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();

    //let pow = square_and_multiply(Scalar::from(2 as u64), Scalar::from(16 as u32));

    //assert!(pow == Scalar::from(65536 as u64));
    
    let p = Polynomial::<Scalar>::lagrange(&xs, &ys).unwrap();
    
    println!("Lagrange poly {:?}", p);//.pretty("x"));
}
