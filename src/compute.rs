use num_traits::{One, Zero};
use secp256k1_math::{point::Point, scalar::Scalar};
use sha3::{Digest, Sha3_256};

use crate::common::PublicNonce;
use crate::util::hash_to_scalar;

#[allow(non_snake_case)]
pub fn binding(id: &Scalar, B: &Vec<PublicNonce>, msg: &String) -> Scalar {
    let mut hasher = Sha3_256::new();

    hasher.update(id.as_bytes());
    for b in B {
        hasher.update(b.D.compress().as_bytes());
        hasher.update(b.E.compress().as_bytes());
    }
    hasher.update(msg.as_bytes());

    hash_to_scalar(&mut hasher)
}

#[allow(non_snake_case)]
pub fn challenge(publicKey: &Point, R: &Point, msg: &String) -> Scalar {
    let mut hasher = Sha3_256::new();

    hasher.update(publicKey.compress().as_bytes());
    hasher.update(R.compress().as_bytes());
    hasher.update(msg.as_bytes());

    hash_to_scalar(&mut hasher)
}

pub fn lambda(i: &usize, indices: &Vec<usize>) -> Scalar {
    let mut lambda = Scalar::one();
    let i_scalar = Scalar::from((i + 1) as u32);
    for j in indices {
        if i != j {
            let j_scalar = Scalar::from((j + 1) as u32);
            lambda *= j_scalar / (j_scalar - i_scalar);
        }
    }
    lambda
}

// Is this the best way to return these values?
#[allow(non_snake_case)]
pub fn intermediate(
    signers: &Vec<usize>,
    B: &Vec<Vec<PublicNonce>>,
    index: usize,
    msg: &String,
) -> (Vec<PublicNonce>, Vec<Point>, Point) {
    let B = signers.iter().map(|&i| B[i][index].clone()).collect();
    let rho: Vec<Scalar> = signers
        .iter()
        .map(|&i| binding(&Scalar::from((i + 1) as u32), &B, &msg))
        .collect();
    let R_vec: Vec<Point> = (0..B.len()).map(|i| &B[i].D + &rho[i] * &B[i].E).collect();
    let R = R_vec.iter().fold(Point::zero(), |R, &R_i| R + R_i);
    (B, R_vec, R)
}
