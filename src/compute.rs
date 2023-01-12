use core::iter::zip;
use num_traits::{One, Zero};
use secp256k1_math::{point::Point, scalar::Scalar};
use sha3::{Digest, Sha3_256};

use crate::common::PublicNonce;
use crate::util::hash_to_scalar;

#[allow(non_snake_case)]
pub fn binding(id: &Scalar, B: &[PublicNonce], msg: &[u8]) -> Scalar {
    let mut hasher = Sha3_256::new();

    hasher.update(id.as_bytes());
    for b in B {
        hasher.update(b.D.compress().as_bytes());
        hasher.update(b.E.compress().as_bytes());
    }
    hasher.update(msg);

    hash_to_scalar(&mut hasher)
}

#[allow(non_snake_case)]
pub fn challenge(publicKey: &Point, R: &Point, msg: &[u8]) -> Scalar {
    let mut hasher = Sha3_256::new();

    hasher.update(publicKey.compress().as_bytes());
    hasher.update(R.compress().as_bytes());
    hasher.update(msg);

    hash_to_scalar(&mut hasher)
}

pub fn lambda(i: usize, indices: &[usize]) -> Scalar {
    let mut lambda = Scalar::one();
    let i_scalar = id(i);
    for j in indices {
        if i != *j {
            let j_scalar = id(*j);
            lambda *= j_scalar / (j_scalar - i_scalar);
        }
    }
    lambda
}

// Is this the best way to return these values?
#[allow(non_snake_case)]
pub fn intermediate(msg: &[u8], signers: &[usize], nonces: &[PublicNonce]) -> (Vec<Point>, Point) {
    let rhos: Vec<Scalar> = signers
        .iter()
        .map(|&i| binding(&id(i), nonces, msg))
        .collect();
    let R_vec: Vec<Point> = zip(nonces, rhos)
        .map(|(nonce, rho)| nonce.D + rho * nonce.E)
        .collect();

    let R = R_vec.iter().fold(Point::zero(), |R, &R_i| R + R_i);
    (R_vec, R)
}

pub fn id(i: usize) -> Scalar {
    Scalar::from((i + 1) as u32)
}
