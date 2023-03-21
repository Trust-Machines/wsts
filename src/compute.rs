use core::iter::zip;
use num_traits::{One, Zero};
use p256k1::{point::Error as PointError, point::Point, scalar::Scalar};
use sha2::{Digest, Sha256};

use crate::common::PublicNonce;
use crate::util::hash_to_scalar;

#[allow(non_snake_case)]
/// Compute a binding value from the party ID, public nonces, and signed message
pub fn binding(id: &Scalar, B: &[PublicNonce], msg: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();

    hasher.update(id.to_bytes());
    for b in B {
        hasher.update(b.D.compress().as_bytes());
        hasher.update(b.E.compress().as_bytes());
    }
    hasher.update(msg);

    hash_to_scalar(&mut hasher)
}

#[allow(non_snake_case)]
/// Compute the schnorr challenge from the public key, aggregated commitments, and the signed message
pub fn challenge(publicKey: &Point, R: &Point, msg: &[u8]) -> Scalar {
    println!("R challenge MSG32    {}", hex::encode(msg));
    // we should be hashing a hash of the msg, not the msg itself
    let prefix = "BIP0340/challenge";
    let mut hasher = Sha256::new();
    let mut prefix_hasher = Sha256::new();
    let mut msg_hasher = Sha256::new();

    prefix_hasher.update(prefix.as_bytes());
    let prefix_hash = prefix_hasher.finalize();

    msg_hasher.update(msg);

    let msg_hash = msg_hasher.finalize();

    println!("R challenge R.x()    {}", hex::encode(R.x().to_bytes()));
    println!(
        "R challenge PUBKEY32 {}",
        hex::encode(publicKey.x().to_bytes())
    );
    println!("R challenge MSG_HASH {}", hex::encode(&msg_hash));

    // for bip340 add prefix, swap the order of Y/R, and only hash the x coords
    hasher.update(prefix_hash);
    hasher.update(prefix_hash);
    hasher.update(R.x().to_bytes());
    hasher.update(publicKey.x().to_bytes());
    hasher.update(msg_hash);

    hash_to_scalar(&mut hasher)
}

/// Compute the Lagrange interpolation value
pub fn lambda(i: usize, key_ids: &[usize]) -> Scalar {
    let mut lambda = Scalar::one();
    let i_scalar = id(i);
    for j in key_ids {
        if i != *j {
            let j_scalar = id(*j);
            lambda *= j_scalar / (j_scalar - i_scalar);
        }
    }
    lambda
}

// Is this the best way to return these values?
#[allow(non_snake_case)]
/// Compute the intermediate values used in both the parties and the aggregator
pub fn intermediate(
    msg: &[u8],
    party_ids: &[usize],
    nonces: &[PublicNonce],
) -> (Vec<Point>, Point) {
    let rhos: Vec<Scalar> = party_ids
        .iter()
        .map(|&i| binding(&id(i), nonces, msg))
        .collect();
    let R_vec: Vec<Point> = zip(nonces, rhos)
        .map(|(nonce, rho)| nonce.D + rho * nonce.E)
        .collect();

    let R = R_vec.iter().fold(Point::zero(), |R, &R_i| R + R_i);
    (R_vec, R)
}

/// Compute a one-based Scalar from a zero-based integer
pub fn id(i: usize) -> Scalar {
    Scalar::from((i + 1) as u32)
}

/// Evaluate the public polynomial `f` at scalar `x` using multi-exponentiation
pub fn poly(x: &Scalar, f: &Vec<Point>) -> Result<Point, PointError> {
    let mut s = Vec::with_capacity(f.len());
    let mut pow = Scalar::one();
    for _ in 0..f.len() {
        s.push(pow);
        pow *= x;
    }

    Point::multimult(s, f.clone())
}
