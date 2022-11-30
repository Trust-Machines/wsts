use secp256k1_math::{point::Compressed, point::Point, scalar::Scalar};
use sha3::{Digest, Sha3_256};

#[allow(dead_code)]
pub fn hash_to_scalar(hasher: &mut Sha3_256) -> Scalar {
    let h = hasher.clone();
    let hash = h.finalize();
    let mut hash_bytes: [u8; 32] = [0; 32];
    hash_bytes.clone_from_slice(hash.as_slice());

    Scalar::from(hash_bytes)
}

#[allow(dead_code)]
pub fn decode_scalar(s: &String) -> Scalar {
    let vec = hex::decode(s).unwrap();
    let mut bytes: [u8; 32] = [0; 32];
    bytes.clone_from_slice(vec.as_slice());

    Scalar::from(bytes)
}

#[allow(dead_code)]
pub fn decode_point(s: &String) -> Point {
    let vec = hex::decode(s).unwrap();
    let compressed = Compressed::from(vec.as_slice());
    Point::from(compressed)
}

#[allow(dead_code)]
pub fn encode_scalar(s: &Scalar) -> String {
    hex::encode(s.as_bytes())
}

#[allow(dead_code)]
pub fn encode_point(p: &Point) -> String {
    hex::encode(p.compress().as_bytes())
}
