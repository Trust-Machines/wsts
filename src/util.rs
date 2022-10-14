use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto as CompressedPoint, ristretto::RistrettoPoint as Point, scalar::Scalar,
};
use sha3::{
    Digest, Sha3_256, 
};

// G is a generator for our group
pub const G: Point = RISTRETTO_BASEPOINT_POINT;

#[allow(dead_code)]
pub fn hash_to_scalar(hasher: &mut Sha3_256) -> Scalar {
    let h = hasher.clone();
    let hash = h.finalize();
    let mut hash_bytes: [u8; 32] = [0; 32];
    hash_bytes.clone_from_slice(hash.as_slice());
    
    Scalar::from_bytes_mod_order(hash_bytes)
}

#[allow(dead_code)]
pub fn decode_scalar(s: &String) -> Scalar {
    let vec = hex::decode(s).unwrap();
    let mut bytes: [u8; 32] = [0; 32];
    bytes.clone_from_slice(vec.as_slice());
    
    Scalar::from_bytes_mod_order(bytes)
}

#[allow(dead_code)]
pub fn decode_point(s: &String) -> Point {
    let vec = hex::decode(s).unwrap();
    let compressed = CompressedPoint::from_slice(vec.as_slice());
    compressed.decompress().unwrap()
}

#[allow(dead_code)]
pub fn encode_scalar(s: &Scalar) -> String {
    hex::encode(s.as_bytes())
}

#[allow(dead_code)]
pub fn encode_point(p: &Point) -> String {
    hex::encode(p.compress().as_bytes())
}
