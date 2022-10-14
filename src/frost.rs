use curve25519_dalek::{
    ristretto::RistrettoPoint as Point,
};

use crate::schnorr::ID;

#[allow(non_snake_case)]
pub struct Share {
    pub id: ID,
    pub A: Vec<Point>,
}
