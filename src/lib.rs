#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

/// Functions for doing BIP-340 schnorr proofs
pub mod bip340;
/// Types which are common to both v1 and v2
pub mod common;
/// Functions to perform various computations needed for v1 and v2
pub mod compute;
/// Errors which are returned from objects and functions
pub mod errors;
/// Schnorr utility types
pub mod schnorr;
/// Traits which are used for v1 and v2
pub mod traits;
/// Utilities for hashing scalars
pub mod util;
/// Version 1 of WTFROST, which encapsulates a number of parties using vanilla FROST
pub mod v1;
/// Version 2 of WTFROST, which optimizes the protocol for speed and bandwidth
pub mod v2;
/// Shamir secret sharing, using in distributed key generation
pub mod vss;

pub use p256k1::{
    ecdsa, field, point::Error as PointError, point::Point, point::G, point::N,
    scalar::Error as ScalarError, scalar::Scalar,
};
