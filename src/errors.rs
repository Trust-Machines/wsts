use core::num::TryFromIntError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::curve::{point::Error as PointError, scalar::Scalar};

#[derive(Error, Debug, Clone, Serialize, Deserialize, PartialEq)]
/// Errors which can happen during distributed key generation
pub enum DkgError {
    #[error("missing public shares from {0:?}")]
    /// The public shares which were missing
    MissingPublicShares(Vec<u32>),
    #[error("missing private shares from {0:?}")]
    /// The private shares which were missing
    MissingPrivateShares(Vec<u32>),
    #[error("bad public shares {0:?}")]
    /// The bad public shares that failed to verify
    BadPublicShares(Vec<u32>),
    #[error("not enough shares {0:?}")]
    /// Not enough shares to complete DKG
    NotEnoughShares(Vec<u32>),
    #[error("bad private shares {0:?}")]
    /// The private shares which failed to verify
    BadPrivateShares(Vec<u32>),
    #[error("point error {0:?}")]
    /// An error during point operations
    Point(PointError),
    #[error("try_from failed")]
    /// An error during try_from operations
    TryFrom,
}

impl From<PointError> for DkgError {
    fn from(e: PointError) -> Self {
        DkgError::Point(e)
    }
}

impl From<TryFromIntError> for DkgError {
    fn from(_e: TryFromIntError) -> Self {
        DkgError::TryFrom
    }
}

#[derive(Error, Debug, Clone, Serialize, Deserialize, PartialEq)]
/// Errors which can happen during signature aggregation
pub enum AggregatorError {
    #[error("bad poly commitment length (expected {0} got {1})")]
    /// The polynomial commitment was the wrong size
    BadPolyCommitmentLen(usize, usize),
    #[error("bad poly commitments {0:?}")]
    /// The polynomial commitments which failed verification
    BadPolyCommitments(Vec<Scalar>),
    #[error("bad nonce length (expected {0} got {1}")]
    /// The nonce length was the wrong size
    BadNonceLen(usize, usize),
    #[error("bad party keys from {0:?}")]
    /// The party public keys which failed
    BadPartyKeys(Vec<u32>),
    #[error("bad party sigs from {0:?}")]
    /// The party signatures which failed to verify
    BadPartySigs(Vec<u32>),
    #[error("bad group sig")]
    /// The aggregate group signature failed to verify
    BadGroupSig,
    #[error("try_from failed")]
    /// An error during try_from operations
    TryFrom,
}

impl From<TryFromIntError> for AggregatorError {
    fn from(_e: TryFromIntError) -> Self {
        AggregatorError::TryFrom
    }
}
