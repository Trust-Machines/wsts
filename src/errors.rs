use p256k1::{point::Error as PointError, scalar::Scalar};
use thiserror::Error;

#[derive(Error, Debug, Clone)]
/// Errors which can happen during distributed key generation
pub enum DkgError {
    #[error("missing shares from {0:?}")]
    /// The shares which were missing
    MissingShares(Vec<usize>),
    #[error("bad IDs {0:?}")]
    /// The IDs which failed to verify
    BadIds(Vec<usize>),
    #[error("not enough shares {0:?}")]
    /// Not enough shares to complete DKG
    NotEnoughShares(Vec<usize>),
    #[error("bad shares {0:?}")]
    /// The shares which failed to verify
    BadShares(Vec<usize>),
    #[error("point error {0:?}")]
    /// An error during point operations
    Point(PointError),
}

impl From<PointError> for DkgError {
    fn from(e: PointError) -> Self {
        DkgError::Point(e)
    }
}

#[derive(Error, Debug, Clone)]
/// Errors which can happen during signature aggregation
pub enum AggregatorError {
    #[error("bad poly commitment length (expected {0} got {1}")]
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
    BadPartyKeys(Vec<usize>),
    #[error("bad party sigs from {0:?}")]
    /// The party signatures which failed to verify
    BadPartySigs(Vec<usize>),
    #[error("bad group sig")]
    /// The aggregate group signature failed to verify
    BadGroupSig,
}
